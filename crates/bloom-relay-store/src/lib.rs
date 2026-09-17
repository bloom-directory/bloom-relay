//! PostgreSQL authority for durable relay identity, tombstones and generations.

use bloom_relay_protocol::{Allocation, AllocationState, ChallengeLease, WIRE_VERSION};
use data_encoding::BASE32_NOPAD;
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use std::net::IpAddr;
use std::{path::PathBuf, sync::Arc};
use thiserror::Error;
use uuid::Uuid;
mod restore;
pub use restore::{RestoreWitness, WitnessError};
mod ct;
pub use ct::{CtAlert, CtLagAlert};

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store unavailable")]
    Unavailable(#[from] sqlx::Error),
    #[error("migration failed")]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error("operation conflicts with prior request")]
    Conflict,
    #[error("invalid request")]
    InvalidRequest,
    #[error("unauthorized")]
    Unauthorized,
    #[error("restore witness rejected security mutation: {0}")]
    Witness(String),
}

#[derive(Clone)]
pub struct Store {
    pool: PgPool,
    witness: Option<Arc<RestoreWitness>>,
}

#[derive(Debug)]
pub struct OutboxJob {
    pub id: i64,
    pub installation_id: Uuid,
    pub kind: String,
    pub payload: serde_json::Value,
}

impl Store {
    pub async fn connect(url: &str) -> Result<Self, StoreError> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(16)
            .connect(url)
            .await?;
        sqlx::migrate!("../../migrations").run(&pool).await?;
        Ok(Self {
            pool,
            witness: None,
        })
    }

    pub async fn connect_with_witness(url: &str, path: PathBuf) -> Result<Self, StoreError> {
        let mut store = Self::connect(url).await?;
        store.witness = Some(Arc::new(
            RestoreWitness::new(path).map_err(|error| StoreError::Witness(error.to_string()))?,
        ));
        store.acknowledge().await?;
        Ok(store)
    }

    async fn acknowledge(&self) -> Result<(), StoreError> {
        if let Some(witness) = &self.witness {
            witness
                .verify_and_advance(self)
                .await
                .map_err(|error| StoreError::Witness(error.to_string()))?;
        }
        Ok(())
    }

    pub async fn verify_integrity(&self) -> Result<(), StoreError> {
        self.acknowledge().await
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn restore_revision(&self) -> Result<u64, StoreError> {
        let revision: i64 =
            sqlx::query_scalar("SELECT revision FROM restore_fence WHERE singleton=TRUE")
                .fetch_one(&self.pool)
                .await?;
        Ok(revision as u64)
    }

    pub async fn restore_pristine(&self) -> Result<bool, StoreError> {
        let pristine: bool = sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM installations) AND NOT EXISTS(SELECT 1 FROM ct_feed_checkpoints)")
            .fetch_one(&self.pool).await?;
        Ok(pristine)
    }

    pub async fn create_bootstrap_challenge(
        &self,
        nonce: &str,
        source: IpAddr,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("SELECT (SELECT count(*) FROM bootstrap_challenges WHERE source_ip=$1::inet AND created_at>now()-interval '1 minute') AS local_count, (SELECT count(*) FROM bootstrap_challenges WHERE created_at>now()-interval '1 minute') AS global_count")
            .bind(source.to_string()).fetch_one(&mut *tx).await?;
        let local: i64 = row.get("local_count");
        let global: i64 = row.get("global_count");
        if local >= 10 || global >= 100 {
            return Ok(false);
        }
        sqlx::query("INSERT INTO bootstrap_challenges(nonce,source_ip,expires_at) VALUES ($1,$2::inet,now()+interval '1 minute')")
            .bind(nonce).bind(source.to_string()).execute(&mut *tx).await?;
        tx.commit().await?;
        self.acknowledge().await?;
        Ok(true)
    }

    pub async fn consume_bootstrap_challenge(
        &self,
        nonce: &str,
        source: IpAddr,
    ) -> Result<bool, StoreError> {
        let changed = sqlx::query("DELETE FROM bootstrap_challenges WHERE nonce=$1 AND source_ip=$2::inet AND expires_at>now()")
            .bind(nonce).bind(source.to_string()).execute(&self.pool).await?.rows_affected();
        Ok(changed == 1)
    }

    pub async fn admin_public_key(
        &self,
        installation_id: Uuid,
    ) -> Result<Option<[u8; 32]>, StoreError> {
        let row = sqlx::query("SELECT admin_public_key FROM installations WHERE installation_id=$1 AND state != 'retired'")
            .bind(installation_id).fetch_optional(&self.pool).await?;
        row.map(|row| {
            let bytes: Vec<u8> = row.try_get("admin_public_key")?;
            bytes.try_into().map_err(|_| StoreError::InvalidRequest)
        })
        .transpose()
    }

    pub async fn consume_nonce(
        &self,
        installation_id: Uuid,
        nonce: &str,
    ) -> Result<bool, StoreError> {
        if nonce.len() < 16 || nonce.len() > 128 {
            return Ok(false);
        }
        let changed = sqlx::query("INSERT INTO used_nonces(installation_id,nonce,expires_at) VALUES ($1,$2,now()+interval '5 minutes') ON CONFLICT DO NOTHING")
            .bind(installation_id).bind(nonce).execute(&self.pool).await?.rows_affected();
        Ok(changed == 1)
    }

    pub async fn authenticate_bearer(
        &self,
        installation_id: Uuid,
        scope: &str,
        bearer: &str,
    ) -> Result<Option<u64>, StoreError> {
        if bearer.len() < 43 || bearer.len() > 128 || !matches!(scope, "tunnel" | "dns_challenge") {
            return Ok(None);
        }
        let digest = Sha256::digest(bearer.as_bytes());
        let row = sqlx::query("SELECT c.generation FROM scoped_bearer_credentials c JOIN installations i USING (installation_id) WHERE c.installation_id=$1 AND c.scope=$2 AND c.token_hash=$3 AND c.revoked_at IS NULL AND c.expires_at > now() AND i.state='dns_ready' ORDER BY c.generation DESC LIMIT 1")
            .bind(installation_id).bind(scope).bind(digest.as_slice()).fetch_optional(&self.pool).await?;
        Ok(row.map(|row| row.get::<i64, _>("generation") as u64))
    }

    pub async fn hostname(&self, installation_id: Uuid) -> Result<Option<String>, StoreError> {
        let row = sqlx::query(
            "SELECT hostname FROM installations WHERE installation_id=$1 AND state='dns_ready'",
        )
        .bind(installation_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| row.get("hostname")))
    }

    pub async fn issue_bearer(
        &self,
        installation_id: Uuid,
        operation_id: Uuid,
        scope: &str,
        token_hash: [u8; 32],
        validity_seconds: i32,
    ) -> Result<(u64, u64), StoreError> {
        if !matches!(scope, "tunnel" | "dns_challenge") || !(60..=86400).contains(&validity_seconds)
        {
            return Err(StoreError::InvalidRequest);
        }
        let mut hasher = Sha256::new();
        hasher.update(b"bloom-relay/issue-bearer/v1\0");
        hasher.update(scope.as_bytes());
        hasher.update(validity_seconds.to_be_bytes());
        hasher.update(token_hash);
        let request_digest = hasher.finalize();
        let mut tx = self.pool.begin().await?;
        if let Some(existing) = sqlx::query("SELECT installation_id,kind,request_digest,result FROM operations WHERE operation_id=$1 FOR UPDATE")
            .bind(operation_id).fetch_optional(&mut *tx).await? {
            let existing_id: Uuid = existing.get("installation_id");
            let kind: String = existing.get("kind");
            let digest: Vec<u8> = existing.get("request_digest");
            if existing_id != installation_id || kind != format!("issue:{scope}") || digest != request_digest.as_slice() {
                return Err(StoreError::Conflict);
            }
            let result: serde_json::Value = existing.get("result");
            let receipt = (result["generation"].as_u64().ok_or(StoreError::InvalidRequest)?, result["expires_at_ms"].as_u64().ok_or(StoreError::InvalidRequest)?);
            drop(tx);
            self.acknowledge().await?;
            return Ok(receipt);
        }
        let row = sqlx::query("UPDATE installations SET generation=generation+1 WHERE installation_id=$1 AND state != 'retired' RETURNING generation")
            .bind(installation_id).fetch_optional(&mut *tx).await?.ok_or(StoreError::Conflict)?;
        let generation: i64 = row.get("generation");
        sqlx::query("UPDATE scoped_bearer_credentials SET revoked_at=now() WHERE installation_id=$1 AND scope=$2 AND revoked_at IS NULL")
            .bind(installation_id).bind(scope).execute(&mut *tx).await?;
        let expiry = sqlx::query("INSERT INTO scoped_bearer_credentials(installation_id,scope,generation,token_hash,expires_at) VALUES ($1,$2,$3,$4,now()+make_interval(secs=>$5)) RETURNING (extract(epoch FROM expires_at)*1000)::bigint AS expires_at_ms")
            .bind(installation_id).bind(scope).bind(generation).bind(token_hash.as_slice()).bind(validity_seconds).fetch_one(&mut *tx).await?;
        let expires_at_ms: i64 = expiry.get("expires_at_ms");
        if scope == "tunnel" {
            sqlx::query("DELETE FROM tunnel_leases WHERE installation_id=$1")
                .bind(installation_id)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("INSERT INTO operations(operation_id,installation_id,kind,request_digest,result) VALUES ($1,$2,$3,$4,$5)")
            .bind(operation_id).bind(installation_id).bind(format!("issue:{scope}")).bind(request_digest.as_slice())
            .bind(serde_json::json!({"generation":generation,"expires_at_ms":expires_at_ms})).execute(&mut *tx).await?;
        sqlx::query(
            "INSERT INTO security_audit(installation_id,event) VALUES ($1,'credential_rotated')",
        )
        .bind(installation_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        self.acknowledge().await?;
        Ok((generation as u64, expires_at_ms as u64))
    }

    pub async fn renew_bearer(
        &self,
        installation_id: Uuid,
        operation_id: Uuid,
        scope: &str,
        generation: u64,
        current_token: &str,
        new_token_hash: [u8; 32],
    ) -> Result<(u64, u64), StoreError> {
        if !matches!(scope, "tunnel" | "dns_challenge")
            || current_token.len() < 43
            || current_token.len() > 128
        {
            return Err(StoreError::InvalidRequest);
        }
        let old_hash = Sha256::digest(current_token.as_bytes());
        let mut hasher = Sha256::new();
        hasher.update(b"bloom-relay/renew-bearer/v1\0");
        hasher.update(scope.as_bytes());
        hasher.update(generation.to_be_bytes());
        hasher.update(old_hash);
        hasher.update(new_token_hash);
        let request_digest = hasher.finalize();
        let mut tx = self.pool.begin().await?;
        if let Some(existing) = sqlx::query("SELECT installation_id,kind,request_digest,result,created_at>now()-interval '5 minutes' AS fresh FROM operations WHERE operation_id=$1 FOR UPDATE")
            .bind(operation_id).fetch_optional(&mut *tx).await? {
            let existing_id: Uuid = existing.get("installation_id");
            let kind: String = existing.get("kind");
            let digest: Vec<u8> = existing.get("request_digest");
            let fresh: bool = existing.get("fresh");
            if existing_id != installation_id || kind != format!("renew:{scope}") || digest != request_digest.as_slice() || !fresh {
                return Err(StoreError::Conflict);
            }
            let result: serde_json::Value = existing.get("result");
            let receipt = (result["generation"].as_u64().ok_or(StoreError::InvalidRequest)?, result["expires_at_ms"].as_u64().ok_or(StoreError::InvalidRequest)?);
            drop(tx);
            self.acknowledge().await?;
            return Ok(receipt);
        }
        let row = sqlx::query("SELECT c.token_hash FROM scoped_bearer_credentials c JOIN installations i USING (installation_id) WHERE c.installation_id=$1 AND c.scope=$2 AND c.generation=$3 AND c.revoked_at IS NULL AND c.expires_at>now() AND i.state='dns_ready' FOR UPDATE OF c")
            .bind(installation_id).bind(scope).bind(generation as i64).fetch_optional(&mut *tx).await?.ok_or(StoreError::Unauthorized)?;
        let observed: Vec<u8> = row.get("token_hash");
        if observed != old_hash.as_slice() {
            return Err(StoreError::Unauthorized);
        }
        let row = sqlx::query("UPDATE installations SET generation=generation+1 WHERE installation_id=$1 RETURNING generation")
            .bind(installation_id).fetch_one(&mut *tx).await?;
        let next: i64 = row.get("generation");
        sqlx::query("UPDATE scoped_bearer_credentials SET revoked_at=now() WHERE installation_id=$1 AND scope=$2 AND generation=$3")
            .bind(installation_id).bind(scope).bind(generation as i64).execute(&mut *tx).await?;
        let expiry = sqlx::query("INSERT INTO scoped_bearer_credentials(installation_id,scope,generation,token_hash,expires_at) VALUES ($1,$2,$3,$4,now()+interval '24 hours') RETURNING (extract(epoch FROM expires_at)*1000)::bigint AS expires_at_ms")
            .bind(installation_id).bind(scope).bind(next).bind(new_token_hash.as_slice()).fetch_one(&mut *tx).await?;
        let expires_at_ms: i64 = expiry.get("expires_at_ms");
        if scope == "tunnel" {
            sqlx::query("DELETE FROM tunnel_leases WHERE installation_id=$1")
                .bind(installation_id)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("INSERT INTO operations(operation_id,installation_id,kind,request_digest,result) VALUES ($1,$2,$3,$4,$5)")
            .bind(operation_id).bind(installation_id).bind(format!("renew:{scope}")).bind(request_digest.as_slice())
            .bind(serde_json::json!({"generation":next,"expires_at_ms":expires_at_ms})).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO security_audit(installation_id,operation_id,event) VALUES ($1,$2,'credential_renewed')")
            .bind(installation_id).bind(operation_id).execute(&mut *tx).await?;
        tx.commit().await?;
        self.acknowledge().await?;
        Ok((next as u64, expires_at_ms as u64))
    }

    pub async fn register_acme_account(
        &self,
        installation_id: Uuid,
        account_uri: &str,
    ) -> Result<(), StoreError> {
        if !account_uri.starts_with("https://acme-v02.api.letsencrypt.org/acme/acct/")
            || !account_uri["https://acme-v02.api.letsencrypt.org/acme/acct/".len()..]
                .bytes()
                .all(|b| b.is_ascii_digit())
        {
            return Err(StoreError::InvalidRequest);
        }
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("UPDATE installations SET acme_account_uri=$2 WHERE installation_id=$1 AND state != 'retired' RETURNING hostname")
            .bind(installation_id).bind(account_uri).fetch_optional(&mut *tx).await?.ok_or(StoreError::Conflict)?;
        let hostname: String = row.get("hostname");
        sqlx::query(
            "INSERT INTO outbox(installation_id,kind,payload) VALUES ($1,'publish_name',$2)",
        )
        .bind(installation_id)
        .bind(serde_json::json!({"hostname":hostname}))
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO security_audit(installation_id,event) VALUES ($1,'acme_account_bound')",
        )
        .bind(installation_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        self.acknowledge().await?;
        Ok(())
    }

    pub async fn dns_identity(
        &self,
        installation_id: Uuid,
    ) -> Result<Option<(String, String)>, StoreError> {
        let row = sqlx::query("SELECT hostname, acme_account_uri FROM installations WHERE installation_id=$1 AND state!='retired' AND acme_account_uri IS NOT NULL")
            .bind(installation_id).fetch_optional(&self.pool).await?;
        Ok(row.map(|row| (row.get("hostname"), row.get("acme_account_uri"))))
    }

    pub async fn retired_hostname(
        &self,
        installation_id: Uuid,
    ) -> Result<Option<String>, StoreError> {
        Ok(sqlx::query(
            "SELECT hostname FROM installations WHERE installation_id=$1 AND state='retired'",
        )
        .bind(installation_id)
        .fetch_optional(&self.pool)
        .await?
        .map(|row| row.get("hostname")))
    }

    pub async fn mark_dns_ready(&self, installation_id: Uuid) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        let changed = sqlx::query("UPDATE installations SET state='dns_ready' WHERE installation_id=$1 AND state='pending_dns' AND acme_account_uri IS NOT NULL")
            .bind(installation_id).execute(&mut *tx).await?.rows_affected();
        if changed > 0 {
            sqlx::query(
                "INSERT INTO security_audit(installation_id,event) VALUES ($1,'dns_ready')",
            )
            .bind(installation_id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        self.acknowledge().await?;
        Ok(())
    }

    pub async fn create_challenge(
        &self,
        installation_id: Uuid,
        generation: u64,
        lease: &ChallengeLease,
    ) -> Result<(), StoreError> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| StoreError::InvalidRequest)?
            .as_millis() as u64;
        if lease.expires_at_ms <= now_ms
            || lease.expires_at_ms > now_ms.saturating_add(900_000)
            || lease.txt_value.len() != 43
            || !lease
                .txt_value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(StoreError::InvalidRequest);
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT installation_id FROM installations WHERE installation_id=$1 AND state='dns_ready' FOR UPDATE")
            .bind(installation_id).fetch_optional(&mut *tx).await?.ok_or(StoreError::Conflict)?;
        let active: i64 = sqlx::query_scalar("SELECT count(*) FROM challenge_leases WHERE installation_id=$1 AND deleted_at IS NULL AND expires_at>now() AND lease_id<>$2")
            .bind(installation_id).bind(lease.operation_id).fetch_one(&mut *tx).await?;
        if active != 0 {
            return Err(StoreError::Conflict);
        }
        let existing = sqlx::query("SELECT txt_value,generation FROM challenge_leases WHERE installation_id=$1 AND lease_id=$2")
            .bind(installation_id).bind(lease.operation_id).fetch_optional(&mut *tx).await?;
        if let Some(existing) = existing {
            let value: String = existing.get("txt_value");
            let observed_generation: i64 = existing.get("generation");
            if value != lease.txt_value || observed_generation != generation as i64 {
                return Err(StoreError::Conflict);
            }
            drop(tx);
            self.acknowledge().await?;
            return Ok(());
        }
        sqlx::query("INSERT INTO challenge_leases(installation_id,lease_id,txt_value,generation,expires_at) VALUES ($1,$2,$3,$4,to_timestamp($5::double precision/1000.0))")
            .bind(installation_id).bind(lease.operation_id).bind(&lease.txt_value).bind(generation as i64).bind(lease.expires_at_ms as i64).execute(&mut *tx).await?;
        sqlx::query(
            "INSERT INTO outbox(installation_id,kind,payload) VALUES ($1,'publish_txt',$2)",
        )
        .bind(installation_id)
        .bind(serde_json::json!({"lease_id":lease.operation_id}))
        .execute(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO security_audit(installation_id,operation_id,event) VALUES ($1,$2,'challenge_created')")
            .bind(installation_id).bind(lease.operation_id).execute(&mut *tx).await?;
        tx.commit().await?;
        self.acknowledge().await?;
        Ok(())
    }

    pub async fn delete_challenge(
        &self,
        installation_id: Uuid,
        generation: u64,
        lease_id: Uuid,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "SELECT installation_id FROM installations WHERE installation_id=$1 FOR UPDATE",
        )
        .bind(installation_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StoreError::Conflict)?;
        let changed = sqlx::query("UPDATE challenge_leases SET deleted_at=now() WHERE installation_id=$1 AND lease_id=$2 AND generation=$3 AND deleted_at IS NULL")
            .bind(installation_id).bind(lease_id).bind(generation as i64).execute(&mut *tx).await?.rows_affected();
        if changed > 0 {
            sqlx::query(
                "INSERT INTO outbox(installation_id,kind,payload) VALUES ($1,'remove_txt',$2)",
            )
            .bind(installation_id)
            .bind(serde_json::json!({"lease_id":lease_id}))
            .execute(&mut *tx)
            .await?;
            sqlx::query("INSERT INTO security_audit(installation_id,operation_id,event) VALUES ($1,$2,'challenge_deleted')")
                .bind(installation_id).bind(lease_id).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        self.acknowledge().await?;
        Ok(())
    }

    pub async fn challenge_for_job(
        &self,
        installation_id: Uuid,
        lease_id: Uuid,
        cleanup: bool,
    ) -> Result<Option<ChallengeLease>, StoreError> {
        if cleanup {
            let active: i64 = sqlx::query_scalar("SELECT count(*) FROM challenge_leases WHERE installation_id=$1 AND lease_id<>$2 AND deleted_at IS NULL AND expires_at>now()")
                .bind(installation_id).bind(lease_id).fetch_one(&self.pool).await?;
            if active > 0 {
                return Ok(None);
            }
        }
        let row = sqlx::query("SELECT txt_value,extract(epoch FROM expires_at)*1000 AS expiry FROM challenge_leases WHERE installation_id=$1 AND lease_id=$2 AND ($3 OR (deleted_at IS NULL AND expires_at>now()))")
            .bind(installation_id).bind(lease_id).bind(cleanup).fetch_optional(&self.pool).await?;
        Ok(row.map(|row| ChallengeLease {
            operation_id: lease_id,
            txt_value: row.get("txt_value"),
            expires_at_ms: row.get::<f64, _>("expiry") as u64,
        }))
    }

    pub async fn mark_challenge_ready(
        &self,
        installation_id: Uuid,
        lease_id: Uuid,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        let changed = sqlx::query("UPDATE challenge_leases SET dns_ready_at=now() WHERE installation_id=$1 AND lease_id=$2 AND dns_ready_at IS NULL AND deleted_at IS NULL AND expires_at>now()")
            .bind(installation_id).bind(lease_id).execute(&mut *tx).await?.rows_affected();
        if changed > 0 {
            sqlx::query("INSERT INTO security_audit(installation_id,operation_id,event) VALUES ($1,$2,'challenge_dns_ready')")
                .bind(installation_id).bind(lease_id).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        self.acknowledge().await?;
        Ok(())
    }

    pub async fn challenge_ready(
        &self,
        installation_id: Uuid,
        lease_id: Uuid,
    ) -> Result<bool, StoreError> {
        Ok(sqlx::query("SELECT 1 FROM challenge_leases WHERE installation_id=$1 AND lease_id=$2 AND dns_ready_at IS NOT NULL AND deleted_at IS NULL AND expires_at>now()")
            .bind(installation_id).bind(lease_id).fetch_optional(&self.pool).await?.is_some())
    }

    pub async fn claim_job(&self) -> Result<Option<OutboxJob>, StoreError> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("SELECT id, installation_id, kind, payload FROM outbox WHERE completed_at IS NULL AND next_attempt_at<=now() ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1")
            .fetch_optional(&mut *tx).await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let id: i64 = row.get("id");
        sqlx::query("UPDATE outbox SET attempts=attempts+1, next_attempt_at=now()+make_interval(secs=>GREATEST(60,LEAST(300,POWER(2,LEAST(8,attempts+1)))::int)) WHERE id=$1")
            .bind(id).execute(&mut *tx).await?;
        let job = OutboxJob {
            id,
            installation_id: row.get("installation_id"),
            kind: row.get("kind"),
            payload: row.get("payload"),
        };
        tx.commit().await?;
        self.acknowledge().await?;
        Ok(Some(job))
    }

    pub async fn complete_job(&self, id: i64) -> Result<(), StoreError> {
        sqlx::query("UPDATE outbox SET completed_at=now() WHERE id=$1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn allocate(
        &self,
        operation_id: Uuid,
        admin_public_key: [u8; 32],
        placement: &str,
    ) -> Result<Allocation, StoreError> {
        if placement.is_empty()
            || placement.len() > 64
            || !placement
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(StoreError::InvalidRequest);
        }
        let mut tx = self.pool.begin().await?;
        if let Some(row) = sqlx::query("SELECT i.installation_id, i.hostname, i.placement, i.state, i.admin_public_key FROM operations o JOIN installations i ON i.installation_id = o.installation_id WHERE o.operation_id = $1 FOR UPDATE OF i")
            .bind(operation_id).fetch_optional(&mut *tx).await? {
            let observed: Vec<u8> = row.try_get("admin_public_key")?;
            if observed != admin_public_key || row.try_get::<String, _>("placement")? != placement { return Err(StoreError::Conflict); }
            let allocation = allocation_from_row(&row)?;
            drop(tx);
            self.acknowledge().await?;
            return Ok(allocation);
        }
        let id = Uuid::new_v4();
        let mut random = [0u8; 16];
        OsRng.fill_bytes(&mut random);
        let hostname = format!(
            "{}.relay.bloom.directory",
            BASE32_NOPAD.encode(&random).to_ascii_lowercase()
        );
        sqlx::query("INSERT INTO installations(installation_id, hostname, admin_public_key, placement, state) VALUES ($1,$2,$3,$4,'pending_dns')")
            .bind(id).bind(&hostname).bind(admin_public_key.as_slice()).bind(placement).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO hostname_reservations(hostname, installation_id) VALUES ($1,$2)")
            .bind(&hostname)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        let allocation = Allocation {
            version: WIRE_VERSION,
            installation_id: id,
            hostname,
            placement: placement.into(),
            state: AllocationState::PendingDns,
        };
        let result = serde_json::to_value(&allocation).map_err(|_| StoreError::InvalidRequest)?;
        sqlx::query("INSERT INTO operations(operation_id, installation_id, kind, request_digest, result) VALUES ($1,$2,'allocate',$3,$4)")
            .bind(operation_id).bind(id).bind(vec![0u8; 32]).bind(result).execute(&mut *tx).await?;
        sqlx::query(
            "INSERT INTO outbox(installation_id,kind,payload) VALUES ($1,'publish_name',$2)",
        )
        .bind(id)
        .bind(serde_json::json!({"hostname": allocation.hostname, "placement": placement}))
        .execute(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO security_audit(installation_id,operation_id,event) VALUES ($1,$2,'allocated')")
            .bind(id).bind(operation_id).execute(&mut *tx).await?;
        tx.commit().await?;
        self.acknowledge().await?;
        Ok(allocation)
    }

    pub async fn claim_tunnel(
        &self,
        installation_id: Uuid,
        gateway_id: &str,
        ttl_seconds: i32,
    ) -> Result<u64, StoreError> {
        if gateway_id.is_empty() || !(5..=60).contains(&ttl_seconds) {
            return Err(StoreError::InvalidRequest);
        }
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("UPDATE installations SET generation = generation + 1 WHERE installation_id = $1 AND state = 'dns_ready' RETURNING generation")
            .bind(installation_id).fetch_optional(&mut *tx).await?.ok_or(StoreError::Conflict)?;
        let generation: i64 = row.try_get("generation")?;
        sqlx::query("INSERT INTO tunnel_leases(installation_id,generation,gateway_id,expires_at) VALUES ($1,$2,$3,now() + make_interval(secs => $4)) ON CONFLICT (installation_id) DO UPDATE SET generation = EXCLUDED.generation, gateway_id = EXCLUDED.gateway_id, expires_at = EXCLUDED.expires_at")
            .bind(installation_id).bind(generation).bind(gateway_id).bind(ttl_seconds).execute(&mut *tx).await?;
        sqlx::query(
            "INSERT INTO security_audit(installation_id,event) VALUES ($1,'tunnel_claimed')",
        )
        .bind(installation_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        self.acknowledge().await?;
        Ok(generation as u64)
    }

    pub async fn tunnel_is_current(
        &self,
        installation_id: Uuid,
        gateway_id: &str,
        generation: u64,
    ) -> Result<bool, StoreError> {
        self.verify_integrity().await?;
        let row = sqlx::query("SELECT 1 FROM tunnel_leases WHERE installation_id = $1 AND gateway_id = $2 AND generation = $3 AND expires_at > now()")
            .bind(installation_id).bind(gateway_id).bind(generation as i64).fetch_optional(&self.pool).await?;
        Ok(row.is_some())
    }

    pub async fn renew_tunnel(
        &self,
        installation_id: Uuid,
        gateway_id: &str,
        generation: u64,
    ) -> Result<bool, StoreError> {
        let changed = sqlx::query("UPDATE tunnel_leases SET expires_at=now()+interval '45 seconds' WHERE installation_id=$1 AND gateway_id=$2 AND generation=$3 AND expires_at>now()")
            .bind(installation_id).bind(gateway_id).bind(generation as i64).execute(&self.pool).await?.rows_affected();
        Ok(changed == 1)
    }

    pub async fn retire(
        &self,
        installation_id: Uuid,
        operation_id: Uuid,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        let changed = sqlx::query("UPDATE installations SET state='retired', retired_at=now(), generation=generation+1 WHERE installation_id=$1 AND state != 'retired'")
            .bind(installation_id).execute(&mut *tx).await?.rows_affected();
        if changed > 0 {
            sqlx::query("DELETE FROM tunnel_leases WHERE installation_id=$1")
                .bind(installation_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("INSERT INTO outbox(installation_id,kind,payload) VALUES ($1,'remove_records','{}'::jsonb)")
                .bind(installation_id).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO security_audit(installation_id,operation_id,event) VALUES ($1,$2,'retired')")
                .bind(installation_id).bind(operation_id).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        self.acknowledge().await?;
        Ok(())
    }
}

fn allocation_from_row(row: &sqlx::postgres::PgRow) -> Result<Allocation, StoreError> {
    let state: String = row.try_get("state")?;
    let state = match state.as_str() {
        "pending_dns" => AllocationState::PendingDns,
        "dns_ready" => AllocationState::DnsReady,
        "retired" => AllocationState::Retired,
        _ => return Err(StoreError::InvalidRequest),
    };
    Ok(Allocation {
        version: WIRE_VERSION,
        installation_id: row.try_get("installation_id")?,
        hostname: row.try_get("hostname")?,
        placement: row.try_get("placement")?,
        state,
    })
}
