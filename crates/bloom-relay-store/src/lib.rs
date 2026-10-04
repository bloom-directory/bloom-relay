//! PostgreSQL authority for durable relay identity, tombstones and generations.

use bloom_relay_protocol::{
    AcmeEnvironment, Allocation, AllocationState, CHALLENGE_VALUE_LIFETIME_MS,
    MAX_LIVE_CHALLENGE_VALUES, WIRE_VERSION, validate_challenge_value,
};
use data_encoding::BASE32_NOPAD;
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row, postgres::PgConnectOptions};
use std::net::IpAddr;
use std::{path::PathBuf, sync::Arc};
use thiserror::Error;
use uuid::Uuid;
mod restore;
pub use restore::{
    RemoteRevision, RemoteWitness, RemoteWrite, RestoreWitness, WitnessError, WitnessFuture,
};
mod ct;
pub mod s3_witness;
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

/// How long after expiry the newest scoped credential may still renew
/// itself. Covers a host asleep or offline through its renewal window.
pub const RENEWAL_GRACE: std::time::Duration = std::time::Duration::from_secs(7 * 24 * 60 * 60);

#[derive(Clone)]
pub struct Store {
    pool: PgPool,
    witness: Option<Arc<RestoreWitness>>,
    acme_environment: AcmeEnvironment,
}

/// The result of ensuring a challenge value.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ChallengeValueState {
    pub revision: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug)]
pub struct OutboxJob {
    pub id: i64,
    /// The attempt this claim made; identifies the claim for `defer_job`.
    pub attempt: i32,
    pub installation_id: Uuid,
    pub kind: String,
    pub payload: serde_json::Value,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsJobScope {
    Serving,
    Challenge,
}

impl DnsJobScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Serving => "serving",
            Self::Challenge => "challenge",
        }
    }
}

/// Names a file holding the database password, for services that receive it
/// as a systemd credential. Those files are mode 0440, which PostgreSQL's
/// pgpass convention (and sqlx) rejects as too permissive.
const PASSWORD_FILE_ENV: &str = "BLOOM_RELAY_DATABASE_PASSWORD_FILE";

/// Connection settings from `url`, with the password taken from
/// `BLOOM_RELAY_DATABASE_PASSWORD_FILE` when it is set. The file holds only
/// the password; one trailing newline is ignored.
fn connect_options(url: &str) -> Result<PgConnectOptions, StoreError> {
    let options: PgConnectOptions = url.parse()?;
    let Some(path) = std::env::var_os(PASSWORD_FILE_ENV) else {
        return Ok(options);
    };
    let password = std::fs::read_to_string(path).map_err(sqlx::Error::Io)?;
    let password = password.strip_suffix('\n').unwrap_or(&password);
    if password.is_empty() || password.contains('\n') {
        return Err(StoreError::InvalidRequest);
    }
    Ok(options.password(password))
}

impl Store {
    pub async fn connect(url: &str) -> Result<Self, StoreError> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(16)
            .connect_with(connect_options(url)?)
            .await?;
        sqlx::migrate!("../../migrations").run(&pool).await?;
        Ok(Self {
            pool,
            witness: None,
            acme_environment: AcmeEnvironment::Production,
        })
    }

    pub async fn connect_with_witness(url: &str, path: PathBuf) -> Result<Self, StoreError> {
        let mut store = Self::connect(url).await?;
        store.witness = Some(Arc::new(
            RestoreWitness::from_env(path)
                .await
                .map_err(|error| StoreError::Witness(error.to_string()))?,
        ));
        store.acknowledge().await?;
        Ok(store)
    }

    /// Service startup checks schema version without taking migration locks or
    /// requiring DDL privileges. Operators run the migrator separately.
    pub async fn connect_runtime_with_witness(
        url: &str,
        path: PathBuf,
    ) -> Result<Self, StoreError> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(16)
            .connect_with(connect_options(url)?)
            .await?;
        let versions: Vec<(i64, Vec<u8>, bool)> = sqlx::query_as(
            "SELECT version,checksum,success FROM _sqlx_migrations ORDER BY version",
        )
        .fetch_all(&pool)
        .await?;
        let embedded = sqlx::migrate!("../../migrations");
        let expected: Vec<_> = embedded
            .migrations
            .iter()
            .map(|migration| (migration.version, migration.checksum.to_vec(), true))
            .collect();
        if versions != expected {
            return Err(StoreError::InvalidRequest);
        }
        let store = Self {
            pool,
            witness: Some(Arc::new(
                RestoreWitness::from_env(path)
                    .await
                    .map_err(|error| StoreError::Witness(error.to_string()))?,
            )),
            acme_environment: AcmeEnvironment::Production,
        };
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

    /// Restricts future ACME account registration to one reviewed Let's Encrypt
    /// environment. Existing owner-bound rows remain readable by runtime workers.
    pub fn with_acme_environment(mut self, environment: AcmeEnvironment) -> Self {
        self.acme_environment = environment;
        self
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

    /// Issues a bootstrap challenge unless the source or the relay is over
    /// quota: 10 per source and 100 overall per minute, and 20 completed
    /// enrollments per source per day. Consumed challenges stay counted, and a
    /// transaction lock serializes the count and insert.
    pub async fn create_bootstrap_challenge(
        &self,
        nonce: &str,
        source: IpAddr,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('bloom-relay/bootstrap-quota'))")
            .execute(&mut *tx)
            .await?;
        let row = sqlx::query("SELECT (SELECT count(*) FROM bootstrap_challenges WHERE source_ip=$1::inet AND created_at>now()-interval '1 minute') AS local_count, (SELECT count(*) FROM bootstrap_challenges WHERE created_at>now()-interval '1 minute') AS global_count, (SELECT count(*) FROM bootstrap_challenges WHERE source_ip=$1::inet AND created_at>now()-interval '1 day 1 minute' AND consumed_at>now()-interval '1 day') AS daily_enrollments")
            .bind(source.to_string()).fetch_one(&mut *tx).await?;
        let local: i64 = row.get("local_count");
        let global: i64 = row.get("global_count");
        let daily: i64 = row.get("daily_enrollments");
        if local >= 10 || global >= 100 || daily >= 20 {
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
        let changed = sqlx::query("UPDATE bootstrap_challenges SET consumed_at=now() WHERE nonce=$1 AND source_ip=$2::inet AND expires_at>now() AND consumed_at IS NULL")
            .bind(nonce).bind(source.to_string()).execute(&self.pool).await?.rows_affected();
        Ok(changed == 1)
    }

    /// Removes bootstrap challenge history older than the quota windows and
    /// expired replay nonces, at most `limit` rows of each per call.
    pub async fn prune_bootstrap_and_nonces(&self, limit: i64) -> Result<u64, StoreError> {
        if !(1..=10_000).contains(&limit) {
            return Err(StoreError::InvalidRequest);
        }
        let challenges = sqlx::query("DELETE FROM bootstrap_challenges WHERE nonce IN (SELECT nonce FROM bootstrap_challenges WHERE created_at<now()-interval '2 days' ORDER BY created_at LIMIT $1)")
            .bind(limit).execute(&self.pool).await?.rows_affected();
        let nonces = sqlx::query("DELETE FROM used_nonces WHERE (installation_id,nonce) IN (SELECT installation_id,nonce FROM used_nonces WHERE expires_at<now() ORDER BY expires_at LIMIT $1)")
            .bind(limit).execute(&self.pool).await?.rows_affected();
        self.acknowledge().await?;
        Ok(challenges + nonces)
    }

    pub async fn admin_public_key(
        &self,
        installation_id: Uuid,
    ) -> Result<Option<[u8; 32]>, StoreError> {
        let row =
            sqlx::query("SELECT admin_public_key FROM installations WHERE installation_id=$1")
                .bind(installation_id)
                .fetch_optional(&self.pool)
                .await?;
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

    /// Authenticate a scoped bearer and report its installation's state in
    /// one snapshot: `Some((generation, state))` for a current credential.
    /// Lets a caller tell an early request (serving DNS still pending) from an
    /// unauthorized one without racing the transition to `dns_ready`.
    pub async fn authenticate_bearer_with_state(
        &self,
        installation_id: Uuid,
        scope: &str,
        bearer: &str,
    ) -> Result<Option<(u64, String)>, StoreError> {
        if bearer.len() < 43 || bearer.len() > 128 || !matches!(scope, "tunnel" | "dns_challenge") {
            return Ok(None);
        }
        let digest = Sha256::digest(bearer.as_bytes());
        let row = sqlx::query("SELECT c.generation, i.state FROM scoped_bearer_credentials c JOIN installations i USING (installation_id) WHERE c.installation_id=$1 AND c.scope=$2 AND c.token_hash=$3 AND c.revoked_at IS NULL AND c.expires_at > now() ORDER BY c.generation DESC LIMIT 1")
            .bind(installation_id).bind(scope).bind(digest.as_slice()).fetch_optional(&self.pool).await?;
        Ok(row.map(|row| (row.get::<i64, _>("generation") as u64, row.get("state"))))
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

    pub async fn allocation_status(
        &self,
        installation_id: Uuid,
    ) -> Result<Option<Allocation>, StoreError> {
        let row = sqlx::query("SELECT installation_id,hostname,placement,state FROM installations WHERE installation_id=$1")
            .bind(installation_id).fetch_optional(&self.pool).await?;
        row.map(|row| allocation_from_row(&row)).transpose()
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
        // Lock order for credentials: the installation row first, then any
        // credential row (as issue_bearer and ensure_challenge_value do), so
        // concurrent renewals, issues and challenge changes cannot deadlock.
        sqlx::query(
            "SELECT installation_id FROM installations WHERE installation_id=$1 FOR UPDATE",
        )
        .bind(installation_id)
        .execute(&mut *tx)
        .await?;
        // A credential may renew for RENEWAL_GRACE after it expires, so a
        // Broker that slept through its renewal window recovers on wake. Only
        // the newest unrevoked credential for the scope qualifies, so a
        // superseded token can never renew; an expired one still cannot open
        // a tunnel (`authenticate_bearer` requires an unexpired credential).
        let row = sqlx::query("SELECT c.token_hash, c.expires_at<=now() AS expired FROM scoped_bearer_credentials c JOIN installations i USING (installation_id) WHERE c.installation_id=$1 AND c.scope=$2 AND c.generation=$3 AND c.revoked_at IS NULL AND c.expires_at>now()-make_interval(secs => $4) AND i.state='dns_ready' AND NOT EXISTS (SELECT 1 FROM scoped_bearer_credentials n WHERE n.installation_id=c.installation_id AND n.scope=c.scope AND n.generation>c.generation) FOR UPDATE OF c")
            .bind(installation_id).bind(scope).bind(generation as i64).bind(RENEWAL_GRACE.as_secs_f64()).fetch_optional(&mut *tx).await?.ok_or(StoreError::Unauthorized)?;
        let renewed_after_expiry: bool = row.get("expired");
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
        sqlx::query(
            "INSERT INTO security_audit(installation_id,operation_id,event) VALUES ($1,$2,$3)",
        )
        .bind(installation_id)
        .bind(operation_id)
        .bind(if renewed_after_expiry {
            "credential_renewed_after_expiry"
        } else {
            "credential_renewed"
        })
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        self.acknowledge().await?;
        Ok((next as u64, expires_at_ms as u64))
    }

    pub async fn register_acme_account(
        &self,
        installation_id: Uuid,
        account_uri: &str,
    ) -> Result<(), StoreError> {
        if self
            .acme_environment
            .validate_account_uri(account_uri)
            .is_err()
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
    ) -> Result<Option<(String, String, String)>, StoreError> {
        let row = sqlx::query("SELECT hostname, acme_account_uri, placement FROM installations WHERE installation_id=$1 AND state!='retired' AND acme_account_uri IS NOT NULL")
            .bind(installation_id).fetch_optional(&self.pool).await?;
        Ok(row.map(|row| {
            (
                row.get("hostname"),
                row.get("acme_account_uri"),
                row.get("placement"),
            )
        }))
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

    /// Ensure a DNS-01 TXT value is published for a `dns_ready` installation.
    /// A live value is refreshed without changing the published set (and so
    /// without resetting readiness); otherwise it joins the set, lapsed values
    /// are dropped, the revision advances and a reconciliation is queued. At
    /// most [`MAX_LIVE_CHALLENGE_VALUES`] distinct values are live at once.
    pub async fn ensure_challenge_value(
        &self,
        installation_id: Uuid,
        generation: u64,
        txt_value: &str,
    ) -> Result<ChallengeValueState, StoreError> {
        validate_challenge_value(txt_value).map_err(|_| StoreError::InvalidRequest)?;
        let mut tx = self.pool.begin().await?;
        // The installation row serializes every change to its challenge set.
        sqlx::query("SELECT installation_id FROM installations WHERE installation_id=$1 AND state='dns_ready' FOR UPDATE")
            .bind(installation_id).fetch_optional(&mut *tx).await?.ok_or(StoreError::Conflict)?;
        // The authenticating credential must still be current; FOR SHARE
        // serializes with revocation (installation row first, as elsewhere).
        sqlx::query("SELECT 1 FROM scoped_bearer_credentials WHERE installation_id=$1 AND scope='dns_challenge' AND generation=$2 AND revoked_at IS NULL AND expires_at>now() FOR SHARE")
            .bind(installation_id).bind(generation as i64).fetch_optional(&mut *tx).await?
            .ok_or(StoreError::Unauthorized)?;
        sqlx::query(
            "INSERT INTO challenge_state(installation_id) VALUES ($1) ON CONFLICT DO NOTHING",
        )
        .bind(installation_id)
        .execute(&mut *tx)
        .await?;
        let lifetime = CHALLENGE_VALUE_LIFETIME_MS as f64 / 1000.0;
        let refreshed = sqlx::query("UPDATE challenge_values SET expires_at=now()+make_interval(secs=>$3) WHERE installation_id=$1 AND txt_value=$2 AND expires_at>now() RETURNING (extract(epoch FROM expires_at)*1000)::bigint AS expiry")
            .bind(installation_id).bind(txt_value).bind(lifetime)
            .fetch_optional(&mut *tx).await?;
        let expiry: i64 = if let Some(row) = refreshed {
            row.get("expiry")
        } else {
            let live: i64 = sqlx::query_scalar("SELECT count(*) FROM challenge_values WHERE installation_id=$1 AND expires_at>now()")
                .bind(installation_id).fetch_one(&mut *tx).await?;
            if live as usize >= MAX_LIVE_CHALLENGE_VALUES {
                return Err(StoreError::Conflict);
            }
            sqlx::query(
                "DELETE FROM challenge_values WHERE installation_id=$1 AND expires_at<=now()",
            )
            .bind(installation_id)
            .execute(&mut *tx)
            .await?;
            let expiry: i64 = sqlx::query_scalar("INSERT INTO challenge_values(installation_id,txt_value,expires_at) VALUES ($1,$2,now()+make_interval(secs=>$3)) RETURNING (extract(epoch FROM expires_at)*1000)::bigint")
                .bind(installation_id).bind(txt_value).bind(lifetime)
                .fetch_one(&mut *tx).await?;
            Self::challenge_set_changed(&mut tx, installation_id, "challenge_value_added").await?;
            expiry
        };
        let revision: i64 =
            sqlx::query_scalar("SELECT revision FROM challenge_state WHERE installation_id=$1")
                .bind(installation_id)
                .fetch_one(&mut *tx)
                .await?;
        tx.commit().await?;
        self.acknowledge().await?;
        Ok(ChallengeValueState {
            revision: revision as u64,
            expires_at_ms: expiry as u64,
        })
    }

    /// Advance the set's revision, queue its reconciliation and audit the
    /// change. Each change queues its own job: a worker that finishes an older
    /// revision never consumes the request for a newer one.
    async fn challenge_set_changed(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        installation_id: Uuid,
        event: &str,
    ) -> Result<(), StoreError> {
        sqlx::query("UPDATE challenge_state SET revision=revision+1 WHERE installation_id=$1")
            .bind(installation_id)
            .execute(&mut **tx)
            .await?;
        sqlx::query("INSERT INTO outbox(installation_id,kind,payload) VALUES ($1,'reconcile_txt','{}'::jsonb)")
            .bind(installation_id).execute(&mut **tx).await?;
        sqlx::query("INSERT INTO security_audit(installation_id,event) VALUES ($1,$2)")
            .bind(installation_id)
            .bind(event)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    /// Whether `txt_value` is live and the published set, at or after
    /// `revision`, has been observed on DNS.
    pub async fn challenge_value_ready(
        &self,
        installation_id: Uuid,
        txt_value: &str,
        revision: u64,
    ) -> Result<bool, StoreError> {
        let revision = i64::try_from(revision).map_err(|_| StoreError::InvalidRequest)?;
        Ok(sqlx::query("SELECT 1 FROM challenge_state s JOIN challenge_values v USING (installation_id) WHERE s.installation_id=$1 AND v.txt_value=$2 AND v.expires_at>now() AND s.ready_revision=s.revision AND s.ready_revision>=$3")
            .bind(installation_id).bind(txt_value).bind(revision)
            .fetch_optional(&self.pool).await?.is_some())
    }

    /// The set the challenge worker should publish: the revision and stored
    /// membership, in one snapshot. Lapsed values stay until an ensure or the
    /// sweep removes them (both advance the revision), so a concurrent refresh
    /// can never be dropped from a revision that is then marked ready.
    pub async fn challenge_target(
        &self,
        installation_id: Uuid,
    ) -> Result<(u64, Vec<String>), StoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await?;
        let revision: Option<i64> =
            sqlx::query_scalar("SELECT revision FROM challenge_state WHERE installation_id=$1")
                .bind(installation_id)
                .fetch_optional(&mut *tx)
                .await?;
        let values: Vec<String> = sqlx::query_scalar(
            "SELECT txt_value FROM challenge_values WHERE installation_id=$1 ORDER BY txt_value",
        )
        .bind(installation_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok((revision.unwrap_or(0) as u64, values))
    }

    /// Record that `revision` is published and observed. Returns false when the
    /// set changed meanwhile; that change queued its own reconciliation.
    pub async fn mark_challenge_reconciled(
        &self,
        installation_id: Uuid,
        revision: u64,
    ) -> Result<bool, StoreError> {
        let changed = sqlx::query(
            "UPDATE challenge_state SET ready_revision=$2 WHERE installation_id=$1 AND revision=$2",
        )
        .bind(installation_id)
        .bind(revision as i64)
        .execute(&self.pool)
        .await?
        .rows_affected();
        self.acknowledge().await?;
        Ok(changed == 1)
    }

    pub async fn claim_job(
        &self,
        placement: &str,
        scope: DnsJobScope,
    ) -> Result<Option<OutboxJob>, StoreError> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("SELECT o.id, o.installation_id, o.kind, o.payload FROM outbox o JOIN installations i USING (installation_id) WHERE i.placement=$1 AND (($2='serving' AND o.kind IN ('publish_name','remove_records')) OR ($2='challenge' AND o.kind IN ('reconcile_txt','remove_txt_all'))) AND o.completed_at IS NULL AND o.next_attempt_at<=now() ORDER BY o.id FOR UPDATE OF o SKIP LOCKED LIMIT 1")
            .bind(placement).bind(scope.as_str()).fetch_optional(&mut *tx).await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let id: i64 = row.get("id");
        // The claim leases the job for longer than any attempt may run (the
        // worker abandons an attempt after JOB_ATTEMPT_DEADLINE).
        let attempt: i32 = sqlx::query_scalar("UPDATE outbox SET attempts=attempts+1, next_attempt_at=now()+interval '120 seconds' WHERE id=$1 RETURNING attempts")
            .bind(id).fetch_one(&mut *tx).await?;
        let job = OutboxJob {
            id,
            attempt,
            installation_id: row.get("installation_id"),
            kind: row.get("kind"),
            payload: row.get("payload"),
        };
        tx.commit().await?;
        self.acknowledge().await?;
        Ok(Some(job))
    }

    /// Reschedule an unfinished job (change not visible yet, or a transient
    /// failure): 5 s after the first attempt, doubling to a 300 s cap. Applies
    /// only while `attempt` is still the job's latest claim, so a stale worker
    /// cannot shorten another worker's lease.
    pub async fn defer_job(&self, id: i64, attempt: i32) -> Result<(), StoreError> {
        sqlx::query("UPDATE outbox SET next_attempt_at=now()+make_interval(secs=>LEAST(300,5*POWER(2,LEAST(6,GREATEST(attempts-1,0))))::int) WHERE id=$1 AND attempts=$2 AND completed_at IS NULL")
            .bind(id)
            .bind(attempt)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn complete_job(&self, id: i64) -> Result<(), StoreError> {
        self.verify_integrity().await?;
        sqlx::query("UPDATE outbox SET completed_at=now() WHERE id=$1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        self.acknowledge().await?;
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
        let row = sqlx::query("UPDATE installations SET generation = generation + 1 WHERE installation_id = $1 AND state = 'dns_ready' AND placement=$2 RETURNING generation")
            .bind(installation_id).bind(gateway_id).fetch_optional(&mut *tx).await?.ok_or(StoreError::Conflict)?;
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

    pub async fn expire_pending_allocations(&self, limit: i64) -> Result<usize, StoreError> {
        if !(1..=100).contains(&limit) {
            return Err(StoreError::InvalidRequest);
        }
        let rows = sqlx::query("SELECT installation_id FROM installations WHERE state='pending_dns' AND created_at<now()-interval '24 hours' ORDER BY created_at LIMIT $1")
            .bind(limit).fetch_all(&self.pool).await?;
        let mut expired = 0;
        for row in rows {
            let id: Uuid = row.get("installation_id");
            let mut tx = self.pool.begin().await?;
            // A DNS publish already in progress must finish before removal is
            // queued; otherwise it could recreate records after cleanup.
            sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
                .bind(id.to_string())
                .execute(&mut *tx)
                .await?;
            let changed = sqlx::query("UPDATE installations SET state='retired',retired_at=now(),generation=generation+1 WHERE installation_id=$1 AND state='pending_dns' AND created_at<now()-interval '24 hours'")
                .bind(id).execute(&mut *tx).await?.rows_affected();
            if changed == 0 {
                continue;
            }
            sqlx::query("INSERT INTO outbox(installation_id,kind,payload) VALUES ($1,'remove_records','{}'::jsonb)")
                .bind(id).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO outbox(installation_id,kind,payload) VALUES ($1,'remove_txt_all','{}'::jsonb)")
                .bind(id).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO security_audit(installation_id,event) VALUES ($1,'pending_allocation_expired')")
                .bind(id).execute(&mut *tx).await?;
            tx.commit().await?;
            self.acknowledge().await?;
            expired += 1;
        }
        Ok(expired)
    }

    /// Drop lapsed challenge values, one installation per transaction, so the
    /// published sets shrink back. Returns the installations changed.
    pub async fn expire_challenge_values(&self, limit: i64) -> Result<usize, StoreError> {
        if !(1..=100).contains(&limit) {
            return Err(StoreError::InvalidRequest);
        }
        let installations: Vec<Uuid> = sqlx::query_scalar("SELECT DISTINCT installation_id FROM challenge_values WHERE expires_at<=now() LIMIT $1")
            .bind(limit).fetch_all(&self.pool).await?;
        let mut changed = 0;
        for installation_id in installations {
            let mut tx = self.pool.begin().await?;
            sqlx::query(
                "SELECT installation_id FROM installations WHERE installation_id=$1 FOR UPDATE",
            )
            .bind(installation_id)
            .execute(&mut *tx)
            .await?;
            let removed = sqlx::query(
                "DELETE FROM challenge_values WHERE installation_id=$1 AND expires_at<=now()",
            )
            .bind(installation_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if removed > 0 {
                Self::challenge_set_changed(&mut tx, installation_id, "challenge_value_expired")
                    .await?;
                changed += 1;
            }
            tx.commit().await?;
            self.acknowledge().await?;
        }
        Ok(changed)
    }

    pub async fn retire(
        &self,
        installation_id: Uuid,
        operation_id: Uuid,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(installation_id.to_string())
            .execute(&mut *tx)
            .await?;
        if let Some(existing) = sqlx::query(
            "SELECT installation_id,kind FROM operations WHERE operation_id=$1 FOR UPDATE",
        )
        .bind(operation_id)
        .fetch_optional(&mut *tx)
        .await?
        {
            let owner: Uuid = existing.get("installation_id");
            let kind: String = existing.get("kind");
            if owner != installation_id || kind != "retire" {
                return Err(StoreError::Conflict);
            }
            drop(tx);
            self.acknowledge().await?;
            return Ok(());
        }
        sqlx::query(
            "SELECT installation_id FROM installations WHERE installation_id=$1 FOR UPDATE",
        )
        .bind(installation_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StoreError::Conflict)?;
        let changed = sqlx::query("UPDATE installations SET state='retired', retired_at=now(), generation=generation+1 WHERE installation_id=$1 AND state != 'retired'")
            .bind(installation_id).execute(&mut *tx).await?.rows_affected();
        if changed > 0 {
            sqlx::query("DELETE FROM tunnel_leases WHERE installation_id=$1")
                .bind(installation_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("INSERT INTO outbox(installation_id,kind,payload) VALUES ($1,'remove_records','{}'::jsonb)")
                .bind(installation_id).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO outbox(installation_id,kind,payload) VALUES ($1,'remove_txt_all','{}'::jsonb)")
                .bind(installation_id).execute(&mut *tx).await?;
            sqlx::query("DELETE FROM challenge_values WHERE installation_id=$1")
                .bind(installation_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("INSERT INTO security_audit(installation_id,operation_id,event) VALUES ($1,$2,'retired')")
                .bind(installation_id).bind(operation_id).execute(&mut *tx).await?;
        }
        let mut hasher = Sha256::new();
        hasher.update(b"bloom-relay/retire/v1\0");
        hasher.update(installation_id.as_bytes());
        let digest = hasher.finalize();
        sqlx::query("INSERT INTO operations(operation_id,installation_id,kind,request_digest,result) VALUES ($1,$2,'retire',$3,'{}'::jsonb)")
            .bind(operation_id).bind(installation_id).bind(digest.as_slice()).execute(&mut *tx).await?;
        tx.commit().await?;
        self.acknowledge().await?;
        Ok(())
    }

    /// Operator-only move. The installation UUID and hostname remain stable;
    /// the old gateway lease is fenced before the new placement publishes DNS.
    pub async fn relocate(
        &self,
        installation_id: Uuid,
        operation_id: Uuid,
        placement: &str,
    ) -> Result<(), StoreError> {
        if placement.is_empty()
            || placement.len() > 64
            || !placement
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(StoreError::InvalidRequest);
        }
        let mut tx = self.pool.begin().await?;
        // DNS workers hold this lock while applying and observing provider changes.
        // A move cannot overtake an already claimed write from the old placement.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(installation_id.to_string())
            .execute(&mut *tx)
            .await?;
        if let Some(existing) = sqlx::query("SELECT installation_id,kind,request_digest FROM operations WHERE operation_id=$1 FOR UPDATE")
            .bind(operation_id).fetch_optional(&mut *tx).await? {
            let expected = relocation_digest(installation_id, placement);
            if existing.get::<Uuid, _>("installation_id") != installation_id
                || existing.get::<String, _>("kind") != "relocate"
                || existing.get::<Vec<u8>, _>("request_digest") != expected {
                return Err(StoreError::Conflict);
            }
            drop(tx);
            self.acknowledge().await?;
            return Ok(());
        }
        let row = sqlx::query("SELECT placement FROM installations WHERE installation_id=$1 AND state='dns_ready' FOR UPDATE")
            .bind(installation_id).fetch_optional(&mut *tx).await?.ok_or(StoreError::Conflict)?;
        let current: String = row.get("placement");
        if current == placement {
            return Err(StoreError::Conflict);
        }
        sqlx::query("UPDATE installations SET placement=$2,generation=generation+1 WHERE installation_id=$1")
            .bind(installation_id).bind(placement).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM tunnel_leases WHERE installation_id=$1")
            .bind(installation_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO outbox(installation_id,kind,payload) VALUES ($1,'publish_name',$2)",
        )
        .bind(installation_id)
        .bind(serde_json::json!({"placement":placement}))
        .execute(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO security_audit(installation_id,operation_id,event) VALUES ($1,$2,'placement_moved')")
            .bind(installation_id).bind(operation_id).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO operations(operation_id,installation_id,kind,request_digest,result) VALUES ($1,$2,'relocate',$3,'{}'::jsonb)")
            .bind(operation_id).bind(installation_id).bind(relocation_digest(installation_id, placement).as_slice()).execute(&mut *tx).await?;
        tx.commit().await?;
        self.acknowledge().await?;
        Ok(())
    }
}

fn relocation_digest(id: Uuid, placement: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"bloom-relay/relocate/v1\0");
    hasher.update(id.as_bytes());
    hasher.update(placement.as_bytes());
    hasher.finalize().into()
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
