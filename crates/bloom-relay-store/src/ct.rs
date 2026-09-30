use crate::{Store, StoreError};
use bloom_relay_protocol::{CertificateMetadata, validate_hostname};
use sqlx::Row;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct CtAlert {
    pub id: i64,
    pub source: String,
    pub position: u64,
    pub hostname: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone)]
pub struct CtLagAlert {
    pub id: i64,
    pub source: String,
    pub lag_seconds: u64,
}

impl Store {
    pub async fn ensure_ct_source(&self, source: &str) -> Result<(), StoreError> {
        validate_source(source)?;
        sqlx::query(
            "INSERT INTO ct_feed_checkpoints(source,position) VALUES ($1,0) ON CONFLICT DO NOTHING",
        )
        .bind(source)
        .execute(&self.pool)
        .await?;
        self.acknowledge().await
    }

    pub async fn ct_checkpoint(&self, source: &str) -> Result<Option<u64>, StoreError> {
        validate_source(source)?;
        let value: Option<i64> =
            sqlx::query_scalar("SELECT position FROM ct_feed_checkpoints WHERE source=$1")
                .bind(source)
                .fetch_optional(&self.pool)
                .await?;
        Ok(value.map(|position| position as u64))
    }

    pub async fn mark_ct_feed_healthy(
        &self,
        source: &str,
        position: u64,
    ) -> Result<(), StoreError> {
        validate_source(source)?;
        let changed = sqlx::query(
            "UPDATE ct_feed_checkpoints SET observed_at=now() WHERE source=$1 AND position=$2",
        )
        .bind(source)
        .bind(position as i64)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(StoreError::Conflict);
        }
        self.acknowledge().await
    }

    pub async fn pending_ct_alerts(
        &self,
        source: &str,
        limit: i64,
    ) -> Result<Vec<CtAlert>, StoreError> {
        validate_source(source)?;
        if !(1..=100).contains(&limit) {
            return Err(StoreError::InvalidRequest);
        }
        let rows = sqlx::query("SELECT id,position,hostname,fingerprint FROM ct_alerts WHERE source=$1 AND delivered_at IS NULL ORDER BY id LIMIT $2")
            .bind(source).bind(limit).fetch_all(&self.pool).await?;
        Ok(rows
            .into_iter()
            .map(|row| CtAlert {
                id: row.get("id"),
                source: source.into(),
                position: row.get::<i64, _>("position") as u64,
                hostname: row.get("hostname"),
                fingerprint: row.get("fingerprint"),
            })
            .collect())
    }

    pub async fn mark_ct_alert_delivered(&self, id: i64) -> Result<(), StoreError> {
        sqlx::query("UPDATE ct_alerts SET delivered_at=now() WHERE id=$1 AND delivered_at IS NULL")
            .bind(id)
            .execute(&self.pool)
            .await?;
        self.acknowledge().await
    }

    pub async fn queue_ct_lag_alert(&self, source: &str) -> Result<(), StoreError> {
        validate_source(source)?;
        sqlx::query("INSERT INTO ct_health_alerts(source,time_window,lag_seconds) SELECT source,(extract(epoch FROM now())/900)::bigint,extract(epoch FROM now()-observed_at)::bigint FROM ct_feed_checkpoints WHERE source=$1 AND observed_at<now()-interval '15 minutes' ON CONFLICT DO NOTHING")
            .bind(source).execute(&self.pool).await?;
        self.acknowledge().await
    }

    pub async fn pending_ct_lag_alerts(
        &self,
        source: &str,
        limit: i64,
    ) -> Result<Vec<CtLagAlert>, StoreError> {
        validate_source(source)?;
        if !(1..=100).contains(&limit) {
            return Err(StoreError::InvalidRequest);
        }
        let rows = sqlx::query("SELECT id,lag_seconds FROM ct_health_alerts WHERE source=$1 AND delivered_at IS NULL ORDER BY id LIMIT $2")
            .bind(source).bind(limit).fetch_all(&self.pool).await?;
        Ok(rows
            .into_iter()
            .map(|row| CtLagAlert {
                id: row.get("id"),
                source: source.into(),
                lag_seconds: row.get::<i64, _>("lag_seconds") as u64,
            })
            .collect())
    }

    pub async fn mark_ct_lag_alert_delivered(&self, id: i64) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE ct_health_alerts SET delivered_at=now() WHERE id=$1 AND delivered_at IS NULL",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        self.acknowledge().await
    }
    /// Broker reports only public certificate metadata; its key never enters relay control.
    pub async fn record_expected_certificate(
        &self,
        installation_id: Uuid,
        certificate: &CertificateMetadata,
    ) -> Result<(), StoreError> {
        validate_hostname(&certificate.hostname).map_err(|_| StoreError::InvalidRequest)?;
        validate_fingerprint(&certificate.key_fingerprint)?;
        if certificate.lineage.is_empty()
            || certificate.lineage.len() > 128
            || certificate.not_after_ms <= certificate.not_before_ms
        {
            return Err(StoreError::InvalidRequest);
        }
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("SELECT hostname,acme_account_uri FROM installations WHERE installation_id=$1 AND state='dns_ready' FOR UPDATE")
            .bind(installation_id).fetch_optional(&mut *tx).await?.ok_or(StoreError::Conflict)?;
        let hostname: String = row.get("hostname");
        let account: Option<String> = row.get("acme_account_uri");
        if hostname != certificate.hostname
            || account.as_deref() != Some(&certificate.acme_account_uri)
        {
            return Err(StoreError::Conflict);
        }
        sqlx::query("INSERT INTO certificate_inventory(installation_id,fingerprint,lineage,not_before,not_after) VALUES ($1,$2,$3,to_timestamp($4::double precision/1000.0),to_timestamp($5::double precision/1000.0)) ON CONFLICT (installation_id,fingerprint) DO NOTHING")
            .bind(installation_id).bind(&certificate.key_fingerprint).bind(&certificate.lineage)
            .bind(certificate.not_before_ms as i64).bind(certificate.not_after_ms as i64)
            .execute(&mut *tx).await?;
        sqlx::query(
            "INSERT INTO security_audit(installation_id,event) VALUES ($1,'certificate_expected')",
        )
        .bind(installation_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        self.acknowledge().await?;
        Ok(())
    }

    /// A CT feed adapter supplies contiguous positions and validated X.509
    /// fingerprints. Unknown or unregistered issuances become durable alerts.
    pub async fn observe_ct(
        &self,
        source: &str,
        position: u64,
        hostname: &str,
        fingerprint: &str,
    ) -> Result<bool, StoreError> {
        validate_hostname(hostname).map_err(|_| StoreError::InvalidRequest)?;
        validate_fingerprint(fingerprint)?;
        if validate_source(source).is_err() || position == 0 || position > i64::MAX as u64 {
            return Err(StoreError::InvalidRequest);
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO ct_feed_checkpoints(source,position) VALUES ($1,0) ON CONFLICT DO NOTHING",
        )
        .bind(source)
        .execute(&mut *tx)
        .await?;
        let row =
            sqlx::query("SELECT position FROM ct_feed_checkpoints WHERE source=$1 FOR UPDATE")
                .bind(source)
                .fetch_one(&mut *tx)
                .await?;
        let current: i64 = row.get("position");
        if position <= current as u64 {
            let previous = sqlx::query("SELECT hostname,fingerprint,expected FROM ct_observations WHERE source=$1 AND position=$2")
                .bind(source).bind(position as i64).fetch_optional(&mut *tx).await?.ok_or(StoreError::Conflict)?;
            let old_host: String = previous.get("hostname");
            let old_fingerprint: String = previous.get("fingerprint");
            if old_host != hostname || old_fingerprint != fingerprint {
                return Err(StoreError::Conflict);
            }
            let expected = previous.get("expected");
            drop(tx);
            self.acknowledge().await?;
            return Ok(expected);
        }
        if position != (current as u64) + 1 {
            return Err(StoreError::Conflict);
        }
        let row = sqlx::query("SELECT installation_id FROM installations WHERE hostname=$1")
            .bind(hostname)
            .fetch_optional(&mut *tx)
            .await?;
        let installation_id: Option<Uuid> = row.map(|row| row.get("installation_id"));
        let expected = if let Some(id) = installation_id {
            sqlx::query(
                "SELECT 1 FROM certificate_inventory WHERE installation_id=$1 AND fingerprint=$2",
            )
            .bind(id)
            .bind(fingerprint)
            .fetch_optional(&mut *tx)
            .await?
            .is_some()
        } else {
            false
        };
        sqlx::query("INSERT INTO ct_observations(source,position,installation_id,hostname,fingerprint,expected) VALUES ($1,$2,$3,$4,$5,$6)")
            .bind(source).bind(position as i64).bind(installation_id).bind(hostname).bind(fingerprint).bind(expected)
            .execute(&mut *tx).await?;
        if !expected {
            sqlx::query("INSERT INTO ct_alerts(source,position,installation_id,hostname,fingerprint) VALUES ($1,$2,$3,$4,$5)")
                .bind(source).bind(position as i64).bind(installation_id).bind(hostname).bind(fingerprint)
                .execute(&mut *tx).await?;
            if let Some(id) = installation_id {
                sqlx::query(
                    "INSERT INTO security_audit(installation_id,event) VALUES ($1,'unexpected_ct')",
                )
                .bind(id)
                .execute(&mut *tx)
                .await?;
            }
        }
        sqlx::query(
            "UPDATE ct_feed_checkpoints SET position=$2, observed_at=now() WHERE source=$1",
        )
        .bind(source)
        .bind(position as i64)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        self.acknowledge().await?;
        Ok(expected)
    }

    pub async fn ct_feed_lag_seconds(&self, source: &str) -> Result<Option<i64>, StoreError> {
        let value: Option<i64> = sqlx::query_scalar("SELECT extract(epoch FROM now()-observed_at)::bigint FROM ct_feed_checkpoints WHERE source=$1")
            .bind(source).fetch_optional(&self.pool).await?;
        Ok(value)
    }
}

fn validate_fingerprint(value: &str) -> Result<(), StoreError> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(StoreError::InvalidRequest);
    }
    Ok(())
}

fn validate_source(source: &str) -> Result<(), StoreError> {
    if source.is_empty()
        || source.len() > 64
        || !source
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(StoreError::InvalidRequest);
    }
    Ok(())
}
