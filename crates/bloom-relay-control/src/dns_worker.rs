use bloom_relay_dns::{HickoryObserver, NameRecords, Provider, Route53Provider, TxtLease};
use bloom_relay_store::{OutboxJob, Store};
use std::{env, net::IpAddr, time::Duration};
use uuid::Uuid;

pub struct DnsWorker {
    store: Store,
    placement: String,
    provider: Route53Provider,
    observer: HickoryObserver,
    ingress: Vec<IpAddr>,
}

impl DnsWorker {
    pub async fn configured(
        store: Store,
        placement: String,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let zone = env::var("BLOOM_RELAY_DNS_ZONE_ID")?;
        let ingress = addresses("BLOOM_RELAY_INGRESS_ADDRESSES")?;
        let authoritative = addresses("BLOOM_RELAY_AUTHORITATIVE_ADDRESSES")?;
        let aws = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        Ok(Self {
            store,
            placement,
            provider: Route53Provider::new(aws_sdk_route53::Client::new(&aws), zone)?,
            observer: HickoryObserver::new(authoritative)?,
            ingress,
        })
    }

    pub async fn run(self) {
        loop {
            match self.store.claim_job(&self.placement).await {
                Ok(Some(job)) => {
                    let id = job.id;
                    match self.process(job).await {
                        Ok(true) => {
                            if let Err(error) = self.store.complete_job(id).await {
                                tracing::warn!(job_id=id, error=%error, "DNS job completion failed");
                            }
                        }
                        Ok(false) => {}
                        Err(error) => tracing::warn!(job_id=id, error=%error, "DNS job will retry"),
                    }
                }
                Ok(None) => tokio::time::sleep(Duration::from_secs(1)).await,
                Err(error) => {
                    tracing::warn!(error=%error, "DNS outbox unavailable");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }

    async fn process(
        &self,
        job: OutboxJob,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        // Serialize provider writes with operator placement moves. The advisory
        // lock has transaction lifetime, including DNS observation.
        let mut lock = self.store.pool().begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(job.installation_id.to_string())
            .execute(&mut *lock)
            .await?;
        let result = self.process_locked(job).await;
        lock.commit().await?;
        result
    }

    async fn process_locked(
        &self,
        job: OutboxJob,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let installation = job.installation_id;
        match job.kind.as_str() {
            "publish_name" => {
                let Some((hostname, acme_account_uri, placement)) =
                    self.store.dns_identity(installation).await?
                else {
                    return Ok(true);
                };
                if placement != self.placement {
                    return Ok(false);
                }
                let records = NameRecords {
                    hostname,
                    acme_account_uri,
                    addresses: self.ingress.clone(),
                };
                self.provider.publish_name(records.clone()).await?;
                if !self.observer.name_visible(&records).await? {
                    return Ok(false);
                }
                self.store.mark_dns_ready(installation).await?;
                Ok(true)
            }
            "publish_txt" | "remove_txt" => {
                let Some(lease_id) = job
                    .payload
                    .get("lease_id")
                    .and_then(|value| value.as_str())
                    .and_then(|value| Uuid::parse_str(value).ok())
                else {
                    return Ok(false);
                };
                let cleanup = job.kind == "remove_txt";
                let Some((hostname, _, placement)) = self.store.dns_identity(installation).await?
                else {
                    return Ok(true);
                };
                if placement != self.placement {
                    return Ok(false);
                }
                let Some(lease) = self
                    .store
                    .challenge_for_job(installation, lease_id, cleanup)
                    .await?
                else {
                    return Ok(true);
                };
                let txt = TxtLease {
                    hostname: hostname.clone(),
                    lease_id: lease_id.to_string(),
                    value: lease.txt_value,
                    expires_at_ms: lease.expires_at_ms,
                };
                if cleanup {
                    self.provider.delete_txt(&txt).await?;
                    Ok(self.observer.txt_absent(&hostname, &txt.value).await?)
                } else {
                    self.provider.create_txt(txt.clone()).await?;
                    if !self.observer.txt_visible(&hostname, &txt.value).await? {
                        return Ok(false);
                    }
                    self.store
                        .mark_challenge_ready(installation, lease_id)
                        .await?;
                    Ok(true)
                }
            }
            "remove_records" => {
                let Some(hostname) = self.store.retired_hostname(installation).await? else {
                    return Ok(true);
                };
                self.provider.retire_name(&hostname).await?;
                Ok(self.observer.name_absent(&hostname).await?)
            }
            _ => Ok(false),
        }
    }
}

fn addresses(key: &str) -> Result<Vec<IpAddr>, Box<dyn std::error::Error + Send + Sync>> {
    let parsed = env::var(key)?
        .split(',')
        .map(str::parse::<IpAddr>)
        .collect::<Result<Vec<_>, _>>()?;
    if parsed.is_empty() || parsed.len() > 8 || parsed.iter().any(IpAddr::is_unspecified) {
        return Err(format!("invalid {key}").into());
    }
    Ok(parsed)
}
