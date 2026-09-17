use bloom_relay_dns::{
    CloudflareProvider, CloudflareScope, DnsError, HickoryObserver, NameRecords, Provider,
    Route53Provider, TxtLease,
};
use bloom_relay_store::{DnsJobScope, OutboxJob, Store};
use std::{env, io::Read, net::IpAddr, time::Duration};
use uuid::Uuid;

pub struct DnsWorker {
    store: Store,
    placement: String,
    scope: DnsJobScope,
    provider: DnsProvider,
    observer: HickoryObserver,
    ingress: Vec<IpAddr>,
}

impl DnsWorker {
    pub async fn configured(
        store: Store,
        placement: String,
        scope: DnsJobScope,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let zone = env::var("BLOOM_RELAY_DNS_ZONE_ID")?;
        let ingress = addresses("BLOOM_RELAY_INGRESS_ADDRESSES")?;
        let authoritative = addresses("BLOOM_RELAY_AUTHORITATIVE_ADDRESSES")?;
        let provider_name = match env::var("BLOOM_RELAY_DNS_PROVIDER") {
            Ok(value) => value,
            Err(env::VarError::NotPresent) => "route53".to_owned(),
            Err(env::VarError::NotUnicode(_)) => return Err("invalid DNS provider selector".into()),
        };
        let provider = match ProviderKind::parse(&provider_name)? {
            ProviderKind::Cloudflare => {
                let token_path = env::var("BLOOM_RELAY_CLOUDFLARE_TOKEN_FILE")?;
                let token = cloudflare_token(&token_path)?;
                let scope = match scope {
                    DnsJobScope::Serving => CloudflareScope::Serving,
                    DnsJobScope::Challenge => CloudflareScope::Challenge,
                };
                DnsProvider::Cloudflare(CloudflareProvider::new(zone, token, scope)?)
            }
            ProviderKind::Route53 => {
                let aws = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
                DnsProvider::Route53(Route53Provider::new(
                    aws_sdk_route53::Client::new(&aws),
                    zone,
                )?)
            }
        };
        Ok(Self {
            store,
            placement,
            scope,
            provider,
            observer: HickoryObserver::new(authoritative)?,
            ingress,
        })
    }

    pub async fn run(self) {
        loop {
            if let Ok(Some(seconds)) = sqlx::query_scalar::<_, Option<f64>>("SELECT max(extract(epoch FROM now()-o.next_attempt_at)) FROM outbox o JOIN installations i USING (installation_id) WHERE o.completed_at IS NULL AND i.placement=$1 AND (($2='serving' AND o.kind IN ('publish_name','remove_records')) OR ($2='challenge' AND o.kind IN ('publish_txt','remove_txt','remove_txt_all')))")
                .bind(&self.placement).bind(self.scope.as_str()).fetch_one(self.store.pool()).await {
                bloom_relay_observe::gauge("bloom_relay_dns_job_lag_seconds", seconds.max(0.0));
            }
            match self.store.claim_job(&self.placement, self.scope).await {
                Ok(Some(job)) => {
                    let id = job.id;
                    match self.process(job).await {
                        Ok(true) => {
                            bloom_relay_observe::count("bloom_relay_dns_jobs_completed_total");
                            if let Err(error) = self.store.complete_job(id).await {
                                tracing::warn!(job_id=id, error=%error, "DNS job completion failed");
                            }
                        }
                        Ok(false) => {
                            bloom_relay_observe::count("bloom_relay_dns_jobs_pending_total")
                        }
                        Err(error) => {
                            bloom_relay_observe::count("bloom_relay_dns_jobs_failed_total");
                            tracing::warn!(job_id=id, error=%error, "DNS job will retry");
                        }
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
        self.store.verify_integrity().await?;
        lock.commit().await?;
        result
    }

    async fn process_locked(
        &self,
        job: OutboxJob,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let installation = job.installation_id;
        if !job_allowed(self.scope, &job.kind) {
            return Err("DNS job outside worker scope".into());
        }
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
                self.store.verify_integrity().await?;
                self.provider.publish_name(records.clone()).await?;
                self.store.verify_integrity().await?;
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
                    self.store.verify_integrity().await?;
                    self.provider.delete_txt(&txt).await?;
                    self.store.verify_integrity().await?;
                    Ok(self.observer.txt_absent(&hostname, &txt.value).await?)
                } else {
                    self.store.verify_integrity().await?;
                    self.provider.create_txt(txt.clone()).await?;
                    self.store.verify_integrity().await?;
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
                self.store.verify_integrity().await?;
                self.provider.retire_name(&hostname).await?;
                self.store.verify_integrity().await?;
                Ok(self.observer.name_absent(&hostname).await?)
            }
            "remove_txt_all" => {
                let Some(hostname) = self.store.retired_hostname(installation).await? else {
                    return Ok(true);
                };
                self.store.verify_integrity().await?;
                self.provider.retire_challenge(&hostname).await?;
                self.store.verify_integrity().await?;
                Ok(self.observer.challenge_absent(&hostname).await?)
            }
            _ => Ok(false),
        }
    }
}

enum DnsProvider {
    Route53(Route53Provider),
    Cloudflare(CloudflareProvider),
}

#[derive(Debug, Eq, PartialEq)]
enum ProviderKind {
    Route53,
    Cloudflare,
}

impl ProviderKind {
    fn parse(value: &str) -> Result<Self, &'static str> {
        match value {
            "route53" => Ok(Self::Route53),
            "cloudflare" => Ok(Self::Cloudflare),
            _ => Err("invalid BLOOM_RELAY_DNS_PROVIDER (expected route53 or cloudflare)"),
        }
    }
}

impl Provider for DnsProvider {
    async fn publish_name(&self, records: NameRecords) -> Result<(), DnsError> {
        match self {
            Self::Route53(provider) => provider.publish_name(records).await,
            Self::Cloudflare(provider) => provider.publish_name(records).await,
        }
    }

    async fn create_txt(&self, lease: TxtLease) -> Result<(), DnsError> {
        match self {
            Self::Route53(provider) => provider.create_txt(lease).await,
            Self::Cloudflare(provider) => provider.create_txt(lease).await,
        }
    }

    async fn delete_txt(&self, lease: &TxtLease) -> Result<(), DnsError> {
        match self {
            Self::Route53(provider) => provider.delete_txt(lease).await,
            Self::Cloudflare(provider) => provider.delete_txt(lease).await,
        }
    }

    async fn retire_name(&self, hostname: &str) -> Result<(), DnsError> {
        match self {
            Self::Route53(provider) => provider.retire_name(hostname).await,
            Self::Cloudflare(provider) => provider.retire_name(hostname).await,
        }
    }

    async fn retire_challenge(&self, hostname: &str) -> Result<(), DnsError> {
        match self {
            Self::Route53(provider) => provider.retire_challenge(hostname).await,
            Self::Cloudflare(provider) => provider.retire_challenge(hostname).await,
        }
    }
}

fn job_allowed(scope: DnsJobScope, kind: &str) -> bool {
    match scope {
        DnsJobScope::Serving => matches!(kind, "publish_name" | "remove_records"),
        DnsJobScope::Challenge => matches!(kind, "publish_txt" | "remove_txt" | "remove_txt_all"),
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

fn cloudflare_token(path: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let mut contents = String::new();
    std::fs::File::open(path)?
        .take(4097)
        .read_to_string(&mut contents)?;
    if contents.len() > 4096 {
        return Err("Cloudflare token file too large".into());
    }
    Ok(contents.trim_end_matches(['\r', '\n']).to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn serving_and_challenge_roles_cannot_process_each_others_jobs() {
        assert!(job_allowed(DnsJobScope::Serving, "publish_name"));
        assert!(!job_allowed(DnsJobScope::Serving, "publish_txt"));
        assert!(job_allowed(DnsJobScope::Challenge, "remove_txt_all"));
        assert!(!job_allowed(DnsJobScope::Challenge, "remove_records"));
    }

    #[test]
    fn provider_selector_is_explicit_and_rejects_unknown_values() {
        assert_eq!(ProviderKind::parse("route53"), Ok(ProviderKind::Route53));
        assert_eq!(
            ProviderKind::parse("cloudflare"),
            Ok(ProviderKind::Cloudflare)
        );
        assert!(ProviderKind::parse("").is_err());
        assert!(ProviderKind::parse("CLOUDFLARE").is_err());
    }
}
