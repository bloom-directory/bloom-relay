//! Exact-owner DNS changes; provider credentials remain in the control worker.

use bloom_relay_protocol::{ProtocolError, validate_hostname};
use std::{collections::BTreeMap, net::IpAddr, sync::Arc};
use thiserror::Error;
use tokio::sync::Mutex;

mod route53;
pub use route53::Route53Provider;
mod observer;
pub use observer::HickoryObserver;

pub const TTL_SECONDS: u32 = 300;
pub const ZONE: &str = "relay.bloom.directory";

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NameRecords {
    pub hostname: String,
    pub addresses: Vec<IpAddr>,
    pub acme_account_uri: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TxtLease {
    pub hostname: String,
    pub lease_id: String,
    pub value: String,
    pub expires_at_ms: u64,
}

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("invalid assigned hostname")]
    InvalidHostname(#[from] ProtocolError),
    #[error("invalid DNS change")]
    InvalidChange,
    #[error("DNS provider unavailable")]
    Unavailable,
    #[error("DNS lease conflicts with current owner")]
    Conflict,
}

pub trait Provider: Send + Sync {
    fn publish_name(
        &self,
        records: NameRecords,
    ) -> impl std::future::Future<Output = Result<(), DnsError>> + Send;
    fn create_txt(
        &self,
        lease: TxtLease,
    ) -> impl std::future::Future<Output = Result<(), DnsError>> + Send;
    fn delete_txt(
        &self,
        lease: &TxtLease,
    ) -> impl std::future::Future<Output = Result<(), DnsError>> + Send;
    fn retire_name(
        &self,
        hostname: &str,
    ) -> impl std::future::Future<Output = Result<(), DnsError>> + Send;
    fn retire_challenge(
        &self,
        hostname: &str,
    ) -> impl std::future::Future<Output = Result<(), DnsError>> + Send;
}

pub fn validate_records(records: &NameRecords) -> Result<(), DnsError> {
    validate_hostname(&records.hostname)?;
    if records.addresses.is_empty()
        || records.addresses.len() > 4
        || records.addresses.iter().any(IpAddr::is_unspecified)
        || !records
            .acme_account_uri
            .starts_with("https://acme-v02.api.letsencrypt.org/acme/acct/")
    {
        return Err(DnsError::InvalidChange);
    }
    Ok(())
}

pub fn caa_values(acme_account_uri: &str) -> Result<[String; 2], DnsError> {
    if !acme_account_uri.starts_with("https://acme-v02.api.letsencrypt.org/acme/acct/")
        || !acme_account_uri["https://acme-v02.api.letsencrypt.org/acme/acct/".len()..]
            .bytes()
            .all(|b| b.is_ascii_digit())
    {
        return Err(DnsError::InvalidChange);
    }
    Ok([
        format!(
            "0 issue \"letsencrypt.org; validationmethods=dns-01; accounturi={acme_account_uri}\""
        ),
        "0 issuewild \";\"".to_owned(),
    ])
}

pub fn challenge_name(hostname: &str) -> Result<String, DnsError> {
    validate_hostname(hostname)?;
    Ok(format!("_acme-challenge.{hostname}"))
}

/// Deterministic provider used by fault-injection and DNS ownership tests.
#[derive(Clone, Default)]
pub struct MemoryProvider {
    inner: Arc<Mutex<MemoryState>>,
}

#[derive(Default)]
struct MemoryState {
    names: BTreeMap<String, NameRecords>,
    leases: BTreeMap<String, TxtLease>,
}

impl MemoryProvider {
    pub async fn records(&self, hostname: &str) -> Option<NameRecords> {
        self.inner.lock().await.names.get(hostname).cloned()
    }
    pub async fn txt(&self, hostname: &str) -> Option<TxtLease> {
        self.inner.lock().await.leases.get(hostname).cloned()
    }
}

impl Provider for MemoryProvider {
    async fn publish_name(&self, records: NameRecords) -> Result<(), DnsError> {
        validate_records(&records)?;
        self.inner
            .lock()
            .await
            .names
            .insert(records.hostname.clone(), records);
        Ok(())
    }

    async fn create_txt(&self, lease: TxtLease) -> Result<(), DnsError> {
        challenge_name(&lease.hostname)?;
        if lease.value.is_empty() || lease.value.len() > 255 || lease.lease_id.is_empty() {
            return Err(DnsError::InvalidChange);
        }
        let mut state = self.inner.lock().await;
        match state.leases.get(&lease.hostname) {
            Some(current)
                if current.lease_id != lease.lease_id
                    && current.expires_at_ms >= lease.expires_at_ms =>
            {
                Err(DnsError::Conflict)
            }
            _ => {
                state.leases.insert(lease.hostname.clone(), lease);
                Ok(())
            }
        }
    }

    async fn delete_txt(&self, lease: &TxtLease) -> Result<(), DnsError> {
        challenge_name(&lease.hostname)?;
        let mut state = self.inner.lock().await;
        if state.leases.get(&lease.hostname).is_some_and(|current| {
            current.lease_id == lease.lease_id && current.value == lease.value
        }) {
            state.leases.remove(&lease.hostname);
        }
        Ok(())
    }

    async fn retire_name(&self, hostname: &str) -> Result<(), DnsError> {
        validate_hostname(hostname)?;
        let mut state = self.inner.lock().await;
        state.names.remove(hostname);
        Ok(())
    }

    async fn retire_challenge(&self, hostname: &str) -> Result<(), DnsError> {
        challenge_name(hostname)?;
        self.inner.lock().await.leases.remove(hostname);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn delayed_cleanup_cannot_delete_new_lease() {
        let dns = MemoryProvider::default();
        let host = "abcdefghijklmnopqrstuv2345.relay.bloom.directory";
        let old = TxtLease {
            hostname: host.into(),
            lease_id: "old".into(),
            value: "a".into(),
            expires_at_ms: 1,
        };
        dns.create_txt(old.clone()).await.unwrap();
        dns.create_txt(TxtLease {
            hostname: host.into(),
            lease_id: "new".into(),
            value: "b".into(),
            expires_at_ms: 2,
        })
        .await
        .unwrap();
        dns.delete_txt(&old).await.unwrap();
        assert_eq!(dns.txt(host).await.unwrap().value, "b");
        assert!(challenge_name("sibling.example").is_err());
    }

    #[tokio::test]
    async fn retirement_splits_serving_and_challenge_records() {
        let dns = MemoryProvider::default();
        let host = "abcdefghijklmnopqrstuv2345.relay.bloom.directory";
        dns.publish_name(NameRecords {
            hostname: host.into(),
            addresses: vec!["192.0.2.10".parse().unwrap()],
            acme_account_uri: "https://acme-v02.api.letsencrypt.org/acme/acct/123".into(),
        })
        .await
        .unwrap();
        dns.create_txt(TxtLease {
            hostname: host.into(),
            lease_id: "lease".into(),
            value: "value".into(),
            expires_at_ms: 5,
        })
        .await
        .unwrap();
        dns.retire_name(host).await.unwrap();
        assert!(dns.records(host).await.is_none());
        assert!(dns.txt(host).await.is_some());
        dns.retire_challenge(host).await.unwrap();
        assert!(dns.txt(host).await.is_none());
    }
}
