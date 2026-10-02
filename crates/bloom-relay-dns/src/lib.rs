//! Exact-owner DNS changes; provider credentials remain in the control worker.

use bloom_relay_protocol::{
    MAX_LIVE_CHALLENGE_VALUES, ProtocolError, validate_acme_account_uri, validate_challenge_value,
    validate_hostname,
};
use std::{collections::BTreeMap, net::IpAddr, sync::Arc};
use thiserror::Error;
use tokio::sync::Mutex;

mod route53;
pub use route53::Route53Provider;
mod cloudflare;
pub use cloudflare::{CloudflareProvider, CloudflareScope};
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
    /// Make the hostname's `_acme-challenge` TXT records exactly `values`
    /// (no records when empty). Idempotent; replays converge.
    fn set_challenge(
        &self,
        hostname: &str,
        values: &[String],
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
        || validate_acme_account_uri(&records.acme_account_uri).is_err()
    {
        return Err(DnsError::InvalidChange);
    }
    Ok(())
}

pub fn caa_values(acme_account_uri: &str) -> Result<[String; 2], DnsError> {
    if validate_acme_account_uri(acme_account_uri).is_err() {
        return Err(DnsError::InvalidChange);
    }
    Ok([
        format!(
            "0 issue \"letsencrypt.org; validationmethods=dns-01; accounturi={acme_account_uri}\""
        ),
        "0 issuewild \";\"".to_owned(),
    ])
}

/// A challenge set the relay may publish: distinct DNS-01 values, bounded.
pub fn validate_challenge_values(values: &[String]) -> Result<(), DnsError> {
    let distinct: std::collections::BTreeSet<_> = values.iter().collect();
    if values.len() > MAX_LIVE_CHALLENGE_VALUES
        || distinct.len() != values.len()
        || values
            .iter()
            .any(|value| validate_challenge_value(value).is_err())
    {
        return Err(DnsError::InvalidChange);
    }
    Ok(())
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
    challenges: BTreeMap<String, Vec<String>>,
}

impl MemoryProvider {
    pub async fn records(&self, hostname: &str) -> Option<NameRecords> {
        self.inner.lock().await.names.get(hostname).cloned()
    }
    pub async fn challenge(&self, hostname: &str) -> Vec<String> {
        self.inner
            .lock()
            .await
            .challenges
            .get(hostname)
            .cloned()
            .unwrap_or_default()
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

    async fn set_challenge(&self, hostname: &str, values: &[String]) -> Result<(), DnsError> {
        challenge_name(hostname)?;
        validate_challenge_values(values)?;
        let mut state = self.inner.lock().await;
        if values.is_empty() {
            state.challenges.remove(hostname);
        } else {
            state
                .challenges
                .insert(hostname.to_owned(), values.to_vec());
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
        self.inner.lock().await.challenges.remove(hostname);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn challenge_set_is_replaced_exactly_and_validated() {
        let dns = MemoryProvider::default();
        let host = "abcdefghijklmnopqrstuv2345.relay.bloom.directory";
        let (a, b) = ("a".repeat(43), "b".repeat(43));
        dns.set_challenge(host, &[a.clone(), b.clone()])
            .await
            .unwrap();
        assert_eq!(dns.challenge(host).await, vec![a.clone(), b.clone()]);
        dns.set_challenge(host, std::slice::from_ref(&b))
            .await
            .unwrap();
        assert_eq!(dns.challenge(host).await, vec![b.clone()]);
        dns.set_challenge(host, &[]).await.unwrap();
        assert!(dns.challenge(host).await.is_empty());
        for invalid in [
            vec![a.clone(), a.clone()],
            vec![a.clone(), b.clone(), "c".repeat(43)],
            vec!["short".into()],
        ] {
            assert!(dns.set_challenge(host, &invalid).await.is_err());
        }
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
        dns.set_challenge(host, &["v".repeat(43)]).await.unwrap();
        dns.retire_name(host).await.unwrap();
        assert!(dns.records(host).await.is_none());
        assert!(!dns.challenge(host).await.is_empty());
        dns.retire_challenge(host).await.unwrap();
        assert!(dns.challenge(host).await.is_empty());
    }

    #[test]
    fn caa_binds_exact_known_production_and_staging_accounts() {
        for account in [
            "https://acme-v02.api.letsencrypt.org/acme/acct/123",
            "https://acme-staging-v02.api.letsencrypt.org/acme/acct/456",
        ] {
            assert_eq!(
                caa_values(account).unwrap(),
                [
                    format!(
                        "0 issue \"letsencrypt.org; validationmethods=dns-01; accounturi={account}\""
                    ),
                    "0 issuewild \";\"".to_owned(),
                ]
            );
        }
        for invalid in [
            "https://example.com/acme/acct/123",
            "https://acme-staging-v02.api.letsencrypt.org/acme/acct/",
            "https://acme-staging-v02.api.letsencrypt.org/acme/acct/123?other=true",
        ] {
            assert!(caa_values(invalid).is_err(), "{invalid}");
        }
        let overlong = format!(
            "{}{}",
            bloom_relay_protocol::AcmeEnvironment::Staging.account_uri_prefix(),
            "1".repeat(
                bloom_relay_protocol::MAX_ACME_ACCOUNT_URI_LEN + 1
                    - bloom_relay_protocol::AcmeEnvironment::Staging
                        .account_uri_prefix()
                        .len()
            )
        );
        assert!(caa_values(&overlong).is_err());
    }
}
