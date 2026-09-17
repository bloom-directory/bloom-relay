//! Read-after-write observation against configured authoritative and recursive DNS.

use super::{DnsError, NameRecords, caa_values, challenge_name, validate_records};
use hickory_resolver::{
    Resolver, TokioResolver,
    config::{NameServerConfig, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
    proto::rr::{RData, RecordType},
};
use std::{collections::BTreeSet, net::IpAddr, time::Duration};

pub struct HickoryObserver {
    authoritative: Vec<IpAddr>,
}

impl HickoryObserver {
    pub fn new(authoritative: Vec<IpAddr>) -> Result<Self, DnsError> {
        if authoritative.is_empty()
            || authoritative.len() > 8
            || authoritative.iter().any(IpAddr::is_unspecified)
        {
            return Err(DnsError::InvalidChange);
        }
        Ok(Self { authoritative })
    }

    fn resolvers(&self) -> Result<(TokioResolver, TokioResolver), DnsError> {
        let config = ResolverConfig::from_name_servers(
            self.authoritative
                .iter()
                .copied()
                .map(NameServerConfig::udp_and_tcp)
                .collect(),
        );
        let mut authoritative =
            Resolver::builder_with_config(config, TokioRuntimeProvider::default());
        authoritative.options_mut().cache_size = 0;
        authoritative.options_mut().timeout = Duration::from_secs(3);
        authoritative.options_mut().attempts = 1;
        let mut recursive = TokioResolver::builder_tokio().map_err(|_| DnsError::Unavailable)?;
        recursive.options_mut().cache_size = 0;
        recursive.options_mut().timeout = Duration::from_secs(3);
        recursive.options_mut().attempts = 1;
        Ok((
            authoritative.build().map_err(|_| DnsError::Unavailable)?,
            recursive.build().map_err(|_| DnsError::Unavailable)?,
        ))
    }

    pub async fn name_visible(&self, records: &NameRecords) -> Result<bool, DnsError> {
        validate_records(records)?;
        let (authoritative, recursive) = self.resolvers()?;
        Ok(check_name(&authoritative, records).await && check_name(&recursive, records).await)
    }

    pub async fn txt_visible(&self, hostname: &str, value: &str) -> Result<bool, DnsError> {
        let name = challenge_name(hostname)?;
        let (authoritative, recursive) = self.resolvers()?;
        Ok(check_txt(&authoritative, &name, value).await
            && check_txt(&recursive, &name, value).await)
    }

    pub async fn txt_absent(&self, hostname: &str, value: &str) -> Result<bool, DnsError> {
        let name = challenge_name(hostname)?;
        let (authoritative, recursive) = self.resolvers()?;
        Ok(check_txt_absent(&authoritative, &name, value).await
            && check_txt_absent(&recursive, &name, value).await)
    }

    pub async fn name_absent(&self, hostname: &str) -> Result<bool, DnsError> {
        super::validate_hostname(hostname)?;
        let (authoritative, recursive) = self.resolvers()?;
        for resolver in [&authoritative, &recursive] {
            for kind in [RecordType::A, RecordType::AAAA, RecordType::CAA] {
                if !record_absent(resolver, &format!("{hostname}."), kind).await {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    pub async fn challenge_absent(&self, hostname: &str) -> Result<bool, DnsError> {
        let name = format!("{}.", challenge_name(hostname)?);
        let (authoritative, recursive) = self.resolvers()?;
        Ok(record_absent(&authoritative, &name, RecordType::TXT).await
            && record_absent(&recursive, &name, RecordType::TXT).await)
    }
}

async fn record_absent(resolver: &TokioResolver, name: &str, kind: RecordType) -> bool {
    match resolver.lookup(name, kind).await {
        Ok(lookup) => lookup.answers().is_empty(),
        Err(error) => error.is_no_records_found(),
    }
}

async fn check_name(resolver: &TokioResolver, records: &NameRecords) -> bool {
    let name = format!("{}.", records.hostname);
    let expected_v4: BTreeSet<_> = records
        .addresses
        .iter()
        .filter(|ip| ip.is_ipv4())
        .map(ToString::to_string)
        .collect();
    let expected_v6: BTreeSet<_> = records
        .addresses
        .iter()
        .filter(|ip| ip.is_ipv6())
        .map(ToString::to_string)
        .collect();
    let Some(observed_v4) = lookup_addresses(resolver, &name, RecordType::A).await else {
        return false;
    };
    let Some(observed_v6) = lookup_addresses(resolver, &name, RecordType::AAAA).await else {
        return false;
    };
    if observed_v4 != expected_v4 || observed_v6 != expected_v6 {
        return false;
    }
    let Ok(expected_caa) = caa_values(&records.acme_account_uri) else {
        return false;
    };
    let Ok(lookup) = resolver.lookup(name, RecordType::CAA).await else {
        return false;
    };
    let observed: BTreeSet<_> = lookup
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            RData::CAA(caa) => Some(format!(
                "0 {} \"{}\"",
                caa.tag,
                String::from_utf8_lossy(&caa.value)
            )),
            _ => None,
        })
        .collect();
    observed == expected_caa.into_iter().collect()
}

async fn lookup_addresses(
    resolver: &TokioResolver,
    name: &str,
    kind: RecordType,
) -> Option<BTreeSet<String>> {
    match resolver.lookup(name, kind).await {
        Ok(lookup) => Some(
            lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    RData::A(address) => Some(address.to_string()),
                    RData::AAAA(address) => Some(address.to_string()),
                    _ => None,
                })
                .collect(),
        ),
        Err(error) if error.is_no_records_found() => Some(BTreeSet::new()),
        Err(_) => None,
    }
}

async fn check_txt(resolver: &TokioResolver, name: &str, value: &str) -> bool {
    let Ok(lookup) = resolver.lookup(format!("{name}."), RecordType::TXT).await else {
        return false;
    };
    lookup.answers().iter().any(|record| match &record.data {
        RData::TXT(txt) => {
            txt.txt_data
                .iter()
                .map(|part| part.as_ref())
                .collect::<Vec<&[u8]>>()
                .concat()
                == value.as_bytes()
        }
        _ => false,
    })
}

async fn check_txt_absent(resolver: &TokioResolver, name: &str, value: &str) -> bool {
    match resolver.lookup(format!("{name}."), RecordType::TXT).await {
        Ok(lookup) => !lookup.answers().iter().any(|record| match &record.data {
            RData::TXT(txt) => {
                txt.txt_data
                    .iter()
                    .flat_map(|part| part.iter())
                    .copied()
                    .collect::<Vec<_>>()
                    == value.as_bytes()
            }
            _ => false,
        }),
        Err(error) => error.is_no_records_found(),
    }
}
