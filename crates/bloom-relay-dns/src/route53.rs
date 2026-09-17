//! Route 53 provider. The caller supplies a zone-restricted AWS client identity.

use super::{
    DnsError, NameRecords, Provider, TTL_SECONDS, TxtLease, caa_values, challenge_name,
    validate_records,
};
use aws_sdk_route53::types::{
    Change, ChangeAction, ChangeBatch, ResourceRecord, ResourceRecordSet, RrType,
};
use std::net::IpAddr;

pub struct Route53Provider {
    client: aws_sdk_route53::Client,
    hosted_zone_id: String,
}

impl Route53Provider {
    pub fn new(client: aws_sdk_route53::Client, hosted_zone_id: String) -> Result<Self, DnsError> {
        if hosted_zone_id.is_empty()
            || !hosted_zone_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'/')
        {
            return Err(DnsError::InvalidChange);
        }
        Ok(Self {
            client,
            hosted_zone_id,
        })
    }

    async fn apply(&self, changes: Vec<Change>) -> Result<(), DnsError> {
        let batch = ChangeBatch::builder()
            .set_changes(Some(changes))
            .build()
            .map_err(|_| DnsError::InvalidChange)?;
        self.client
            .change_resource_record_sets()
            .hosted_zone_id(&self.hosted_zone_id)
            .change_batch(batch)
            .send()
            .await
            .map_err(|_| DnsError::Unavailable)?;
        Ok(())
    }
}

fn change(
    name: &str,
    kind: RrType,
    ttl: u32,
    values: impl IntoIterator<Item = String>,
    action: ChangeAction,
) -> Result<Change, DnsError> {
    let mut record = ResourceRecordSet::builder()
        .name(name)
        .r#type(kind)
        .ttl(ttl as i64);
    let mut count = 0usize;
    for value in values {
        count += 1;
        record = record.resource_records(
            ResourceRecord::builder()
                .value(value)
                .build()
                .map_err(|_| DnsError::InvalidChange)?,
        );
    }
    if count == 0 {
        return Err(DnsError::InvalidChange);
    }
    Change::builder()
        .action(action)
        .resource_record_set(record.build().map_err(|_| DnsError::InvalidChange)?)
        .build()
        .map_err(|_| DnsError::InvalidChange)
}

impl Provider for Route53Provider {
    async fn publish_name(&self, records: NameRecords) -> Result<(), DnsError> {
        validate_records(&records)?;
        let mut changes = Vec::new();
        let ipv4 = records
            .addresses
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(v) => Some(v.to_string()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let ipv6 = records
            .addresses
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V6(v) => Some(v.to_string()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let existing = self
            .client
            .list_resource_record_sets()
            .hosted_zone_id(&self.hosted_zone_id)
            .start_record_name(&records.hostname)
            .max_items(10)
            .send()
            .await
            .map_err(|_| DnsError::Unavailable)?;
        for record in existing.resource_record_sets() {
            if record.name().trim_end_matches('.') != records.hostname {
                continue;
            }
            let stale = (record.r#type() == &RrType::A && ipv4.is_empty())
                || (record.r#type() == &RrType::Aaaa && ipv6.is_empty());
            if stale {
                changes.push(
                    Change::builder()
                        .action(ChangeAction::Delete)
                        .resource_record_set(record.clone())
                        .build()
                        .map_err(|_| DnsError::InvalidChange)?,
                );
            }
        }
        if !ipv4.is_empty() {
            changes.push(change(
                &records.hostname,
                RrType::A,
                TTL_SECONDS,
                ipv4,
                ChangeAction::Upsert,
            )?);
        }
        if !ipv6.is_empty() {
            changes.push(change(
                &records.hostname,
                RrType::Aaaa,
                TTL_SECONDS,
                ipv6,
                ChangeAction::Upsert,
            )?);
        }
        changes.push(change(
            &records.hostname,
            RrType::Caa,
            TTL_SECONDS,
            caa_values(&records.acme_account_uri)?,
            ChangeAction::Upsert,
        )?);
        self.apply(changes).await
    }

    async fn create_txt(&self, lease: TxtLease) -> Result<(), DnsError> {
        let name = challenge_name(&lease.hostname)?;
        if lease.value.is_empty() || lease.value.len() > 255 {
            return Err(DnsError::InvalidChange);
        }
        self.apply(vec![change(
            &name,
            RrType::Txt,
            30,
            [format!("\"{}\"", lease.value)],
            ChangeAction::Upsert,
        )?])
        .await
    }

    async fn delete_txt(&self, lease: &TxtLease) -> Result<(), DnsError> {
        let name = challenge_name(&lease.hostname)?;
        let current = self
            .client
            .list_resource_record_sets()
            .hosted_zone_id(&self.hosted_zone_id)
            .start_record_name(&name)
            .max_items(2)
            .send()
            .await
            .map_err(|_| DnsError::Unavailable)?;
        let Some(record) = current.resource_record_sets().iter().find(|record| {
            record.name().trim_end_matches('.') == name && record.r#type() == &RrType::Txt
        }) else {
            return Ok(());
        };
        if record.resource_records().len() != 1
            || record.resource_records()[0].value() != format!("\"{}\"", lease.value)
        {
            return Err(DnsError::Conflict);
        }
        self.apply(vec![
            Change::builder()
                .action(ChangeAction::Delete)
                .resource_record_set(record.clone())
                .build()
                .map_err(|_| DnsError::InvalidChange)?,
        ])
        .await
    }

    async fn retire_name(&self, hostname: &str) -> Result<(), DnsError> {
        super::validate_hostname(hostname)?;
        let mut changes = Vec::new();
        for name in [hostname.to_owned(), challenge_name(hostname)?] {
            let existing = self
                .client
                .list_resource_record_sets()
                .hosted_zone_id(&self.hosted_zone_id)
                .start_record_name(&name)
                .max_items(10)
                .send()
                .await
                .map_err(|_| DnsError::Unavailable)?;
            for record in existing.resource_record_sets() {
                if record.name().trim_end_matches('.') != name {
                    continue;
                }
                let allowed = if name == hostname {
                    matches!(record.r#type(), RrType::A | RrType::Aaaa | RrType::Caa)
                } else {
                    record.r#type() == &RrType::Txt
                };
                if allowed {
                    changes.push(
                        Change::builder()
                            .action(ChangeAction::Delete)
                            .resource_record_set(record.clone())
                            .build()
                            .map_err(|_| DnsError::InvalidChange)?,
                    );
                }
            }
        }
        if changes.is_empty() {
            return Ok(());
        }
        self.apply(changes).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn provider_changes_are_exact_and_bounded() {
        assert!(
            change(
                "_acme-challenge.abcdefghijklmnopqrstuv2345.relay.bloom.directory",
                RrType::Txt,
                30,
                ["\"token\"".into()],
                ChangeAction::Upsert
            )
            .is_ok()
        );
        assert!(
            change(
                "bad",
                RrType::Txt,
                30,
                Vec::<String>::new(),
                ChangeAction::Upsert
            )
            .is_err()
        );
    }
}
