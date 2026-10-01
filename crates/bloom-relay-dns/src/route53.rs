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
        let quoted = format!("\"{}\"", lease.value);
        if !record
            .resource_records()
            .iter()
            .any(|value| value.value() == quoted)
        {
            // A newer lease's UPSERT already replaced this value.
            return Ok(());
        }
        if record.resource_records().len() != 1 {
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
        let name = hostname.to_owned();
        {
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
                let allowed = matches!(record.r#type(), RrType::A | RrType::Aaaa | RrType::Caa);
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

    async fn retire_challenge(&self, hostname: &str) -> Result<(), DnsError> {
        let name = challenge_name(hostname)?;
        let existing = self
            .client
            .list_resource_record_sets()
            .hosted_zone_id(&self.hosted_zone_id)
            .start_record_name(&name)
            .max_items(2)
            .send()
            .await
            .map_err(|_| DnsError::Unavailable)?;
        let Some(record) = existing.resource_record_sets().iter().find(|record| {
            record.name().trim_end_matches('.') == name && record.r#type() == &RrType::Txt
        }) else {
            return Ok(());
        };
        self.apply(vec![
            Change::builder()
                .action(ChangeAction::Delete)
                .resource_record_set(record.clone())
                .build()
                .map_err(|_| DnsError::InvalidChange)?,
        ])
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_route53::{
        Client,
        operation::{
            change_resource_record_sets::ChangeResourceRecordSetsOutput,
            list_resource_record_sets::ListResourceRecordSetsOutput,
        },
        types::{ChangeInfo, ChangeStatus},
    };
    use aws_smithy_mocks::{MockResponseInterceptor, Rule, RuleMode, mock};

    const HOST: &str = "abcdefghijklmnopqrstuv2345.relay.bloom.directory";

    /// A client answered only by `rules`. Built by hand: the SDK's
    /// `test-util` feature would pull a second, legacy HTTP stack.
    fn mocked(rules: &[&Rule]) -> Route53Provider {
        let interceptor = rules.iter().fold(
            MockResponseInterceptor::new().rule_mode(RuleMode::MatchAny),
            |interceptor, rule| interceptor.with_rule(rule),
        );
        let config = aws_sdk_route53::Config::builder()
            .behavior_version(aws_sdk_route53::config::BehaviorVersion::latest())
            .region(aws_sdk_route53::config::Region::new("us-east-1"))
            .credentials_provider(aws_sdk_route53::config::Credentials::new(
                "test", "test", None, None, "test",
            ))
            .http_client(aws_smithy_mocks::create_mock_http_client())
            .interceptor(interceptor)
            .build();
        Route53Provider::new(Client::from_conf(config), "Z123".into()).unwrap()
    }

    fn published(value: &str) -> ListResourceRecordSetsOutput {
        ListResourceRecordSetsOutput::builder()
            .resource_record_sets(
                ResourceRecordSet::builder()
                    .name(format!("_acme-challenge.{HOST}."))
                    .r#type(RrType::Txt)
                    .ttl(30)
                    .resource_records(
                        ResourceRecord::builder()
                            .value(format!("\"{value}\""))
                            .build()
                            .unwrap(),
                    )
                    .build()
                    .unwrap(),
            )
            .is_truncated(false)
            .max_items(2)
            .build()
            .unwrap()
    }

    fn lease(value: &str) -> TxtLease {
        TxtLease {
            hostname: HOST.into(),
            lease_id: "old".into(),
            value: value.into(),
            expires_at_ms: 1,
        }
    }

    #[tokio::test]
    async fn cleanup_deletes_its_own_value_and_leaves_a_newer_lease() {
        let newer = mock!(Client::list_resource_record_sets).then_output(|| published("new"));
        let provider = mocked(&[&newer]);
        // Only the list rule exists: any change request would fail the call.
        provider.delete_txt(&lease("old")).await.unwrap();

        let own = mock!(Client::list_resource_record_sets).then_output(|| published("old"));
        let delete = mock!(Client::change_resource_record_sets)
            .match_requests(|request| {
                request.change_batch().is_some_and(|batch| {
                    batch.changes().len() == 1
                        && batch.changes()[0].action() == &ChangeAction::Delete
                })
            })
            .then_output(|| {
                ChangeResourceRecordSetsOutput::builder()
                    .change_info(
                        ChangeInfo::builder()
                            .id("C1")
                            .status(ChangeStatus::Pending)
                            .submitted_at(aws_sdk_route53::primitives::DateTime::from_secs(0))
                            .build()
                            .unwrap(),
                    )
                    .build()
            });
        let provider = mocked(&[&own, &delete]);
        provider.delete_txt(&lease("old")).await.unwrap();
        assert_eq!(delete.num_calls(), 1);
    }
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
