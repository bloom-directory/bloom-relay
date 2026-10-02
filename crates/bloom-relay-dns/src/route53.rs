//! Route 53 provider. The caller supplies a zone-restricted AWS client identity.

use super::{
    DnsError, NameRecords, Provider, TTL_SECONDS, caa_values, challenge_name,
    validate_challenge_values, validate_records,
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

    async fn set_challenge(&self, hostname: &str, values: &[String]) -> Result<(), DnsError> {
        let name = challenge_name(hostname)?;
        validate_challenge_values(values)?;
        if values.is_empty() {
            return self.retire_challenge(hostname).await;
        }
        // One record set holds every value; an UPSERT replaces it whole.
        self.apply(vec![change(
            &name,
            RrType::Txt,
            30,
            values.iter().map(|value| format!("\"{value}\"")),
            ChangeAction::Upsert,
        )?])
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

    fn changed() -> ChangeResourceRecordSetsOutput {
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
    }

    #[tokio::test]
    async fn challenge_set_is_one_upserted_record_set_and_empty_deletes_it() {
        let (a, b) = ("a".repeat(43), "b".repeat(43));
        let upsert = mock!(Client::change_resource_record_sets)
            .match_requests(|request| {
                request.change_batch().is_some_and(|batch| {
                    let change = &batch.changes()[0];
                    batch.changes().len() == 1
                        && change.action() == &ChangeAction::Upsert
                        && change.resource_record_set().is_some_and(|set| {
                            set.resource_records()
                                .iter()
                                .map(|record| record.value())
                                .eq([
                                    format!("\"{}\"", "a".repeat(43)),
                                    format!("\"{}\"", "b".repeat(43)),
                                ]
                                .iter()
                                .map(String::as_str))
                        })
                })
            })
            .then_output(changed);
        let provider = mocked(&[&upsert]);
        provider
            .set_challenge(HOST, &[a.clone(), b.clone()])
            .await
            .unwrap();
        assert_eq!(upsert.num_calls(), 1);

        let published = mock!(Client::list_resource_record_sets)
            .then_output(|| published("a".repeat(43).as_str()));
        let delete = mock!(Client::change_resource_record_sets)
            .match_requests(|request| {
                request
                    .change_batch()
                    .is_some_and(|batch| batch.changes()[0].action() == &ChangeAction::Delete)
            })
            .then_output(changed);
        let provider = mocked(&[&published, &delete]);
        provider.set_challenge(HOST, &[]).await.unwrap();
        assert_eq!(delete.num_calls(), 1);

        let provider = mocked(&[]);
        assert!(provider.set_challenge(HOST, &[a.clone(), a]).await.is_err());
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
