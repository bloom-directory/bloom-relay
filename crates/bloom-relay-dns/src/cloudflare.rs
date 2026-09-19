//! Cloudflare DNS v4 adapter for the existing, exact Bloom relay names.
//! A zone-scoped API token is still broader than these code-level ownership checks.

use super::{
    DnsError, NameRecords, Provider, TTL_SECONDS, TxtLease, caa_values, challenge_name,
    validate_records,
};
use bloom_relay_protocol::validate_hostname;
use reqwest::{Client, Method, StatusCode, Url, redirect::Policy};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    time::Duration,
};

const SERVING_COMMENT: &str = "bloom-relay serving v1";
const CHALLENGE_PREFIX: &str = "bloom-relay challenge v1 ";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloudflareScope {
    Serving,
    Challenge,
}

pub struct CloudflareProvider {
    client: Client,
    base: Url,
    token: String,
    scope: CloudflareScope,
}

#[derive(Clone, Deserialize)]
struct Record {
    id: String,
    name: String,
    #[serde(rename = "type")]
    kind: String,
    content: String,
    ttl: u32,
    #[serde(default)]
    proxied: bool,
    #[serde(default)]
    comment: String,
    data: Option<CaaData>,
}

#[derive(Clone, Deserialize)]
struct CaaData {
    flags: u8,
    tag: String,
    value: String,
}

#[derive(Deserialize)]
struct Envelope<T> {
    success: bool,
    result: Option<T>,
    result_info: Option<ResultInfo>,
}

#[derive(Deserialize)]
struct ResultInfo {
    total_pages: u32,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
struct RecordKey {
    kind: String,
    content: String,
}

struct ServingPlan {
    stale: Vec<Record>,
    missing: Vec<Value>,
    updates: Vec<(Record, Value)>,
}

impl Record {
    fn key(&self) -> Result<RecordKey, DnsError> {
        let content = if self.kind == "CAA" {
            let data = self.data.as_ref().ok_or(DnsError::Conflict)?;
            if data.flags != 0 || !matches!(data.tag.as_str(), "issue" | "issuewild") {
                return Err(DnsError::Conflict);
            }
            format!("{}:{}", data.tag, data.value)
        } else {
            self.content.clone()
        };
        Ok(RecordKey {
            kind: self.kind.clone(),
            content,
        })
    }
}

impl CloudflareProvider {
    pub fn new(zone_id: String, token: String, scope: CloudflareScope) -> Result<Self, DnsError> {
        if !valid_id(&zone_id)
            || token.is_empty()
            || token
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        {
            return Err(DnsError::InvalidChange);
        }
        let base = Url::parse(&format!(
            "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
        ))
        .map_err(|_| DnsError::InvalidChange)?;
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(Policy::none())
            .build()
            .map_err(|_| DnsError::Unavailable)?;
        Ok(Self {
            client,
            base,
            token,
            scope,
        })
    }

    fn require(&self, scope: CloudflareScope) -> Result<(), DnsError> {
        if self.scope == scope {
            Ok(())
        } else {
            Err(DnsError::InvalidChange)
        }
    }

    async fn send<T: for<'de> Deserialize<'de>>(
        &self,
        method: Method,
        url: Url,
        body: Option<Value>,
    ) -> Result<Envelope<T>, DnsError> {
        let mut request = self.client.request(method, url).bearer_auth(&self.token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let mut response = request.send().await.map_err(|_| DnsError::Unavailable)?;
        if response.status() == StatusCode::CONFLICT {
            return Err(DnsError::Conflict);
        }
        if !response.status().is_success() {
            return Err(DnsError::Unavailable);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| DnsError::Unavailable)? {
            if body.len() + chunk.len() > 256 * 1024 {
                return Err(DnsError::Unavailable);
            }
            body.extend_from_slice(&chunk);
        }
        let envelope: Envelope<T> =
            serde_json::from_slice(&body).map_err(|_| DnsError::Unavailable)?;
        if !envelope.success {
            return Err(DnsError::Unavailable);
        }
        Ok(envelope)
    }

    async fn list(&self, name: &str) -> Result<Vec<Record>, DnsError> {
        let mut url = self.base.clone();
        url.query_pairs_mut()
            .append_pair("name.exact", name)
            .append_pair("per_page", "1000");
        let envelope: Envelope<Vec<Record>> = self.send(Method::GET, url, None).await?;
        if envelope.result_info.is_none_or(|info| info.total_pages > 1) {
            return Err(DnsError::Unavailable);
        }
        let records = envelope.result.ok_or(DnsError::Unavailable)?;
        if records.len() > 1000 || records.iter().any(|r| r.name != name || !valid_id(&r.id)) {
            return Err(DnsError::Unavailable);
        }
        Ok(records)
    }

    async fn create(&self, body: Value) -> Result<(), DnsError> {
        let envelope: Envelope<Value> = self
            .send(Method::POST, self.base.clone(), Some(body))
            .await?;
        if envelope.result.is_none() {
            return Err(DnsError::Unavailable);
        }
        Ok(())
    }

    async fn delete(&self, record: &Record) -> Result<(), DnsError> {
        if !valid_id(&record.id) {
            return Err(DnsError::Unavailable);
        }
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|_| DnsError::InvalidChange)?
            .push(&record.id);
        let _: Envelope<Value> = self.send(Method::DELETE, url, None).await?;
        Ok(())
    }

    async fn update(&self, record: &Record, body: Value) -> Result<(), DnsError> {
        if !valid_id(&record.id) {
            return Err(DnsError::Unavailable);
        }
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|_| DnsError::InvalidChange)?
            .push(&record.id);
        let envelope: Envelope<Value> = self.send(Method::PATCH, url, Some(body)).await?;
        if envelope.result.is_none() {
            return Err(DnsError::Unavailable);
        }
        Ok(())
    }

    async fn reconcile_serving(
        &self,
        name: &str,
        desired: Vec<(RecordKey, Value)>,
    ) -> Result<(), DnsError> {
        let existing = self.list(name).await?;
        let plan = plan_serving(existing, desired)?;
        // Keep existing CAA authority (including issuewild denial) until its
        // replacement exists. The next reconciliation resolves ambiguous writes.
        for body in plan.missing {
            self.create(body).await?;
        }
        for (record, body) in plan.updates {
            self.update(&record, body).await?;
        }
        for record in &plan.stale {
            self.delete(record).await?;
        }
        Ok(())
    }
}

fn plan_serving(
    existing: Vec<Record>,
    desired: Vec<(RecordKey, Value)>,
) -> Result<ServingPlan, DnsError> {
    let desired_map: BTreeMap<_, _> = desired.into_iter().collect();
    let mut found = BTreeSet::new();
    let mut stale = Vec::new();
    let mut updates = Vec::new();
    for record in existing {
        if matches!(record.kind.as_str(), "CNAME" | "NS") {
            return Err(DnsError::Conflict);
        }
        if !matches!(record.kind.as_str(), "A" | "AAAA" | "CAA") {
            continue;
        }
        if record.comment != SERVING_COMMENT {
            return Err(DnsError::Conflict);
        }
        let key = record.key()?;
        if let Some(body) = desired_map.get(&key)
            && found.insert(key)
        {
            if record.ttl != TTL_SECONDS || record.proxied {
                updates.push((record, body.clone()));
            }
            continue;
        }
        stale.push(record);
    }
    let mut missing: Vec<Value> = desired_map
        .into_iter()
        .filter_map(|(key, body)| (!found.contains(&key)).then_some(body))
        .collect();
    missing.sort_by_key(create_rank);
    stale.sort_by_key(delete_rank);
    Ok(ServingPlan {
        stale,
        missing,
        updates,
    })
}

// A child CAA RRset stops CAA inheritance. Install the wildcard denial before
// the account authorization, and remove authorization before the final denial.
fn create_rank(body: &Value) -> u8 {
    match (body["type"].as_str(), body["data"]["tag"].as_str()) {
        (Some("CAA"), Some("issuewild")) => 0,
        (Some("CAA"), Some("issue")) => 1,
        _ => 2,
    }
}

fn delete_rank(record: &Record) -> u8 {
    match (
        record.kind.as_str(),
        record.data.as_ref().map(|data| data.tag.as_str()),
    ) {
        ("CAA", Some("issue")) => 0,
        ("CAA", Some("issuewild")) => 2,
        _ => 1,
    }
}

fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

fn valid_lease(lease: &TxtLease) -> Result<(), DnsError> {
    challenge_name(&lease.hostname)?;
    if lease.lease_id.len() != 36
        || !lease
            .lease_id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b'-')
        || lease.value.is_empty()
        || lease.value.len() > 255
        || !lease
            .value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(DnsError::InvalidChange);
    }
    Ok(())
}

fn txt_content(record: &Record) -> &str {
    record
        .content
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(&record.content)
}

fn serving_desired(records: &NameRecords) -> Result<Vec<(RecordKey, Value)>, DnsError> {
    validate_records(records)?;
    let mut desired = Vec::new();
    for ip in &records.addresses {
        let kind = match ip {
            IpAddr::V4(_) => "A",
            IpAddr::V6(_) => "AAAA",
        };
        let content = ip.to_string();
        let key = RecordKey {
            kind: kind.into(),
            content: content.clone(),
        };
        if desired.iter().any(|(existing, _)| existing == &key) {
            continue;
        }
        desired.push((key, json!({"type":kind,"name":records.hostname,"content":content,"ttl":TTL_SECONDS,"proxied":false,"comment":SERVING_COMMENT})));
    }
    for value in caa_values(&records.acme_account_uri)? {
        let (tag, content) = if value.contains(" issuewild ") {
            ("issuewild", ";".to_owned())
        } else {
            (
                "issue",
                format!(
                    "letsencrypt.org; validationmethods=dns-01; accounturi={}",
                    records.acme_account_uri
                ),
            )
        };
        desired.push((RecordKey {kind:"CAA".into(), content:format!("{tag}:{content}")}, json!({"type":"CAA","name":records.hostname,"ttl":TTL_SECONDS,"comment":SERVING_COMMENT,"data":{"flags":0,"tag":tag,"value":content}})));
    }
    Ok(desired)
}

impl Provider for CloudflareProvider {
    async fn publish_name(&self, records: NameRecords) -> Result<(), DnsError> {
        self.require(CloudflareScope::Serving)?;
        let desired = serving_desired(&records)?;
        self.reconcile_serving(&records.hostname, desired).await
    }

    async fn create_txt(&self, lease: TxtLease) -> Result<(), DnsError> {
        self.require(CloudflareScope::Challenge)?;
        valid_lease(&lease)?;
        let name = challenge_name(&lease.hostname)?;
        let comment = format!("{CHALLENGE_PREFIX}{}", lease.lease_id);
        let mut found = false;
        for record in self.list(&name).await? {
            if record.kind != "TXT" {
                return Err(DnsError::Conflict);
            }
            if record.comment == comment {
                if txt_content(&record) != lease.value {
                    return Err(DnsError::Conflict);
                }
                found = true;
            }
            if !record.comment.starts_with(CHALLENGE_PREFIX) {
                return Err(DnsError::Conflict);
            }
        }
        if found {
            return Ok(());
        }
        self.create(
            json!({"type":"TXT","name":name,"content":format!("\"{}\"", lease.value),"ttl":60,"comment":comment}),
        )
        .await
    }

    async fn delete_txt(&self, lease: &TxtLease) -> Result<(), DnsError> {
        self.require(CloudflareScope::Challenge)?;
        valid_lease(lease)?;
        let name = challenge_name(&lease.hostname)?;
        let comment = format!("{CHALLENGE_PREFIX}{}", lease.lease_id);
        let records = self.list(&name).await?;
        let matching: Vec<_> = records
            .into_iter()
            .filter(|record| record.kind == "TXT" && record.comment == comment)
            .collect();
        if matching
            .iter()
            .any(|record| txt_content(record) != lease.value)
        {
            return Err(DnsError::Conflict);
        }
        for record in &matching {
            self.delete(record).await?;
        }
        Ok(())
    }

    async fn retire_name(&self, hostname: &str) -> Result<(), DnsError> {
        self.require(CloudflareScope::Serving)?;
        validate_hostname(hostname)?;
        let mut records: Vec<_> = self
            .list(hostname)
            .await?
            .into_iter()
            .filter(|record| matches!(record.kind.as_str(), "A" | "AAAA" | "CAA"))
            .collect();
        if records
            .iter()
            .any(|record| record.comment != SERVING_COMMENT)
        {
            return Err(DnsError::Conflict);
        }
        for record in &records {
            if record.kind == "CAA" {
                record.key()?;
            }
        }
        records.sort_by_key(delete_rank);
        for record in &records {
            self.delete(record).await?;
        }
        Ok(())
    }

    async fn retire_challenge(&self, hostname: &str) -> Result<(), DnsError> {
        self.require(CloudflareScope::Challenge)?;
        let name = challenge_name(hostname)?;
        let records: Vec<_> = self
            .list(&name)
            .await?
            .into_iter()
            .filter(|record| record.kind == "TXT")
            .collect();
        if records
            .iter()
            .any(|record| !record.comment.starts_with(CHALLENGE_PREFIX))
        {
            return Err(DnsError::Conflict);
        }
        for record in &records {
            self.delete(record).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    const TEST_ZONE: &str = "0123456789abcdef0123456789abcdef";
    const HOST: &str = "abcdefghijklmnopqrstuv2345.relay.bloom.directory";

    #[test]
    fn exact_zone_and_scope_validation() {
        assert!(
            CloudflareProvider::new(TEST_ZONE.into(), "token".into(), CloudflareScope::Serving)
                .is_ok()
        );
        assert!(
            CloudflareProvider::new("other".into(), "token".into(), CloudflareScope::Serving)
                .is_err()
        );
        let provider =
            CloudflareProvider::new(TEST_ZONE.into(), "token".into(), CloudflareScope::Serving)
                .unwrap();
        assert!(provider.require(CloudflareScope::Challenge).is_err());
    }

    #[test]
    fn serving_records_are_exact_and_unproxied() {
        let records = NameRecords {
            hostname: HOST.into(),
            addresses: vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
            acme_account_uri: "https://acme-v02.api.letsencrypt.org/acme/acct/123".into(),
        };
        let desired = serving_desired(&records).unwrap();
        assert_eq!(desired.len(), 4);
        assert!(
            desired
                .iter()
                .all(|(_, body)| body["name"] == HOST && body["comment"] == SERVING_COMMENT)
        );
        assert_eq!(
            desired.iter().find(|(key, _)| key.kind == "A").unwrap().1["proxied"],
            false
        );
        assert_eq!(
            desired
                .iter()
                .find(|(key, _)| key.content.starts_with("issuewild:"))
                .unwrap()
                .1["data"]["value"],
            ";"
        );
    }

    #[test]
    fn txt_rejects_untrusted_content() {
        let lease = TxtLease {
            hostname: HOST.into(),
            lease_id: "00000000-0000-0000-0000-000000000001".into(),
            value: "token\";bad".into(),
            expires_at_ms: 1,
        };
        assert!(valid_lease(&lease).is_err());
    }

    async fn fixture_with_pages(
        records: Value,
        requests: usize,
        total_pages: u32,
    ) -> (CloudflareProvider, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut observed = Vec::new();
            for _ in 0..requests {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buffer = vec![0; 8192];
                let size = stream.read(&mut buffer).await.unwrap();
                let request = String::from_utf8_lossy(&buffer[..size]);
                observed.push(request.lines().next().unwrap().to_owned());
                let body = if request.starts_with("GET ") {
                    json!({"success":true,"result":records,"result_info":{"total_pages":total_pages}})
                } else {
                    json!({"success":true,"result":{"id":"00000000000000000000000000000001"}})
                }
                .to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
            observed
        });
        let mut provider = CloudflareProvider::new(
            TEST_ZONE.into(),
            "fixture-token".into(),
            CloudflareScope::Challenge,
        )
        .unwrap();
        provider.base = Url::parse(&format!(
            "http://{address}/client/v4/zones/{TEST_ZONE}/dns_records"
        ))
        .unwrap();
        (provider, handle)
    }

    async fn fixture(
        records: Value,
        requests: usize,
    ) -> (CloudflareProvider, tokio::task::JoinHandle<Vec<String>>) {
        fixture_with_pages(records, requests, 1).await
    }

    #[tokio::test]
    async fn cleanup_deletes_only_matching_lease_record() {
        let name = format!("_acme-challenge.{HOST}");
        let old = "00000000-0000-0000-0000-000000000001";
        let new = "00000000-0000-0000-0000-000000000002";
        let records = json!([
            {"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":name,"type":"TXT","content":"old","ttl":60,"comment":format!("{CHALLENGE_PREFIX}{old}")},
            {"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","name":name,"type":"TXT","content":"new","ttl":60,"comment":format!("{CHALLENGE_PREFIX}{new}")}
        ]);
        let (provider, handle) = fixture(records, 2).await;
        let lease = TxtLease {
            hostname: HOST.into(),
            lease_id: old.into(),
            value: "old".into(),
            expires_at_ms: 1,
        };
        provider.delete_txt(&lease).await.unwrap();
        let requests = handle.await.unwrap();
        assert!(requests[0].starts_with("GET "));
        assert!(requests[0].contains("name.exact="));
        assert!(requests[1].starts_with("DELETE "));
        assert!(requests[1].contains("/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "));
    }

    #[tokio::test]
    async fn foreign_serving_record_causes_no_write() {
        let records = json!([{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":HOST,"type":"A","content":"192.0.2.1","ttl":300,"proxied":false,"comment":"operator"}]);
        let (mut provider, handle) = fixture(records, 1).await;
        provider.scope = CloudflareScope::Serving;
        let change = NameRecords {
            hostname: HOST.into(),
            addresses: vec!["192.0.2.2".parse().unwrap()],
            acme_account_uri: "https://acme-v02.api.letsencrypt.org/acme/acct/123".into(),
        };
        assert!(matches!(
            provider.publish_name(change).await,
            Err(DnsError::Conflict)
        ));
        let requests = handle.await.unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with("GET "));
    }

    #[tokio::test]
    async fn empty_result_page_zero_can_create_records() {
        let (mut provider, handle) = fixture_with_pages(json!([]), 4, 0).await;
        provider.scope = CloudflareScope::Serving;
        let change = NameRecords {
            hostname: HOST.into(),
            addresses: vec!["192.0.2.2".parse().unwrap()],
            acme_account_uri: "https://acme-v02.api.letsencrypt.org/acme/acct/123".into(),
        };
        provider.publish_name(change).await.unwrap();
        let requests = handle.await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.starts_with("POST "))
                .count(),
            3
        );
    }

    #[test]
    fn retry_plan_keeps_existing_values_after_partial_write() {
        let change = NameRecords {
            hostname: HOST.into(),
            addresses: vec!["192.0.2.2".parse().unwrap()],
            acme_account_uri: "https://acme-v02.api.letsencrypt.org/acme/acct/123".into(),
        };
        let desired = serving_desired(&change).unwrap();
        let initial = plan_serving(vec![], desired.clone()).unwrap();
        assert_eq!(initial.missing.len(), 3);
        assert_eq!(initial.missing[0]["data"]["tag"], "issuewild");
        assert_eq!(initial.missing[1]["data"]["tag"], "issue");
        let existing: Record = serde_json::from_value(json!({
            "id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":HOST,"type":"A",
            "content":"192.0.2.2","ttl":300,"proxied":false,"comment":SERVING_COMMENT
        }))
        .unwrap();
        let plan = plan_serving(vec![existing], desired).unwrap();
        assert!(plan.stale.is_empty());
        assert_eq!(plan.missing.len(), 2);
        assert!(plan.updates.is_empty());
    }

    #[tokio::test]
    async fn ambiguous_create_is_reconciled_from_next_list() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let existing = json!([{
            "id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":HOST,"type":"CAA",
            "content":"0 issuewild \";\"","data":{"flags":0,"tag":"issuewild","value":";"},
            "ttl":300,"proxied":false,"comment":SERVING_COMMENT
        }]);
        let replies = [
            (
                200,
                json!({"success":true,"result":[],"result_info":{"total_pages":0}}),
            ),
            (503, json!({"success":false})),
            (
                200,
                json!({"success":true,"result":existing,"result_info":{"total_pages":1}}),
            ),
            (
                200,
                json!({"success":true,"result":{"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}),
            ),
            (
                200,
                json!({"success":true,"result":{"id":"cccccccccccccccccccccccccccccccc"}}),
            ),
        ];
        let server = tokio::spawn(async move {
            let mut methods = Vec::new();
            for (status, body) in replies {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buffer = [0; 8192];
                let size = stream.read(&mut buffer).await.unwrap();
                let request = String::from_utf8_lossy(&buffer[..size]);
                methods.push(request.split_whitespace().next().unwrap().to_owned());
                let body = body.to_string();
                let response = format!(
                    "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
            methods
        });
        let mut provider = CloudflareProvider::new(
            TEST_ZONE.into(),
            "fixture-token".into(),
            CloudflareScope::Serving,
        )
        .unwrap();
        provider.base = Url::parse(&format!(
            "http://{address}/client/v4/zones/{TEST_ZONE}/dns_records"
        ))
        .unwrap();
        let change = NameRecords {
            hostname: HOST.into(),
            addresses: vec!["192.0.2.2".parse().unwrap()],
            acme_account_uri: "https://acme-v02.api.letsencrypt.org/acme/acct/123".into(),
        };
        assert!(matches!(
            provider.publish_name(change.clone()).await,
            Err(DnsError::Unavailable)
        ));
        provider.publish_name(change).await.unwrap();
        assert_eq!(
            server.await.unwrap(),
            ["GET", "POST", "GET", "POST", "POST"]
        );
    }

    #[tokio::test]
    async fn owned_metadata_drift_uses_patch_in_place() {
        let change = NameRecords {
            hostname: HOST.into(),
            addresses: vec!["192.0.2.2".parse().unwrap()],
            acme_account_uri: "https://acme-v02.api.letsencrypt.org/acme/acct/123".into(),
        };
        let record: Record = serde_json::from_value(json!({
            "id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":HOST,"type":"A",
            "content":"192.0.2.2","ttl":120,"proxied":true,"comment":SERVING_COMMENT
        }))
        .unwrap();
        let plan = plan_serving(vec![record], serving_desired(&change).unwrap()).unwrap();
        assert!(plan.stale.is_empty());
        assert_eq!(plan.missing.len(), 2);
        assert_eq!(plan.updates.len(), 1);
        let (provider, server) = fixture(json!([]), 1).await;
        let (record, body) = plan.updates.into_iter().next().unwrap();
        provider.update(&record, body).await.unwrap();
        assert!(server.await.unwrap()[0].starts_with("PATCH "));
    }

    #[tokio::test]
    async fn retirement_keeps_wildcard_deny_until_issue_is_removed() {
        let records = json!([
            {"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":HOST,"type":"CAA","content":"0 issuewild \";\"","data":{"flags":0,"tag":"issuewild","value":";"},"ttl":300,"comment":SERVING_COMMENT},
            {"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","name":HOST,"type":"A","content":"192.0.2.2","ttl":300,"comment":SERVING_COMMENT},
            {"id":"cccccccccccccccccccccccccccccccc","name":HOST,"type":"CAA","content":"0 issue \"letsencrypt.org\"","data":{"flags":0,"tag":"issue","value":"letsencrypt.org"},"ttl":300,"comment":SERVING_COMMENT}
        ]);
        let (mut provider, server) = fixture(records, 4).await;
        provider.scope = CloudflareScope::Serving;
        provider.retire_name(HOST).await.unwrap();
        let requests = server.await.unwrap();
        assert!(requests[1].contains("/cccccccccccccccccccccccccccccccc "));
        assert!(requests[2].contains("/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb "));
        assert!(requests[3].contains("/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "));
    }
}
