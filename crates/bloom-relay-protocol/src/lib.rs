//! Versioned, scope-bound relay wire messages. No wallet or ceremony authority lives here.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::str::FromStr;
use thiserror::Error;
use uuid::Uuid;

pub const WIRE_VERSION: u16 = 1;
pub const MAX_CONTROL_BODY: usize = 16 * 1024;
pub const MAX_CLIENT_HELLO: usize = 64 * 1024;
pub const CLIENT_HELLO_TIMEOUT_SECS: u64 = 5;
pub const TICKET_TIMEOUT_SECS: u64 = 10;
pub const MAX_INSTALLATION_STREAMS: usize = 128;
pub const MAX_GATEWAY_STREAMS: usize = 10_000;
pub const BUFFER_PER_DIRECTION: usize = 64 * 1024;
pub const BUFFER_BUDGET: usize = 256 * 1024 * 1024;
pub const STREAM_IDLE_SECS: u64 = 120;
pub const STREAM_LIFETIME_SECS: u64 = 1800;
pub const HEARTBEAT_SECS: u64 = 15;
pub const DEAD_PEER_SECS: u64 = 45;
/// Maximum tolerated positive server clock offset when a client validates a
/// timestamp in an authenticated, trusted response. Expiration remains strict.
pub const TRUSTED_RESPONSE_CLOCK_SKEW_MS: u64 = 5_000;
/// Keeps the account-bound CAA value within its 255-octet DNS field limit.
pub const MAX_ACME_ACCOUNT_URI_LEN: usize = 200;

const ACME_PRODUCTION_ACCOUNT_PREFIX: &str = "https://acme-v02.api.letsencrypt.org/acme/acct/";
const ACME_STAGING_ACCOUNT_PREFIX: &str = "https://acme-staging-v02.api.letsencrypt.org/acme/acct/";

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcmeEnvironment {
    #[default]
    Production,
    Staging,
}

impl AcmeEnvironment {
    pub fn account_uri_prefix(self) -> &'static str {
        match self {
            Self::Production => ACME_PRODUCTION_ACCOUNT_PREFIX,
            Self::Staging => ACME_STAGING_ACCOUNT_PREFIX,
        }
    }

    pub fn validate_account_uri(self, account_uri: &str) -> Result<(), ProtocolError> {
        if account_uri.len() > MAX_ACME_ACCOUNT_URI_LEN {
            return Err(ProtocolError::InvalidAcmeAccountUri);
        }
        let Some(account_id) = account_uri.strip_prefix(self.account_uri_prefix()) else {
            return Err(ProtocolError::InvalidAcmeAccountUri);
        };
        if account_id.is_empty() || !account_id.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ProtocolError::InvalidAcmeAccountUri);
        }
        Ok(())
    }
}

impl FromStr for AcmeEnvironment {
    type Err = ProtocolError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "production" => Ok(Self::Production),
            "staging" => Ok(Self::Staging),
            _ => Err(ProtocolError::InvalidAcmeEnvironment),
        }
    }
}

pub fn validate_acme_account_uri(account_uri: &str) -> Result<AcmeEnvironment, ProtocolError> {
    for environment in [AcmeEnvironment::Production, AcmeEnvironment::Staging] {
        if environment.validate_account_uri(account_uri).is_ok() {
            return Ok(environment);
        }
    }
    Err(ProtocolError::InvalidAcmeAccountUri)
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    SurfaceAdmin,
    Tunnel,
    DnsChallenge,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthClaims {
    pub version: u16,
    pub installation_id: Uuid,
    pub scope: Scope,
    pub generation: u64,
    pub audience: String,
    pub operation_id: Uuid,
    pub nonce: String,
    pub expires_at_ms: u64,
    pub body_sha256: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRequest<T> {
    pub claims: AuthClaims,
    pub body: T,
    pub signature: String,
}

impl AuthClaims {
    /// RFC 8785 JSON canonicalization, separated from other Bloom signatures.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        if self.version != WIRE_VERSION {
            return Err(ProtocolError::IncompatibleVersion);
        }
        let mut bytes = b"bloom-relay/control/v1\0".to_vec();
        bytes.extend(serde_jcs::to_vec(self).map_err(|_| ProtocolError::InvalidEncoding)?);
        Ok(bytes)
    }

    pub fn verify(
        &self,
        body: &[u8],
        signature: &str,
        key: &VerifyingKey,
        required_scope: Scope,
        audience: &str,
        now_ms: u64,
    ) -> Result<(), ProtocolError> {
        if self.scope != required_scope || self.audience != audience {
            return Err(ProtocolError::Unauthorized);
        }
        if self.expires_at_ms <= now_ms || self.expires_at_ms > now_ms.saturating_add(60_000) {
            return Err(ProtocolError::Expired);
        }
        if body.len() > MAX_CONTROL_BODY {
            return Err(ProtocolError::TooLarge);
        }
        if sha256_hex(body) != self.body_sha256 {
            return Err(ProtocolError::InvalidSignature);
        }
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| ProtocolError::InvalidSignature)?;
        let signature =
            Signature::from_slice(&signature_bytes).map_err(|_| ProtocolError::InvalidSignature)?;
        key.verify(&self.signing_bytes()?, &signature)
            .map_err(|_| ProtocolError::InvalidSignature)
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapChallenge {
    pub version: u16,
    pub nonce: String,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllocateRequest {
    pub admin_public_key: String,
    pub bootstrap_nonce: String,
    pub operation_id: Uuid,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allocation {
    pub version: u16,
    pub installation_id: Uuid,
    pub hostname: String,
    pub placement: String,
    pub state: AllocationState,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllocationReceipt {
    pub allocation: Allocation,
    pub operation_id: Uuid,
    /// Lowercase SHA-256 of the 32-byte installation admin public key.
    pub admin_key_sha256: String,
    pub issued_at_ms: u64,
    /// Ed25519 over the domain-separated RFC 8785 canonical body.
    pub signature: String,
}

impl AllocationReceipt {
    pub fn signed_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        if self.allocation.version != WIRE_VERSION {
            return Err(ProtocolError::IncompatibleVersion);
        }
        let mut bytes = b"bloom-relay/allocation-receipt/v1\0".to_vec();
        bytes.extend(
            serde_jcs::to_vec(&(
                &self.allocation,
                self.operation_id,
                &self.admin_key_sha256,
                self.issued_at_ms,
            ))
            .map_err(|_| ProtocolError::InvalidEncoding)?,
        );
        Ok(bytes)
    }

    pub fn verify(
        &self,
        relay_key: &VerifyingKey,
        operation_id: Uuid,
        admin_public_key: &[u8; 32],
        now_ms: u64,
    ) -> Result<(), ProtocolError> {
        validate_hostname(&self.allocation.hostname)?;
        if self.operation_id != operation_id
            || self.admin_key_sha256 != sha256_hex(admin_public_key)
            || self.issued_at_ms > now_ms.saturating_add(TRUSTED_RESPONSE_CLOCK_SKEW_MS)
            || now_ms.saturating_sub(self.issued_at_ms) > 300_000
        {
            return Err(ProtocolError::Unauthorized);
        }
        let signature = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| ProtocolError::InvalidSignature)?;
        let signature =
            Signature::from_slice(&signature).map_err(|_| ProtocolError::InvalidSignature)?;
        relay_key
            .verify(&self.signed_bytes()?, &signature)
            .map_err(|_| ProtocolError::InvalidSignature)
    }

    pub fn verify_bytes(
        &self,
        relay_public_key: &[u8; 32],
        operation_id: Uuid,
        admin_public_key: &[u8; 32],
        now_ms: u64,
    ) -> Result<(), ProtocolError> {
        let key = VerifyingKey::from_bytes(relay_public_key)
            .map_err(|_| ProtocolError::InvalidSignature)?;
        self.verify(&key, operation_id, admin_public_key, now_ms)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllocationState {
    PendingDns,
    DnsReady,
    Retired,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeLease {
    pub operation_id: Uuid,
    pub txt_value: String,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialIssueRequest {
    pub scope: Scope,
    /// Client-generated 256-bit bearer secret; only its SHA-256 is sent.
    pub token_sha256: String,
    pub validity_seconds: u32,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialIssueReceipt {
    pub version: u16,
    pub scope: Scope,
    pub generation: u64,
    pub operation_id: Uuid,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRenewRequest {
    pub version: u16,
    pub installation_id: Uuid,
    pub scope: Scope,
    pub generation: u64,
    pub operation_id: Uuid,
    pub nonce: String,
    pub expires_at_ms: u64,
    pub new_token_sha256: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeAccountRequest {
    pub account_uri: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationStatusRequest {
    pub installation_id: Uuid,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetireRequest {
    pub installation_id: Uuid,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsChallengeRequest {
    pub version: u16,
    pub installation_id: Uuid,
    pub lease: ChallengeLease,
    pub nonce: String,
    pub generation: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsChallengeDeleteRequest {
    pub version: u16,
    pub installation_id: Uuid,
    pub lease_id: Uuid,
    pub nonce: String,
    pub generation: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateMetadata {
    pub hostname: String,
    pub acme_account_uri: String,
    pub key_fingerprint: String,
    pub lineage: String,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum TunnelEvent {
    Open {
        version: u16,
        ticket: String,
        connection_id: Uuid,
        hostname: String,
        generation: u64,
        expires_at_ms: u64,
    },
    Heartbeat {
        version: u16,
        generation: u64,
    },
}

/// Bounded newline-delimited control messages over the HTTP/2 byte stream.
/// HTTP/2 DATA frame boundaries are deliberately not used as message boundaries.
#[derive(Default)]
pub struct ControlDecoder {
    pending: Vec<u8>,
}

impl ControlDecoder {
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<TunnelEvent>, ProtocolError> {
        if chunk.len() > MAX_CONTROL_BODY || self.pending.len() + chunk.len() > MAX_CONTROL_BODY {
            return Err(ProtocolError::TooLarge);
        }
        self.pending.extend_from_slice(chunk);
        let mut events = Vec::new();
        while let Some(end) = self.pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=end).collect();
            let event = serde_json::from_slice(&line[..line.len() - 1])
                .map_err(|_| ProtocolError::InvalidEncoding)?;
            events.push(event);
        }
        Ok(events)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorEnvelope {
    pub code: ErrorCode,
    pub request_id: Uuid,
    pub retryable: bool,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    Unauthorized,
    Conflict,
    ExpiredOrReplayed,
    QuotaExceeded,
    DependencyUnavailable,
    Internal,
    IncompatibleVersion,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ProtocolError {
    #[error("incompatible relay protocol version")]
    IncompatibleVersion,
    #[error("invalid encoding")]
    InvalidEncoding,
    #[error("unauthorized")]
    Unauthorized,
    #[error("expired or invalid deadline")]
    Expired,
    #[error("control message too large")]
    TooLarge,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid hostname")]
    InvalidHostname,
    #[error("invalid ACME environment")]
    InvalidAcmeEnvironment,
    #[error("invalid ACME account URI")]
    InvalidAcmeAccountUri,
}

pub fn validate_hostname(hostname: &str) -> Result<(), ProtocolError> {
    let Some(label) = hostname.strip_suffix(".relay.bloom.directory") else {
        return Err(ProtocolError::InvalidHostname);
    };
    if label.len() != 26
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return Err(ProtocolError::InvalidHostname);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn signed_claims_reject_wrong_scope_body_and_deadline() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let body = b"{}";
        let claims = AuthClaims {
            version: WIRE_VERSION,
            installation_id: Uuid::nil(),
            scope: Scope::DnsChallenge,
            generation: 2,
            audience: "relay-control.bloom.directory".into(),
            operation_id: Uuid::nil(),
            nonce: "nonce".into(),
            expires_at_ms: 5_000,
            body_sha256: sha256_hex(body),
        };
        let sig = URL_SAFE_NO_PAD.encode(key.sign(&claims.signing_bytes().unwrap()).to_bytes());
        assert!(
            claims
                .verify(
                    body,
                    &sig,
                    &key.verifying_key(),
                    Scope::DnsChallenge,
                    "relay-control.bloom.directory",
                    1_000
                )
                .is_ok()
        );
        assert_eq!(
            claims.verify(
                body,
                &sig,
                &key.verifying_key(),
                Scope::SurfaceAdmin,
                "relay-control.bloom.directory",
                1_000
            ),
            Err(ProtocolError::Unauthorized)
        );
        assert_eq!(
            claims.verify(
                b"bad",
                &sig,
                &key.verifying_key(),
                Scope::DnsChallenge,
                "relay-control.bloom.directory",
                1_000
            ),
            Err(ProtocolError::InvalidSignature)
        );
        assert_eq!(
            claims.verify(
                body,
                &sig,
                &key.verifying_key(),
                Scope::DnsChallenge,
                "relay-control.bloom.directory",
                5_000
            ),
            Err(ProtocolError::Expired)
        );
    }

    #[test]
    fn hostname_is_exact_and_lowercase() {
        assert!(validate_hostname("abcdefghijklmnopqrstuv2345.relay.bloom.directory").is_ok());
        for invalid in [
            "relay.bloom.directory",
            "ABCDefghijklmnopqrstuv2345.relay.bloom.directory",
            "abcdefghijklmnopqrstuv2345.relay.bloom.directory.",
            "x.abcdefghijklmnopqrstuv2345.relay.bloom.directory",
        ] {
            assert!(validate_hostname(invalid).is_err());
        }
    }

    #[test]
    fn acme_environment_accepts_only_its_exact_account_uri_namespace() {
        let production = "https://acme-v02.api.letsencrypt.org/acme/acct/123";
        let staging = "https://acme-staging-v02.api.letsencrypt.org/acme/acct/456";
        assert_eq!(
            validate_acme_account_uri(production),
            Ok(AcmeEnvironment::Production)
        );
        assert_eq!(
            validate_acme_account_uri(staging),
            Ok(AcmeEnvironment::Staging)
        );
        assert!(
            AcmeEnvironment::Production
                .validate_account_uri(staging)
                .is_err()
        );
        assert!(
            AcmeEnvironment::Staging
                .validate_account_uri(production)
                .is_err()
        );
        for invalid in [
            "https://acme-v02.api.letsencrypt.org/acme/acct/",
            "https://acme-v02.api.letsencrypt.org/acme/acct/123/",
            "https://acme-v02.api.letsencrypt.org/acme/acct/12x",
            "https://example.com/acme/acct/123",
            "http://acme-v02.api.letsencrypt.org/acme/acct/123",
        ] {
            assert!(validate_acme_account_uri(invalid).is_err(), "{invalid}");
        }
        let overlong = format!(
            "{}{}",
            AcmeEnvironment::Production.account_uri_prefix(),
            "1".repeat(
                MAX_ACME_ACCOUNT_URI_LEN + 1
                    - AcmeEnvironment::Production.account_uri_prefix().len()
            )
        );
        assert_eq!(overlong.len(), MAX_ACME_ACCOUNT_URI_LEN + 1);
        assert!(validate_acme_account_uri(&overlong).is_err());
        assert_eq!("production".parse(), Ok(AcmeEnvironment::Production));
        assert_eq!("staging".parse(), Ok(AcmeEnvironment::Staging));
        assert!("STAGING".parse::<AcmeEnvironment>().is_err());
    }

    #[test]
    fn control_decoder_handles_split_and_coalesced_frames() {
        let event = TunnelEvent::Heartbeat {
            version: WIRE_VERSION,
            generation: 3,
        };
        let line = format!("{}\n", serde_json::to_string(&event).unwrap());
        let mut decoder = ControlDecoder::default();
        assert!(decoder.push(&line.as_bytes()[..4]).unwrap().is_empty());
        assert_eq!(
            decoder.push(&line.as_bytes()[4..]).unwrap(),
            vec![event.clone()]
        );
        assert_eq!(
            decoder.push(format!("{line}{line}").as_bytes()).unwrap(),
            vec![event.clone(), event]
        );
        assert_eq!(
            decoder.push(&vec![b'x'; MAX_CONTROL_BODY + 1]).unwrap_err(),
            ProtocolError::TooLarge
        );
    }

    #[test]
    fn allocation_receipt_binds_operation_and_admin_identity() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let mut receipt = AllocationReceipt {
            allocation: Allocation {
                version: WIRE_VERSION,
                installation_id: Uuid::new_v4(),
                hostname: "abcdefghijklmnopqrstuv2345.relay.bloom.directory".into(),
                placement: "shard-1".into(),
                state: AllocationState::PendingDns,
            },
            operation_id: Uuid::new_v4(),
            admin_key_sha256: sha256_hex(&[7; 32]),
            issued_at_ms: 1000,
            signature: String::new(),
        };
        receipt.signature =
            URL_SAFE_NO_PAD.encode(key.sign(&receipt.signed_bytes().unwrap()).to_bytes());
        assert!(
            receipt
                .verify(&key.verifying_key(), receipt.operation_id, &[7; 32], 1001)
                .is_ok()
        );
        assert_eq!(
            receipt.verify(&key.verifying_key(), Uuid::new_v4(), &[7; 32], 1001),
            Err(ProtocolError::Unauthorized)
        );
        assert_eq!(
            receipt.verify(&key.verifying_key(), receipt.operation_id, &[8; 32], 1001),
            Err(ProtocolError::Unauthorized)
        );
        receipt.allocation.hostname = "sibling.example".into();
        assert_eq!(
            receipt.verify(&key.verifying_key(), receipt.operation_id, &[7; 32], 1001),
            Err(ProtocolError::InvalidHostname)
        );
    }

    #[test]
    fn allocation_receipt_allows_only_bounded_future_clock_offset() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let now = 1_000_000;
        let mut receipt = AllocationReceipt {
            allocation: Allocation {
                version: WIRE_VERSION,
                installation_id: Uuid::new_v4(),
                hostname: "abcdefghijklmnopqrstuv2345.relay.bloom.directory".into(),
                placement: "shard-1".into(),
                state: AllocationState::PendingDns,
            },
            operation_id: Uuid::new_v4(),
            admin_key_sha256: sha256_hex(&[7; 32]),
            issued_at_ms: now + TRUSTED_RESPONSE_CLOCK_SKEW_MS,
            signature: String::new(),
        };
        receipt.signature =
            URL_SAFE_NO_PAD.encode(key.sign(&receipt.signed_bytes().unwrap()).to_bytes());
        assert!(
            receipt
                .verify(&key.verifying_key(), receipt.operation_id, &[7; 32], now)
                .is_ok()
        );

        receipt.issued_at_ms += 1;
        receipt.signature =
            URL_SAFE_NO_PAD.encode(key.sign(&receipt.signed_bytes().unwrap()).to_bytes());
        assert_eq!(
            receipt.verify(&key.verifying_key(), receipt.operation_id, &[7; 32], now),
            Err(ProtocolError::Unauthorized)
        );
    }
}
