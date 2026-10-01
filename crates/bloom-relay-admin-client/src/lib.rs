//! Pinned HTTPS bootstrap for privileged Signer administration.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bloom_relay_protocol::{
    AcmeAccountRequest, AllocateRequest, Allocation, AllocationReceipt, AuthClaims,
    BootstrapChallenge, CredentialIssueReceipt, CredentialIssueRequest, InstallationStatusRequest,
    RetireRequest, Scope, SignedRequest, TRUSTED_RESPONSE_CLOCK_SKEW_MS, WIRE_VERSION, sha256_hex,
    validate_hostname,
};
use rand::{RngCore, rngs::OsRng};
use std::{
    io::Read,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

const CONTROL_ORIGIN: &str = "https://relay-control.bloom.directory";
const CONTROL_AUDIENCE: &str = "relay-control.bloom.directory";

pub struct EnrollmentConfig {
    /// Pinned PEM trust anchors for the relay control service: one or more
    /// root certificates, any of which may issue the control certificate.
    pub control_ca_pem: Vec<u8>,
}

pub struct SecretToken(Zeroizing<String>);
impl SecretToken {
    pub fn generate() -> Self {
        let mut random = [0u8; 32];
        OsRng.fill_bytes(&mut random);
        Self(Zeroizing::new(URL_SAFE_NO_PAD.encode(random)))
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
    pub fn from_encoded(value: String) -> Result<Self, EnrollmentError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(value.as_bytes())
            .map_err(|_| EnrollmentError::InvalidTrust)?;
        if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(bytes) != value {
            return Err(EnrollmentError::InvalidTrust);
        }
        Ok(Self(Zeroizing::new(value)))
    }
}

#[derive(Debug, Error)]
pub enum EnrollmentError {
    #[error("invalid relay trust configuration")]
    InvalidTrust,
    #[error("relay control unavailable")]
    Unavailable,
    /// The control API (or the proxy in front of it) answered with an HTTP
    /// error status: a refusal, not an outage. 503 on `/v1/bootstrap/` is the
    /// closed enrollment gate.
    #[error("relay control refused the request (HTTP {0})")]
    Refused(u16),
    #[error("relay request rejected")]
    Rejected,
    #[error("relay response failed identity verification")]
    InvalidReceipt,
    #[error("incompatible relay protocol")]
    IncompatibleProtocol,
}

/// `ureq` returns HTTP error statuses as errors; keep them apart from
/// connection failures so a refusal never reads as an outage.
fn control_error(error: ureq::Error) -> EnrollmentError {
    match error {
        ureq::Error::StatusCode(status) => EnrollmentError::Refused(status),
        _ => EnrollmentError::Unavailable,
    }
}

/// The caller owns the protected admin key and the pinned relay receipt
/// verification keys; a receipt signed by any of them is accepted. No hostname
/// or origin is accepted from an untrusted response without proof.
pub fn enroll<F>(
    config: EnrollmentConfig,
    admin_public_key: &[u8; 32],
    relay_receipt_public_keys: &[[u8; 32]],
    operation_id: Uuid,
    sign: F,
) -> Result<AllocationReceipt, EnrollmentError>
where
    F: Fn(&[u8]) -> Result<[u8; 64], EnrollmentError>,
{
    let agent = build_agent(&config)?;
    let challenge: BootstrapChallenge = read_bounded_json(
        agent
            .post(format!("{CONTROL_ORIGIN}/v1/bootstrap/challenge"))
            .send_empty()
            .map_err(control_error)?,
    )?;
    if challenge.version != WIRE_VERSION {
        return Err(EnrollmentError::IncompatibleProtocol);
    }
    let now = now_ms();
    if !trusted_response_expiry(challenge.expires_at_ms, now, 60_000) || challenge.nonce.len() != 43
    {
        return Err(EnrollmentError::Rejected);
    }
    let body = AllocateRequest {
        admin_public_key: URL_SAFE_NO_PAD.encode(admin_public_key),
        bootstrap_nonce: challenge.nonce.clone(),
        operation_id,
    };
    let canonical_body = serde_jcs::to_vec(&body).map_err(|_| EnrollmentError::Rejected)?;
    let claims = AuthClaims {
        version: WIRE_VERSION,
        installation_id: Uuid::nil(),
        scope: Scope::SurfaceAdmin,
        generation: 0,
        audience: CONTROL_AUDIENCE.into(),
        operation_id,
        nonce: challenge.nonce,
        expires_at_ms: now.saturating_add(30_000).min(challenge.expires_at_ms),
        body_sha256: sha256_hex(&canonical_body),
    };
    let signature = URL_SAFE_NO_PAD.encode(sign(
        &claims
            .signing_bytes()
            .map_err(|_| EnrollmentError::Rejected)?,
    )?);
    let request = SignedRequest {
        claims,
        body,
        signature,
    };
    let receipt: AllocationReceipt = read_bounded_json(
        agent
            .post(format!("{CONTROL_ORIGIN}/v1/bootstrap/enroll"))
            .send_json(&request)
            .map_err(control_error)?,
    )?;
    receipt
        .verify_bytes(
            relay_receipt_public_keys,
            operation_id,
            admin_public_key,
            now_ms(),
        )
        .map_err(|_| EnrollmentError::InvalidReceipt)?;
    Ok(receipt)
}

/// The caller retains `token` through ambiguous network failures and retries
/// with the same operation ID. Only its digest crosses the control API.
pub fn issue_credential<F>(
    config: EnrollmentConfig,
    installation_id: Uuid,
    scope: Scope,
    token: &SecretToken,
    operation_id: Uuid,
    sign: F,
) -> Result<CredentialIssueReceipt, EnrollmentError>
where
    F: Fn(&[u8]) -> Result<[u8; 64], EnrollmentError>,
{
    if !matches!(scope, Scope::Tunnel | Scope::DnsChallenge) {
        return Err(EnrollmentError::Rejected);
    }
    let agent = build_agent(&config)?;
    let body = CredentialIssueRequest {
        scope,
        token_sha256: sha256_hex(token.expose().as_bytes()),
        validity_seconds: 86_400,
    };
    let now = now_ms();
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let claims = AuthClaims {
        version: WIRE_VERSION,
        installation_id,
        scope: Scope::SurfaceAdmin,
        generation: 0,
        audience: CONTROL_AUDIENCE.into(),
        operation_id,
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        expires_at_ms: now + 30_000,
        body_sha256: sha256_hex(&serde_jcs::to_vec(&body).map_err(|_| EnrollmentError::Rejected)?),
    };
    let signature = URL_SAFE_NO_PAD.encode(sign(
        &claims
            .signing_bytes()
            .map_err(|_| EnrollmentError::Rejected)?,
    )?);
    let request = SignedRequest {
        claims,
        body,
        signature,
    };
    let receipt: CredentialIssueReceipt = read_bounded_json(
        agent
            .post(format!("{CONTROL_ORIGIN}/v1/credentials"))
            .send_json(&request)
            .map_err(control_error)?,
    )?;
    let receipt_now = now_ms();
    if receipt.version != WIRE_VERSION
        || receipt.scope != scope
        || receipt.operation_id != operation_id
        || receipt.generation == 0
        || !trusted_response_expiry(receipt.expires_at_ms, receipt_now, 86_400_000)
    {
        return Err(EnrollmentError::InvalidReceipt);
    }
    Ok(receipt)
}

/// One-time privileged binding of Broker's production ACME account to the
/// allocated installation before restrictive CAA records are published.
pub fn register_acme_account<F>(
    config: EnrollmentConfig,
    installation_id: Uuid,
    account_uri: String,
    operation_id: Uuid,
    sign: F,
) -> Result<(), EnrollmentError>
where
    F: Fn(&[u8]) -> Result<[u8; 64], EnrollmentError>,
{
    let agent = build_agent(&config)?;
    let body = AcmeAccountRequest { account_uri };
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let claims = AuthClaims {
        version: WIRE_VERSION,
        installation_id,
        scope: Scope::SurfaceAdmin,
        generation: 0,
        audience: CONTROL_AUDIENCE.into(),
        operation_id,
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        expires_at_ms: now_ms() + 30_000,
        body_sha256: sha256_hex(&serde_jcs::to_vec(&body).map_err(|_| EnrollmentError::Rejected)?),
    };
    let signature = URL_SAFE_NO_PAD.encode(sign(
        &claims
            .signing_bytes()
            .map_err(|_| EnrollmentError::Rejected)?,
    )?);
    let response = agent
        .post(format!("{CONTROL_ORIGIN}/v1/acme-account"))
        .send_json(SignedRequest {
            claims,
            body,
            signature,
        })
        .map_err(control_error)?;
    if response.status() != 202 {
        return Err(EnrollmentError::Rejected);
    }
    Ok(())
}

pub fn installation_status<F>(
    config: EnrollmentConfig,
    installation_id: Uuid,
    operation_id: Uuid,
    sign: F,
) -> Result<Allocation, EnrollmentError>
where
    F: Fn(&[u8]) -> Result<[u8; 64], EnrollmentError>,
{
    let response = signed_admin_call(
        config,
        installation_id,
        operation_id,
        InstallationStatusRequest { installation_id },
        "/v1/installations/status",
        sign,
    )?;
    let allocation: Allocation = read_bounded_json(response)?;
    if allocation.version != WIRE_VERSION
        || allocation.installation_id != installation_id
        || validate_hostname(&allocation.hostname).is_err()
    {
        return Err(EnrollmentError::InvalidReceipt);
    }
    Ok(allocation)
}

pub fn retire_installation<F>(
    config: EnrollmentConfig,
    installation_id: Uuid,
    operation_id: Uuid,
    sign: F,
) -> Result<(), EnrollmentError>
where
    F: Fn(&[u8]) -> Result<[u8; 64], EnrollmentError>,
{
    let response = signed_admin_call(
        config,
        installation_id,
        operation_id,
        RetireRequest { installation_id },
        "/v1/installations/retire",
        sign,
    )?;
    if response.status() != 202 {
        return Err(EnrollmentError::Rejected);
    }
    Ok(())
}

fn signed_admin_call<T, F>(
    config: EnrollmentConfig,
    installation_id: Uuid,
    operation_id: Uuid,
    body: T,
    path: &str,
    sign: F,
) -> Result<ureq::http::Response<ureq::Body>, EnrollmentError>
where
    T: serde::Serialize,
    F: Fn(&[u8]) -> Result<[u8; 64], EnrollmentError>,
{
    let agent = build_agent(&config)?;
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let claims = AuthClaims {
        version: WIRE_VERSION,
        installation_id,
        scope: Scope::SurfaceAdmin,
        generation: 0,
        audience: CONTROL_AUDIENCE.into(),
        operation_id,
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        expires_at_ms: now_ms() + 30_000,
        body_sha256: sha256_hex(&serde_jcs::to_vec(&body).map_err(|_| EnrollmentError::Rejected)?),
    };
    let signature = URL_SAFE_NO_PAD.encode(sign(
        &claims
            .signing_bytes()
            .map_err(|_| EnrollmentError::Rejected)?,
    )?);
    agent
        .post(format!("{CONTROL_ORIGIN}{path}"))
        .send_json(SignedRequest {
            claims,
            body,
            signature,
        })
        .map_err(control_error)
}

/// Every certificate in a PEM bundle; `None` if it holds none or any is
/// malformed, so a damaged pin file never silently narrows to fewer roots.
fn pinned_roots(pem: &[u8]) -> Option<Vec<ureq::tls::Certificate<'static>>> {
    let mut roots = Vec::new();
    for item in ureq::tls::parse_pem(pem) {
        match item.ok()? {
            ureq::tls::PemItem::Certificate(cert) => roots.push(cert),
            _ => return None,
        }
    }
    (!roots.is_empty()).then_some(roots)
}

fn build_agent(config: &EnrollmentConfig) -> Result<ureq::Agent, EnrollmentError> {
    let roots = pinned_roots(&config.control_ca_pem).ok_or(EnrollmentError::InvalidTrust)?;
    Ok(ureq::config::Config::builder()
        .https_only(true)
        .max_redirects(0)
        .proxy(None)
        .timeout_global(Some(Duration::from_secs(10)))
        .tls_config(
            ureq::tls::TlsConfig::builder()
                .provider(ureq::tls::TlsProvider::Rustls)
                .root_certs(ureq::tls::RootCerts::new_with_certs(&roots))
                .build(),
        )
        .build()
        .new_agent())
}

fn read_bounded_json<T: serde::de::DeserializeOwned>(
    mut response: ureq::http::Response<ureq::Body>,
) -> Result<T, EnrollmentError> {
    let mut bytes = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(16 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| EnrollmentError::Rejected)?;
    if bytes.len() > 16 * 1024 {
        return Err(EnrollmentError::Rejected);
    }
    serde_json::from_slice(&bytes).map_err(|_| EnrollmentError::Rejected)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn trusted_response_expiry(expires_at_ms: u64, now_ms: u64, lifetime_ms: u64) -> bool {
    expires_at_ms > now_ms
        && expires_at_ms
            <= now_ms
                .saturating_add(lifetime_ms)
                .saturating_add(TRUSTED_RESPONSE_CLOCK_SKEW_MS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_roots_load_every_certificate_or_none() {
        let bundle = include_bytes!("../../../testdata/isrg-roots.pem");
        assert_eq!(pinned_roots(bundle).unwrap().len(), 2);
        let mut damaged = bundle.to_vec();
        damaged.extend_from_slice(
            b"-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n",
        );
        assert!(pinned_roots(&damaged).is_none());
        assert!(pinned_roots(b"").is_none());
        let mut with_key = bundle.to_vec();
        with_key.extend_from_slice(b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n-----END PRIVATE KEY-----\n");
        assert!(pinned_roots(&with_key).is_none());
    }

    #[test]
    fn http_refusals_are_not_reported_as_outages() {
        assert!(matches!(
            control_error(ureq::Error::StatusCode(503)),
            EnrollmentError::Refused(503)
        ));
        assert_eq!(
            EnrollmentError::Refused(503).to_string(),
            "relay control refused the request (HTTP 503)"
        );
        assert!(matches!(
            control_error(ureq::Error::Io(std::io::Error::other("reset"))),
            EnrollmentError::Unavailable
        ));
    }

    #[test]
    fn trusted_response_expiry_allows_only_bounded_future_clock_offset() {
        let now = 1_000_000;
        let lifetime = 60_000;
        assert!(trusted_response_expiry(
            now + lifetime + TRUSTED_RESPONSE_CLOCK_SKEW_MS,
            now,
            lifetime
        ));
        assert!(!trusted_response_expiry(
            now + lifetime + TRUSTED_RESPONSE_CLOCK_SKEW_MS + 1,
            now,
            lifetime
        ));
        assert!(!trusted_response_expiry(now, now, lifetime));
    }
}
