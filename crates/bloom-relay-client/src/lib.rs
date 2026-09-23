//! Broker-owned tunnel client. It can only attach to the fixed ceremony listener.

use bloom_relay_protocol::{
    CertificateMetadata, ChallengeLease, ControlDecoder, CredentialIssueReceipt,
    CredentialRenewRequest, DnsChallengeDeleteRequest, DnsChallengeRequest,
    MAX_INSTALLATION_STREAMS, Scope, TRUSTED_RESPONSE_CLOCK_SKEW_MS, TunnelEvent, WIRE_VERSION,
    sha256_hex, validate_hostname,
};
use bytes::Bytes;
use futures_util::future::poll_fn;
use h2::client;
use http::{Method, Request, Uri};
use rustls::{ClientConfig, pki_types::ServerName};
use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{Semaphore, watch},
    task::JoinSet,
    time::timeout,
};
use tokio_rustls::TlsConnector;

pub const CEREMONY_UPSTREAM: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18735);
const CONTROL_ORIGIN: &str = "https://relay-control.bloom.directory";

/// The caller persists `new_token` and `operation_id` before this call and
/// atomically replaces its protected credential file after the receipt. On an
/// ambiguous transport failure it retries those same values.
pub async fn renew_scoped_credential(
    control_ca_pem: Vec<u8>,
    installation_id: uuid::Uuid,
    scope: Scope,
    generation: u64,
    credential_path: PathBuf,
    new_token: String,
    operation_id: uuid::Uuid,
) -> Result<CredentialIssueReceipt, ClientError> {
    if !matches!(scope, Scope::Tunnel | Scope::DnsChallenge)
        || generation == 0
        || installation_id.is_nil()
        || operation_id.is_nil()
    {
        return Err(ClientError::InvalidConfiguration);
    }
    validate_token(&new_token)?;
    let current = read_credential(&credential_path)?;
    let request = CredentialRenewRequest {
        version: WIRE_VERSION,
        installation_id,
        scope,
        generation,
        operation_id,
        nonce: uuid::Uuid::new_v4().to_string(),
        expires_at_ms: now_ms().saturating_add(30_000),
        new_token_sha256: sha256_hex(new_token.as_bytes()),
    };
    tokio::task::spawn_blocking(move || {
        let agent = pinned_control_agent(&control_ca_pem)?;
        let mut response = agent
            .post(format!("{CONTROL_ORIGIN}/v1/credentials/renew"))
            .header("authorization", format!("Bearer {current}"))
            .send_json(request)
            .map_err(|_| ClientError::Transport)?;
        let receipt: CredentialIssueReceipt = response
            .body_mut()
            .with_config()
            .limit(16 * 1024)
            .read_json()
            .map_err(|_| ClientError::Transport)?;
        let receipt_now = now_ms();
        if receipt.version != WIRE_VERSION
            || receipt.scope != scope
            || receipt.operation_id != operation_id
            || receipt.generation <= generation
            || !trusted_response_expiry(receipt.expires_at_ms, receipt_now, 86_400_000)
        {
            return Err(ClientError::Rejected);
        }
        Ok(receipt)
    })
    .await
    .map_err(|_| ClientError::Transport)?
}

fn pinned_control_agent(ca: &[u8]) -> Result<ureq::Agent, ClientError> {
    let cert =
        ureq::tls::Certificate::from_pem(ca).map_err(|_| ClientError::InvalidConfiguration)?;
    let tls = ureq::tls::TlsConfig::builder()
        .provider(ureq::tls::TlsProvider::Rustls)
        .root_certs(ureq::tls::RootCerts::new_with_certs(&[cert]))
        .build();
    Ok(ureq::config::Config::builder()
        .https_only(true)
        .max_redirects(0)
        .proxy(None)
        .timeout_global(Some(Duration::from_secs(10)))
        .tls_config(tls)
        .build()
        .new_agent())
}

fn validate_token(token: &str) -> Result<(), ClientError> {
    if token.len() < 43
        || token.len() > 128
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(ClientError::InvalidConfiguration);
    }
    Ok(())
}

/// DNS-01 authority is scoped to the allocated installation at the control service.
/// Broker has no API to choose a DNS owner name or mutate arbitrary records.
#[derive(Clone)]
pub struct DnsChallengeClient {
    installation_id: uuid::Uuid,
    generation: u64,
    credential_path: PathBuf,
    control_ca_pem: Vec<u8>,
}

impl DnsChallengeClient {
    pub fn new(
        control_ca_pem: Vec<u8>,
        installation_id: uuid::Uuid,
        generation: u64,
        credential_path: PathBuf,
    ) -> Result<Self, ClientError> {
        if control_ca_pem.is_empty()
            || installation_id.is_nil()
            || generation == 0
            || credential_path.as_os_str().is_empty()
        {
            return Err(ClientError::InvalidConfiguration);
        }
        Ok(Self {
            installation_id,
            generation,
            credential_path,
            control_ca_pem,
        })
    }

    pub async fn create(&self, lease: ChallengeLease) -> Result<(), ClientError> {
        let request = DnsChallengeRequest {
            version: WIRE_VERSION,
            installation_id: self.installation_id,
            generation: self.generation,
            nonce: uuid::Uuid::new_v4().to_string(),
            lease,
        };
        self.call(
            "POST",
            "/v1/dns/challenge".to_owned(),
            Some(serde_json::to_value(request).map_err(|_| ClientError::InvalidConfiguration)?),
            202,
        )
        .await
    }

    pub async fn ready(&self, lease_id: uuid::Uuid) -> Result<bool, ClientError> {
        let path = format!("/v1/dns/challenge/{}/{}", self.installation_id, lease_id);
        let status = self.request("GET", path, None).await?;
        match status {
            204 => Ok(true),
            202 => Ok(false),
            _ => Err(ClientError::Rejected),
        }
    }

    pub async fn delete(&self, lease_id: uuid::Uuid) -> Result<(), ClientError> {
        let request = DnsChallengeDeleteRequest {
            version: WIRE_VERSION,
            installation_id: self.installation_id,
            generation: self.generation,
            nonce: uuid::Uuid::new_v4().to_string(),
            lease_id,
        };
        self.call(
            "POST",
            "/v1/dns/challenge/delete".to_owned(),
            Some(serde_json::to_value(request).map_err(|_| ClientError::InvalidConfiguration)?),
            202,
        )
        .await
    }

    pub async fn report_certificate(
        &self,
        certificate: CertificateMetadata,
    ) -> Result<(), ClientError> {
        self.call(
            "POST",
            "/v1/certificates".to_owned(),
            Some(serde_json::to_value(certificate).map_err(|_| ClientError::InvalidConfiguration)?),
            202,
        )
        .await
    }

    async fn call(
        &self,
        method: &'static str,
        path: String,
        body: Option<serde_json::Value>,
        expected: u16,
    ) -> Result<(), ClientError> {
        if self.request(method, path, body).await? == expected {
            Ok(())
        } else {
            Err(ClientError::Rejected)
        }
    }

    async fn request(
        &self,
        method: &'static str,
        path: String,
        body: Option<serde_json::Value>,
    ) -> Result<u16, ClientError> {
        let token = read_credential(&self.credential_path)?;
        let ca = self.control_ca_pem.clone();
        let installation_id = self.installation_id;
        tokio::task::spawn_blocking(move || {
            let agent = pinned_control_agent(&ca)?;
            let url = format!("{CONTROL_ORIGIN}{path}");
            let authorization = format!("Bearer {token}");
            let response = match (method, body) {
                ("POST", Some(body)) => agent
                    .post(url)
                    .header("authorization", &authorization)
                    .header("x-bloom-installation", installation_id.to_string())
                    .send_json(body),
                ("GET", None) => agent
                    .get(url)
                    .header("authorization", &authorization)
                    .call(),
                _ => return Err(ClientError::InvalidConfiguration),
            }
            .map_err(|_| ClientError::Transport)?;
            Ok(response.status().as_u16())
        })
        .await
        .map_err(|_| ClientError::Transport)?
    }
}

#[derive(Clone)]
pub struct TunnelConfig {
    pub gateway: SocketAddr,
    pub control_server_name: String,
    pub hostname: String,
    pub installation_id: uuid::Uuid,
    pub credential_path: PathBuf,
    pub tls: Arc<ClientConfig>,
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("invalid relay configuration")]
    InvalidConfiguration,
    #[error("incompatible relay protocol: offered {offered}, supported {supported}")]
    IncompatibleProtocol { offered: u16, supported: u16 },
    #[error("relay transport unavailable")]
    Transport,
    #[error("relay control tunnel is draining and must reconnect")]
    TunnelRetired,
    #[error("relay rejected tunnel")]
    Rejected,
}

pub struct TunnelClient {
    config: TunnelConfig,
    upstream: SocketAddr,
}

impl TunnelClient {
    pub fn new(config: TunnelConfig, upstream: SocketAddr) -> Result<Self, ClientError> {
        validate_hostname(&config.hostname).map_err(|_| ClientError::InvalidConfiguration)?;
        if upstream != CEREMONY_UPSTREAM
            || config.credential_path.as_os_str().is_empty()
            || config.control_server_name.is_empty()
        {
            return Err(ClientError::InvalidConfiguration);
        }
        Ok(Self { config, upstream })
    }

    pub async fn run_until<F>(self, shutdown: F) -> Result<(), ClientError>
    where
        F: Future<Output = ()>,
    {
        let (ready, _) = watch::channel(false);
        self.run_until_ready(shutdown, ready).await
    }

    pub async fn run_until_ready<F>(
        self,
        shutdown: F,
        ready: watch::Sender<bool>,
    ) -> Result<(), ClientError>
    where
        F: Future<Output = ()>,
    {
        let _ready_guard = ReadyGuard(ready.clone());
        let credential = read_credential(&self.config.credential_path)?;
        let tcp = timeout(
            Duration::from_secs(10),
            TcpStream::connect(self.config.gateway),
        )
        .await
        .map_err(|_| ClientError::Transport)?
        .map_err(|_| ClientError::Transport)?;
        let server_name = ServerName::try_from(self.config.control_server_name.clone())
            .map_err(|_| ClientError::InvalidConfiguration)?;
        let tls = timeout(
            Duration::from_secs(10),
            TlsConnector::from(self.config.tls.clone()).connect(server_name, tcp),
        )
        .await
        .map_err(|_| ClientError::Transport)?
        .map_err(|_| ClientError::Transport)?;
        let (mut sender, connection) = timeout(Duration::from_secs(10), client::handshake(tls))
            .await
            .map_err(|_| ClientError::Transport)?
            .map_err(|_| ClientError::Transport)?;
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            TunnelTaskCompletion::Connection(connection.await.map_err(|_| ClientError::Transport))
        });
        let uri: Uri = format!("https://{}/v1/tunnel", self.config.control_server_name)
            .parse()
            .map_err(|_| ClientError::InvalidConfiguration)?;
        let request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("x-bloom-version", WIRE_VERSION.to_string())
            .header(
                "x-bloom-installation",
                self.config.installation_id.to_string(),
            )
            .header("x-bloom-hostname", &self.config.hostname)
            .header("authorization", format!("Bearer {credential}"))
            .body(())
            .map_err(|_| ClientError::InvalidConfiguration)?;
        let (response, _) = sender
            .send_request(request, true)
            .map_err(|_| ClientError::Transport)?;
        let response = timeout(Duration::from_secs(10), response)
            .await
            .map_err(|_| ClientError::Transport)?
            .map_err(|_| ClientError::Transport)?;
        if !response.status().is_success() {
            return Err(ClientError::Rejected);
        }
        ready.send_replace(true);
        let mut events = response.into_body();
        let mut decoder = ControlDecoder::default();
        let streams = Arc::new(Semaphore::new(MAX_INSTALLATION_STREAMS));
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    return Ok(());
                },
                task = tasks.join_next() => {
                    match task {
                        Some(Ok(completion)) => {
                            if let Some(error) = completion.into_fatal_error() {
                                return Err(error);
                            }
                        }
                        Some(Err(_)) | None => return Err(ClientError::Transport),
                    }
                }
                frame = timeout(Duration::from_secs(45), events.data()) => {
                    let frame = frame.map_err(|_| ClientError::Transport)?;
                    let Some(frame) = frame else { return Err(ClientError::Transport) };
                    let frame = frame.map_err(|_| ClientError::Transport)?;
                    events.flow_control().release_capacity(frame.len()).map_err(|_| ClientError::Transport)?;
                    for event in decoder.push(&frame).map_err(|_| ClientError::Transport)? {
                        if let TunnelEvent::Open { version, ticket, hostname, generation, expires_at_ms, .. } = event {
                            if version != WIRE_VERSION { return Err(ClientError::IncompatibleProtocol { offered: version, supported: WIRE_VERSION }); }
                            if hostname != self.config.hostname || expires_at_ms <= now_ms() { continue; }
                            let upstream = self.upstream;
                            let authority = self.config.hostname.clone();
                            let installation_id = self.config.installation_id;
                            let credential = credential.clone();
                            let mut sender = sender.clone();
                            let Ok(permit) = streams.clone().try_acquire_owned() else { continue; };
                            tasks.spawn(async move {
                                let _permit = permit;
                                TunnelTaskCompletion::Stream(
                                    open_stream(&mut sender, upstream, &authority, installation_id, generation, &credential, &ticket).await
                                )
                            });
                        }
                    }
                }
            }
        }
    }
}

enum TunnelTaskCompletion {
    Connection(Result<(), ClientError>),
    Stream(Result<(), ClientError>),
}

impl TunnelTaskCompletion {
    fn into_fatal_error(self) -> Option<ClientError> {
        match self {
            // The HTTP/2 driver owns the shared transport. Any completion means
            // the control tunnel can no longer admit browser streams.
            Self::Connection(Ok(())) => Some(ClientError::Transport),
            Self::Connection(Err(error)) => Some(error),
            // A GOAWAY retires this shared HTTP/2 connection. The control
            // reader can still receive OPEN events briefly, so make the
            // supervisor replace the tunnel instead of silently dropping them.
            Self::Stream(Err(ClientError::TunnelRetired)) => Some(ClientError::TunnelRetired),
            // CONNECT rejection, local upstream failure, resets, and stream
            // timeouts affect only the browser connection that owns the stream.
            Self::Stream(Ok(()) | Err(_)) => None,
        }
    }
}

struct ReadyGuard(watch::Sender<bool>);
impl Drop for ReadyGuard {
    fn drop(&mut self) {
        self.0.send_replace(false);
    }
}

fn read_credential(path: &std::path::Path) -> Result<String, ClientError> {
    let metadata = std::fs::metadata(path).map_err(|_| ClientError::InvalidConfiguration)?;
    if !metadata.is_file() || metadata.len() > 256 {
        return Err(ClientError::InvalidConfiguration);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ClientError::InvalidConfiguration);
        }
    }
    let secret = std::fs::read_to_string(path).map_err(|_| ClientError::InvalidConfiguration)?;
    let secret = secret.trim_end_matches(['\n', '\r']);
    if secret.len() < 43
        || secret.len() > 128
        || !secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(ClientError::InvalidConfiguration);
    }
    Ok(secret.into())
}

/// An external exact-host HTTPS probe after the tunnel claim. It is readiness
/// evidence for Broker reconciliation, never surface authorization by itself.
pub async fn probe_public_health(
    hostname: &str,
    test_ca_pem: Option<&[u8]>,
) -> Result<(), ClientError> {
    validate_hostname(hostname).map_err(|_| ClientError::InvalidConfiguration)?;
    let hostname = hostname.to_owned();
    let test_ca_pem = test_ca_pem.map(Vec::from);
    tokio::task::spawn_blocking(move || {
        let mut tls = ureq::tls::TlsConfig::builder().provider(ureq::tls::TlsProvider::Rustls);
        if let Some(pem) = test_ca_pem {
            let cert = ureq::tls::Certificate::from_pem(&pem)
                .map_err(|_| ClientError::InvalidConfiguration)?;
            tls = tls.root_certs(ureq::tls::RootCerts::new_with_certs(&[cert]));
        }
        let agent = ureq::config::Config::builder()
            .https_only(true)
            .max_redirects(0)
            .proxy(None)
            .timeout_global(Some(Duration::from_secs(10)))
            .tls_config(tls.build())
            .build()
            .new_agent();
        let url = format!("https://{hostname}/.well-known/bloom/relay-health");
        let response = agent.get(url).call().map_err(|_| ClientError::Transport)?;
        if response.status() != 204 {
            return Err(ClientError::Rejected);
        }
        Ok(())
    })
    .await
    .map_err(|_| ClientError::Transport)?
}

async fn open_stream(
    sender: &mut client::SendRequest<Bytes>,
    upstream: SocketAddr,
    hostname: &str,
    installation_id: uuid::Uuid,
    generation: u64,
    credential: &str,
    ticket: &str,
) -> Result<(), ClientError> {
    timeout(
        Duration::from_secs(1800),
        open_stream_inner(
            sender,
            upstream,
            hostname,
            installation_id,
            generation,
            credential,
            ticket,
        ),
    )
    .await
    .map_err(|_| ClientError::Transport)?
}

async fn open_stream_inner(
    sender: &mut client::SendRequest<Bytes>,
    upstream: SocketAddr,
    hostname: &str,
    installation_id: uuid::Uuid,
    generation: u64,
    credential: &str,
    ticket: &str,
) -> Result<(), ClientError> {
    let uri: Uri = format!("https://{hostname}")
        .parse()
        .map_err(|_| ClientError::InvalidConfiguration)?;
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .header("x-bloom-version", WIRE_VERSION.to_string())
        .header("x-bloom-installation", installation_id.to_string())
        .header("x-bloom-hostname", hostname)
        .header("x-bloom-generation", generation.to_string())
        .header("authorization", format!("Bearer {credential}"))
        .header("x-bloom-ticket", ticket)
        .body(())
        .map_err(|_| ClientError::InvalidConfiguration)?;
    let (response, mut outbound) = sender
        .send_request(request, false)
        .map_err(map_h2_stream_error)?;
    let response = timeout(Duration::from_secs(10), response)
        .await
        .map_err(|_| ClientError::Transport)?
        .map_err(map_h2_stream_error)?;
    if !response.status().is_success() {
        return Err(ClientError::Rejected);
    }
    let mut inbound = response.into_body();
    let mut local = TcpStream::connect(upstream)
        .await
        .map_err(|_| ClientError::Transport)?;
    let mut local_done = false;
    let mut remote_done = false;
    while !(local_done && remote_done) {
        let mut buffer = [0u8; 16 * 1024];
        timeout(Duration::from_secs(120), async {
            tokio::select! {
                read = local.read(&mut buffer), if !local_done => {
                    let n = read.map_err(|_| ClientError::Transport)?;
                    if n == 0 {
                        local_done = true;
                        outbound.send_data(Bytes::new(), true).map_err(|_| ClientError::Transport)?;
                    } else { send_bounded(&mut outbound, Bytes::copy_from_slice(&buffer[..n])).await?; }
                }
                frame = inbound.data(), if !remote_done => {
                    match frame {
                        Some(Ok(frame)) => {
                            local.write_all(&frame).await.map_err(|_| ClientError::Transport)?;
                            inbound.flow_control().release_capacity(frame.len()).map_err(|_| ClientError::Transport)?;
                        }
                        Some(Err(error)) => return Err(map_h2_stream_error(error)),
                        None => {
                            remote_done = true;
                            local.shutdown().await.map_err(|_| ClientError::Transport)?;
                        }
                    }
                }
            }
            Ok::<(), ClientError>(())
        }).await.map_err(|_| ClientError::Transport)??;
    }
    Ok(())
}

fn map_h2_stream_error(error: h2::Error) -> ClientError {
    if error.is_go_away() {
        ClientError::TunnelRetired
    } else {
        ClientError::Transport
    }
}

async fn send_bounded(
    stream: &mut h2::SendStream<Bytes>,
    mut bytes: Bytes,
) -> Result<(), ClientError> {
    while !bytes.is_empty() {
        stream.reserve_capacity(bytes.len().min(16 * 1024));
        while stream.capacity() == 0 {
            poll_fn(|cx| stream.poll_capacity(cx))
                .await
                .ok_or(ClientError::Transport)?
                .map_err(|_| ClientError::Transport)?;
        }
        let count = bytes.len().min(stream.capacity()).min(16 * 1024);
        stream
            .send_data(bytes.split_to(count), false)
            .map_err(|_| ClientError::Transport)?;
    }
    Ok(())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis() as u64)
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
    fn upstream_cannot_be_supplied_by_gateway_or_config() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let tls = ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let config = TunnelConfig {
            gateway: "127.0.0.1:443".parse().unwrap(),
            control_server_name: "relay-control.bloom.directory".into(),
            hostname: "abcdefghijklmnopqrstuv2345.relay.bloom.directory".into(),
            installation_id: uuid::Uuid::new_v4(),
            credential_path: PathBuf::from("/protected/test-token"),
            tls: Arc::new(tls),
        };
        assert!(TunnelClient::new(config.clone(), "127.0.0.1:18734".parse().unwrap()).is_err());
        assert!(TunnelClient::new(config, CEREMONY_UPSTREAM).is_ok());
    }

    #[test]
    fn credential_expiry_allows_only_bounded_future_clock_offset() {
        let now = 1_000_000;
        let lifetime = 86_400_000;
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

    #[test]
    fn retired_tunnel_stream_failure_restarts_shared_connection() {
        assert!(matches!(
            TunnelTaskCompletion::Stream(Err(ClientError::TunnelRetired)).into_fatal_error(),
            Some(ClientError::TunnelRetired)
        ));
        assert!(
            TunnelTaskCompletion::Stream(Err(ClientError::Rejected))
                .into_fatal_error()
                .is_none()
        );
        assert!(
            TunnelTaskCompletion::Stream(Err(ClientError::Transport))
                .into_fatal_error()
                .is_none()
        );
    }
}
