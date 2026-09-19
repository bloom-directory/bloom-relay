use anyhow::{Context, Result, anyhow, bail};
use bloom_relay_admin_client::{
    EnrollmentConfig, EnrollmentError, SecretToken, enroll, installation_status, issue_credential,
    register_acme_account, retire_installation,
};
use bloom_relay_client::{CEREMONY_UPSTREAM, DnsChallengeClient, TunnelClient, TunnelConfig};
use bloom_relay_protocol::{Allocation, AllocationState, ChallengeLease, Scope};
use ed25519_dalek::{Signer, SigningKey};
use rand::{RngCore, rngs::OsRng};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName},
};
use std::{
    env, fs,
    io::BufReader,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{oneshot, watch},
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use uuid::Uuid;

const CONTROL_SERVER_NAME: &str = "relay-control.bloom.directory";
const EXPECTED_GATEWAY: &str = "84.32.151.158:443";
const EXPECTED_INGRESS: &str = "84.32.25.82:443";
const POLL_LIMIT: Duration = Duration::from_secs(300);

struct Inputs {
    control_ca: Vec<u8>,
    receipt_key: [u8; 32],
    acme_account_uri: String,
    gateway: SocketAddr,
    ingress: SocketAddr,
}

struct TunnelRun {
    stop: oneshot::Sender<()>,
    task: JoinHandle<Result<(), bloom_relay_client::ClientError>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let inputs = Inputs::read()?;
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    // Binding precedes enrollment so an occupied Broker listener cannot consume
    // a public hostname. Dropping this listener never affects another process.
    let listener = TcpListener::bind(CEREMONY_UPSTREAM)
        .await
        .context("127.0.0.1:18735 is occupied or unavailable")?;
    let temp = secure_tempdir()?;
    let admin_key = SigningKey::generate(&mut OsRng);
    let operation_id = Uuid::new_v4();
    let receipt = enroll(
        enrollment_config(&inputs),
        admin_key.verifying_key().as_bytes(),
        &inputs.receipt_key,
        operation_id,
        signer(&admin_key),
    )
    .context("enrollment failed")?;
    let allocation = receipt.allocation;
    println!(
        "PASS enroll {} {}",
        allocation.installation_id, allocation.hostname
    );

    let result = tokio::select! {
        result = run_enrolled(&inputs, &admin_key, &allocation, &temp, listener) => result,
        result = shutdown_signal() => result.and_then(|()| Err(anyhow!("probe interrupted; retiring allocation"))),
    };
    let retirement = retire_installation(
        enrollment_config(&inputs),
        allocation.installation_id,
        Uuid::new_v4(),
        signer(&admin_key),
    );
    match retirement {
        Ok(()) => println!(
            "PASS retire {} {}",
            allocation.installation_id, allocation.hostname
        ),
        Err(ref error) => eprintln!("retirement failed: {error}"),
    }
    drop(temp);
    result?;
    retirement.context("retirement failed")?;
    Ok(())
}

async fn shutdown_signal() -> Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("cannot register probe termination handler")?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result.context("probe interrupt handler failed"),
        _ = terminate.recv() => Ok(()),
    }
}

async fn run_enrolled(
    inputs: &Inputs,
    admin_key: &SigningKey,
    allocation: &Allocation,
    temp: &TempDir,
    listener: TcpListener,
) -> Result<()> {
    let tunnel_token = SecretToken::generate();
    let _tunnel_receipt = issue_credential(
        enrollment_config(inputs),
        allocation.installation_id,
        Scope::Tunnel,
        &tunnel_token,
        Uuid::new_v4(),
        signer(admin_key),
    )
    .context("tunnel credential issue failed")?;
    let tunnel_path = write_secret(temp.path(), "tunnel.token", tunnel_token.expose())?;
    println!(
        "PASS tunnel-credential {} {}",
        allocation.installation_id, allocation.hostname
    );

    let dns_token = SecretToken::generate();
    let dns_receipt = issue_credential(
        enrollment_config(inputs),
        allocation.installation_id,
        Scope::DnsChallenge,
        &dns_token,
        Uuid::new_v4(),
        signer(admin_key),
    )
    .context("DNS credential issue failed")?;
    let dns_path = write_secret(temp.path(), "dns.token", dns_token.expose())?;
    println!(
        "PASS dns-credential {} {}",
        allocation.installation_id, allocation.hostname
    );

    register_acme_account(
        enrollment_config(inputs),
        allocation.installation_id,
        inputs.acme_account_uri.clone(),
        Uuid::new_v4(),
        signer(admin_key),
    )
    .context("ACME account registration failed")?;
    println!(
        "PASS acme-account {} {}",
        allocation.installation_id, allocation.hostname
    );
    await_dns_ready(inputs, admin_key, allocation).await?;
    println!(
        "PASS dns-ready {} {}",
        allocation.installation_id, allocation.hostname
    );

    let dns = DnsChallengeClient::new(
        inputs.control_ca.clone(),
        allocation.installation_id,
        dns_receipt.generation,
        dns_path,
    )
    .context("DNS client setup failed")?;
    let lease_id = Uuid::new_v4();
    let lease = ChallengeLease {
        operation_id: lease_id,
        txt_value: random_dns_value(),
        expires_at_ms: now_ms().saturating_add(300_000),
    };
    let dns_result = async {
        dns.create(lease).await.context("DNS lease create failed")?;
        await_challenge_ready(&dns, lease_id, allocation).await?;
        println!(
            "PASS dns-lease-ready {} {}",
            allocation.installation_id, allocation.hostname
        );

        let synthetic = rcgen::generate_simple_self_signed(vec![allocation.hostname.clone()])
            .context("synthetic certificate generation failed")?;
        let cert_der = synthetic.cert.der().clone();
        let server_tls = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert_der.clone()],
                PrivatePkcs8KeyDer::from(synthetic.signing_key.serialize_der()).into(),
            )
            .context("synthetic TLS server setup failed")?;
        let server = spawn_synthetic_server(listener, Arc::new(server_tls));
        let tunnel_tls = client_tls_from_ca(&inputs.control_ca, true)?;
        let tunnel_config = TunnelConfig {
            gateway: inputs.gateway,
            control_server_name: CONTROL_SERVER_NAME.into(),
            hostname: allocation.hostname.clone(),
            installation_id: allocation.installation_id,
            credential_path: tunnel_path,
            tls: tunnel_tls,
        };
        let browser_tls = client_tls_from_cert(cert_der)?;

        let first = start_tunnel(tunnel_config.clone()).await?;
        probe_concurrent(inputs.ingress, &allocation.hostname, browser_tls.clone()).await?;
        println!(
            "PASS concurrent-streams {} {}",
            allocation.installation_id, allocation.hostname
        );
        stop_tunnel(first).await?;

        let second = start_tunnel(tunnel_config).await?;
        probe_once(inputs.ingress, &allocation.hostname, browser_tls).await?;
        println!(
            "PASS tunnel-reconnect {} {}",
            allocation.installation_id, allocation.hostname
        );
        stop_tunnel(second).await?;
        server.abort();
        Ok::<(), anyhow::Error>(())
    }
    .await;
    let cleanup = dns
        .delete(lease_id)
        .await
        .context("DNS lease cleanup failed");
    if cleanup.is_ok() {
        println!(
            "PASS dns-lease-delete {} {}",
            allocation.installation_id, allocation.hostname
        );
    }
    dns_result?;
    cleanup
}

fn signer(key: &SigningKey) -> impl Fn(&[u8]) -> Result<[u8; 64], EnrollmentError> + '_ {
    move |message| Ok(key.sign(message).to_bytes())
}

impl Inputs {
    fn read() -> Result<Self> {
        if env::var("BLOOM_RELAY_DEPLOYED_SMOKE").as_deref() != Ok("1") {
            bail!(
                "set BLOOM_RELAY_DEPLOYED_SMOKE=1 for this destructive disposable-infrastructure probe"
            );
        }
        let gateway_text = required("BLOOM_RELAY_SMOKE_GATEWAY_ADDR")?;
        let ingress_text = required("BLOOM_RELAY_SMOKE_INGRESS_ADDR")?;
        if gateway_text != EXPECTED_GATEWAY || ingress_text != EXPECTED_INGRESS {
            bail!("gateway or ingress does not match the fixed deployed topology");
        }
        let control_ca = fs::read(required("BLOOM_RELAY_SMOKE_CONTROL_CA_FILE")?)
            .context("control CA read failed")?;
        if control_ca.is_empty() || control_ca.len() > 64 * 1024 {
            bail!("invalid control CA file");
        }
        let receipt_hex = public_value(
            "BLOOM_RELAY_SMOKE_RECEIPT_PUBLIC_KEY_HEX",
            "BLOOM_RELAY_SMOKE_RECEIPT_PUBLIC_KEY_FILE",
        )?;
        if receipt_hex.len() != 64
            || !receipt_hex
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            bail!("receipt public key must be 64 lowercase hex characters");
        }
        let receipt: Vec<u8> = hex::decode(receipt_hex).context("invalid receipt public key")?;
        let receipt_key: [u8; 32] = receipt
            .try_into()
            .map_err(|_| anyhow!("invalid receipt public key"))?;
        let acme_account_uri = public_value(
            "BLOOM_RELAY_SMOKE_ACME_ACCOUNT_URI",
            "BLOOM_RELAY_SMOKE_ACME_ACCOUNT_URI_FILE",
        )?;
        let suffix = acme_account_uri
            .strip_prefix("https://acme-v02.api.letsencrypt.org/acme/acct/")
            .ok_or_else(|| {
                anyhow!("ACME account URI must be a production Let's Encrypt account URI")
            })?;
        if suffix.is_empty() || !suffix.bytes().all(|b| b.is_ascii_digit()) {
            bail!("invalid ACME account URI");
        }
        Ok(Self {
            control_ca,
            receipt_key,
            acme_account_uri,
            gateway: gateway_text.parse().context("invalid gateway address")?,
            ingress: ingress_text.parse().context("invalid ingress address")?,
        })
    }
}

fn required(name: &str) -> Result<String> {
    let value = env::var(name).with_context(|| format!("missing {name}"))?;
    if value.is_empty() || value.trim() != value || value.contains(['\r', '\n']) {
        bail!("invalid {name}");
    }
    Ok(value)
}

fn public_value(direct_name: &str, file_name: &str) -> Result<String> {
    match (env::var(direct_name).ok(), env::var(file_name).ok()) {
        (Some(_), Some(_)) => bail!("set exactly one of {direct_name} and {file_name}"),
        (Some(value), None) => validate_public_value(direct_name, value),
        (None, Some(path)) => {
            let path = validate_public_value(file_name, path)?;
            let metadata =
                fs::metadata(&path).with_context(|| format!("cannot inspect {file_name}"))?;
            if !metadata.is_file() || metadata.len() > 4096 {
                bail!("invalid {file_name}");
            }
            let value =
                fs::read_to_string(path).with_context(|| format!("cannot read {file_name}"))?;
            validate_public_value(file_name, value.trim_end_matches(['\r', '\n']).to_owned())
        }
        (None, None) => bail!("set exactly one of {direct_name} and {file_name}"),
    }
}

fn validate_public_value(name: &str, value: String) -> Result<String> {
    if value.is_empty() || value.trim() != value || value.contains(['\r', '\n']) {
        bail!("invalid {name}");
    }
    Ok(value)
}

fn enrollment_config(inputs: &Inputs) -> EnrollmentConfig {
    EnrollmentConfig {
        control_ca_pem: inputs.control_ca.clone(),
    }
}

async fn await_dns_ready(inputs: &Inputs, key: &SigningKey, allocation: &Allocation) -> Result<()> {
    let deadline = tokio::time::Instant::now() + POLL_LIMIT;
    let mut attempts = 0u32;
    loop {
        let status = installation_status(
            enrollment_config(inputs),
            allocation.installation_id,
            Uuid::new_v4(),
            signer(key),
        )
        .context("installation status failed")?;
        match status.state {
            AllocationState::DnsReady => return Ok(()),
            AllocationState::PendingDns if tokio::time::Instant::now() < deadline => {
                if attempts.is_multiple_of(15) {
                    println!(
                        "WAIT dns-ready {} {}",
                        allocation.installation_id, allocation.hostname
                    );
                }
                attempts += 1;
                sleep(Duration::from_secs(2)).await
            }
            AllocationState::PendingDns => bail!("DNS readiness timed out"),
            AllocationState::Retired => bail!("installation retired before DNS readiness"),
        }
    }
}

async fn await_challenge_ready(
    client: &DnsChallengeClient,
    lease_id: Uuid,
    allocation: &Allocation,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + POLL_LIMIT;
    let mut attempts = 0u32;
    while tokio::time::Instant::now() < deadline {
        if client
            .ready(lease_id)
            .await
            .context("DNS lease status failed")?
        {
            return Ok(());
        }
        if attempts.is_multiple_of(15) {
            println!(
                "WAIT dns-lease {} {}",
                allocation.installation_id, allocation.hostname
            );
        }
        attempts += 1;
        sleep(Duration::from_secs(2)).await;
    }
    bail!("DNS lease readiness timed out")
}

async fn start_tunnel(config: TunnelConfig) -> Result<TunnelRun> {
    let (ready, mut watched) = watch::channel(false);
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(
        TunnelClient::new(config, CEREMONY_UPSTREAM)
            .context("tunnel setup failed")?
            .run_until_ready(
                async move {
                    let _ = stopped.await;
                },
                ready,
            ),
    );
    timeout(Duration::from_secs(20), async {
        while !*watched.borrow() {
            watched
                .changed()
                .await
                .map_err(|_| anyhow!("tunnel exited before ready"))?;
        }
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("tunnel ready timeout")??;
    Ok(TunnelRun { stop, task })
}

async fn stop_tunnel(run: TunnelRun) -> Result<()> {
    let _ = run.stop.send(());
    timeout(Duration::from_secs(10), run.task)
        .await
        .context("tunnel shutdown timeout")?
        .context("tunnel task failed")?
        .context("tunnel shutdown failed")
}

fn spawn_synthetic_server(listener: TcpListener, tls: Arc<ServerConfig>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(tls);
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut ping = [0u8; 4];
                if stream.read_exact(&mut ping).await.is_ok() && &ping == b"ping" {
                    let _ = stream.write_all(b"pong").await;
                    let _ = stream.shutdown().await;
                }
            });
        }
    })
}

async fn probe_concurrent(
    ingress: SocketAddr,
    hostname: &str,
    tls: Arc<ClientConfig>,
) -> Result<()> {
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let hostname = hostname.to_owned();
        let tls = tls.clone();
        tasks.push(tokio::spawn(async move {
            probe_once(ingress, &hostname, tls).await
        }));
    }
    for task in tasks {
        task.await.context("probe task failed")??;
    }
    Ok(())
}

async fn probe_once(ingress: SocketAddr, hostname: &str, tls: Arc<ClientConfig>) -> Result<()> {
    let tcp = timeout(Duration::from_secs(10), TcpStream::connect(ingress))
        .await
        .context("ingress connect timeout")?
        .context("ingress connect failed")?;
    let server_name =
        ServerName::try_from(hostname.to_owned()).context("invalid relay hostname")?;
    let mut stream = timeout(
        Duration::from_secs(10),
        TlsConnector::from(tls).connect(server_name, tcp),
    )
    .await
    .context("ingress TLS timeout")?
    .context("ingress TLS failed")?;
    stream
        .write_all(b"ping")
        .await
        .context("probe write failed")?;
    let mut pong = [0u8; 4];
    timeout(Duration::from_secs(10), stream.read_exact(&mut pong))
        .await
        .context("probe reply timeout")?
        .context("probe reply failed")?;
    if &pong != b"pong" {
        bail!("invalid probe reply");
    }
    Ok(())
}

fn client_tls_from_ca(pem: &[u8], h2: bool) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    let mut reader = BufReader::new(pem);
    let mut count = 0;
    for cert in rustls_pemfile::certs(&mut reader) {
        roots
            .add(cert.context("invalid control CA PEM")?)
            .context("invalid control CA certificate")?;
        count += 1;
    }
    if count == 0 {
        bail!("control CA PEM contains no certificates");
    }
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    if h2 {
        config.alpn_protocols = vec![b"h2".to_vec()];
    }
    Ok(Arc::new(config))
}

fn client_tls_from_cert(cert: CertificateDer<'static>) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots.add(cert).context("synthetic trust setup failed")?;
    Ok(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

fn secure_tempdir() -> Result<TempDir> {
    let temp = tempfile::Builder::new()
        .prefix("bloom-relay-smoke-")
        .tempdir()
        .context("temporary directory creation failed")?;
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
        .context("temporary directory permission failed")?;
    Ok(temp)
}

fn write_secret(directory: &Path, name: &str, secret: &str) -> Result<PathBuf> {
    let path = directory.join(name);
    fs::write(&path, secret.as_bytes()).context("credential write failed")?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .context("credential permission failed")?;
    Ok(path)
}

fn random_dns_value() -> String {
    let mut value = [0u8; 32];
    OsRng.fill_bytes(&mut value);
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(value)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| value.as_millis() as u64)
}
