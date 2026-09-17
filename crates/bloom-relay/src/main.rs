use bloom_relay_protocol::{
    BUFFER_BUDGET, BUFFER_PER_DIRECTION, MAX_CLIENT_HELLO, MAX_GATEWAY_STREAMS,
    MAX_INSTALLATION_STREAMS, TunnelEvent, WIRE_VERSION, validate_hostname,
};
use bloom_relay_store::{RestoreWitness, Store};
use bytes::Bytes;
use futures_util::future::poll_fn;
use h2::{RecvStream, SendStream, server};
use http::{Method, Response, StatusCode};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::Acceptor,
};
use std::{
    collections::HashMap,
    env,
    io::Cursor,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, OwnedSemaphorePermit, Semaphore, oneshot},
    task::JoinSet,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

type Error = Box<dyn std::error::Error + Send + Sync>;
struct Tunnel {
    id: Uuid,
    generation: u64,
    control: Mutex<SendStream<Bytes>>,
    streams: Arc<Semaphore>,
}
struct Ticket {
    host: String,
    id: Uuid,
    generation: u64,
    deadline: Instant,
    claim: oneshot::Sender<(RecvStream, SendStream<Bytes>)>,
}
struct Gateway {
    store: Store,
    gateway_id: String,
    tunnels: Mutex<HashMap<String, Arc<Tunnel>>>,
    tickets: Mutex<HashMap<String, Ticket>>,
    streams: Arc<Semaphore>,
}

struct IngressQuota {
    state: StdMutex<(Instant, u32, HashMap<IpAddr, u32>)>,
}

impl IngressQuota {
    fn new() -> Self {
        Self {
            state: StdMutex::new((Instant::now(), 0, HashMap::new())),
        }
    }
    fn allow(&self, source: IpAddr) -> bool {
        self.allow_at(source, Instant::now())
    }
    fn allow_at(&self, source: IpAddr, now: Instant) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if now.duration_since(state.0) >= Duration::from_secs(60) {
            state.0 = now;
            state.1 = 0;
            state.2.clear();
        }
        if state.1 >= 5_000 || state.2.get(&source).copied().unwrap_or(0) >= 120 {
            return false;
        }
        state.1 += 1;
        *state.2.entry(source).or_default() += 1;
        true
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| "TLS provider conflict")?;
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let health = bloom_relay_observe::install("gateway")?;
    let gateway_id = env::var("BLOOM_RELAY_GATEWAY_ID")?;
    if gateway_id.is_empty() || gateway_id.len() > 64 {
        return Err("invalid gateway ID".into());
    }
    let witness_path = env::var("BLOOM_RELAY_RESTORE_WITNESS_PATH")?;
    let gateway = Arc::new(Gateway {
        store: Store::connect_runtime_with_witness(
            &env::var("BLOOM_RELAY_DATABASE_URL")?,
            witness_path.clone().into(),
        )
        .await?,
        gateway_id,
        tunnels: Mutex::new(HashMap::new()),
        tickets: Mutex::new(HashMap::new()),
        streams: Arc::new(Semaphore::new(
            MAX_GATEWAY_STREAMS.min(BUFFER_BUDGET / (2 * BUFFER_PER_DIRECTION)),
        )),
    });
    let witness = RestoreWitness::new(witness_path.into())?;
    witness.verify_and_advance(&gateway.store).await?;
    let witness_store = gateway.store.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if let Err(error) = witness.verify_and_advance(&witness_store).await {
                tracing::error!(%error, "restore witness failed; gateway stopping");
                std::process::exit(78);
            }
        }
    });
    let tls = TlsAcceptor::from(Arc::new(load_tls(
        &env::var("BLOOM_RELAY_CONTROL_CERT_PATH")?,
        &env::var("BLOOM_RELAY_CONTROL_KEY_PATH")?,
    )?));
    let control =
        TcpListener::bind(env::var("BLOOM_RELAY_TUNNEL_BIND")?.parse::<SocketAddr>()?).await?;
    let ingress =
        TcpListener::bind(env::var("BLOOM_RELAY_INGRESS_BIND")?.parse::<SocketAddr>()?).await?;
    let control_slots = Arc::new(Semaphore::new(512));
    let ingress_slots = Arc::new(Semaphore::new(
        MAX_GATEWAY_STREAMS.min(BUFFER_BUDGET / (2 * BUFFER_PER_DIRECTION)),
    ));
    let ingress_quota = IngressQuota::new();
    let mut connections = JoinSet::new();
    let mut telemetry = tokio::time::interval(Duration::from_secs(15));
    health.set_ready(true);
    tracing::info!("gateway ready");
    loop {
        tokio::select! {
            _ = telemetry.tick() => {
                bloom_relay_observe::gauge("bloom_relay_live_tunnels", gateway.tunnels.lock().await.len() as f64);
                bloom_relay_observe::gauge("bloom_relay_live_streams", (MAX_GATEWAY_STREAMS.min(BUFFER_BUDGET / (2 * BUFFER_PER_DIRECTION)) - gateway.streams.available_permits()) as f64);
            }
            accepted = control.accept() => {
                let (tcp, _) = accepted?;
                let Some((tcp, permit)) = admit_connection(tcp, &control_slots) else { continue; };
                let gateway = gateway.clone();
                let tls = tls.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = control_connection(gateway, tls, tcp).await {
                        bloom_relay_observe::count("bloom_relay_control_connection_failed_total");
                        tracing::warn!(%error, "control connection closed");
                    }
                });
            }
            accepted = ingress.accept() => {
                let (tcp, peer) = accepted?;
                if !ingress_quota.allow(peer.ip()) {
                    bloom_relay_observe::count("bloom_relay_ingress_quota_rejected_total");
                    continue;
                }
                let Some((tcp, permit)) = admit_connection(tcp, &ingress_slots) else {
                    bloom_relay_observe::count("bloom_relay_ingress_capacity_rejected_total");
                    continue;
                };
                bloom_relay_observe::count("bloom_relay_ingress_accepted_total");
                let gateway = gateway.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = browser_connection(gateway, tcp).await {
                        bloom_relay_observe::count("bloom_relay_browser_connection_failed_total");
                        tracing::debug!(%error, "browser connection closed");
                    }
                });
            }
            _ = shutdown_signal() => break,
        }
    }
    drop(control);
    drop(ingress);
    health.set_ready(false);
    if timeout(Duration::from_secs(30), async {
        while connections.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler");
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn admit_connection(
    tcp: TcpStream,
    slots: &Arc<Semaphore>,
) -> Option<(TcpStream, OwnedSemaphorePermit)> {
    slots
        .clone()
        .try_acquire_owned()
        .ok()
        .map(|permit| (tcp, permit))
}

fn load_tls(cert_path: &str, key_path: &str) -> Result<ServerConfig, Error> {
    let certs = CertificateDer::pem_file_iter(cert_path)?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(key_path)?;
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(config)
}

async fn control_connection(
    gateway: Arc<Gateway>,
    tls: TlsAcceptor,
    tcp: TcpStream,
) -> Result<(), Error> {
    let tls = timeout(Duration::from_secs(10), tls.accept(tcp)).await??;
    if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
        return Err("HTTP/2 required".into());
    }
    let mut connection = server::handshake(tls).await?;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(15));
    let mut active: Option<(String, Arc<Tunnel>)> = None;
    loop {
        let request = tokio::select! {
            request = connection.accept() => request,
            _ = heartbeat.tick() => {
                if let Some((host, tunnel)) = &active {
                    if !gateway.store.renew_tunnel(tunnel.id, &gateway.gateway_id, tunnel.generation).await? {
                        bloom_relay_observe::count("bloom_relay_tunnel_lease_fenced_total");
                        break;
                    }
                    let event = TunnelEvent::Heartbeat { version: WIRE_VERSION, generation: tunnel.generation };
                    send_data(&mut *tunnel.control.lock().await, Bytes::from(format!("{}\n", serde_json::to_string(&event)?))).await?;
                    if gateway.tunnels.lock().await.get(host).is_none_or(|current| current.generation != tunnel.generation) { break; }
                }
                continue;
            }
        };
        let Some(request) = request else {
            break;
        };
        let (request, mut response) = request?;
        if request.method() == Method::POST && request.uri().path() == "/v1/tunnel" {
            let version = request
                .headers()
                .get("x-bloom-version")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u16>().ok());
            let id = request
                .headers()
                .get("x-bloom-installation")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| Uuid::parse_str(v).ok());
            let host = request
                .headers()
                .get("x-bloom-hostname")
                .and_then(|v| v.to_str().ok());
            let token = request
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "));
            let valid = if let (Some(id), Some(host), Some(token)) = (id, host, token) {
                version == Some(WIRE_VERSION)
                    && validate_hostname(host).is_ok()
                    && gateway.store.hostname(id).await?.as_deref() == Some(host)
                    && gateway
                        .store
                        .authenticate_bearer(id, "tunnel", token)
                        .await?
                        .is_some()
            } else {
                false
            };
            if !valid {
                response.send_response(
                    Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .body(())?,
                    true,
                )?;
                continue;
            }
            let id = id.ok_or("missing installation")?;
            let host = host.ok_or("missing hostname")?;
            let generation = gateway
                .store
                .claim_tunnel(id, &gateway.gateway_id, 45)
                .await?;
            let control = response
                .send_response(Response::builder().status(StatusCode::OK).body(())?, false)?;
            let tunnel = Arc::new(Tunnel {
                id,
                generation,
                control: Mutex::new(control),
                streams: Arc::new(Semaphore::new(MAX_INSTALLATION_STREAMS)),
            });
            if gateway
                .tunnels
                .lock()
                .await
                .insert(host.to_owned(), tunnel.clone())
                .is_some()
            {
                bloom_relay_observe::count("bloom_relay_tunnel_reconnect_total");
            }
            bloom_relay_observe::count("bloom_relay_tunnel_claim_total");
            active = Some((host.to_owned(), tunnel));
        } else if request.method() == Method::CONNECT {
            let claim = if let Some(ticket) = request
                .headers()
                .get("x-bloom-ticket")
                .and_then(|v| v.to_str().ok())
            {
                gateway.tickets.lock().await.remove(ticket)
            } else {
                None
            };
            if let Some(ticket) = claim {
                let same_tunnel = active.as_ref().is_some_and(|(host, tunnel)| {
                    ticket_owner_matches(
                        host,
                        tunnel.id,
                        tunnel.generation,
                        &ticket.host,
                        ticket.id,
                        ticket.generation,
                    )
                });
                let valid = ticket.deadline > Instant::now()
                    && same_tunnel
                    && request
                        .uri()
                        .authority()
                        .is_some_and(|authority| authority.as_str() == ticket.host)
                    && gateway
                        .store
                        .tunnel_is_current(ticket.id, &gateway.gateway_id, ticket.generation)
                        .await?;
                if valid {
                    let outbound = response.send_response(
                        Response::builder().status(StatusCode::OK).body(())?,
                        false,
                    )?;
                    let _ = ticket.claim.send((request.into_body(), outbound));
                    continue;
                }
            }
            response.send_response(Response::builder().status(StatusCode::GONE).body(())?, true)?;
        } else {
            response.send_response(
                Response::builder().status(StatusCode::NOT_FOUND).body(())?,
                true,
            )?;
        }
    }
    if let Some((host, tunnel)) = active {
        let mut tunnels = gateway.tunnels.lock().await;
        if tunnels
            .get(&host)
            .is_some_and(|current| current.generation == tunnel.generation)
        {
            tunnels.remove(&host);
        }
    }
    Ok(())
}

async fn browser_connection(gateway: Arc<Gateway>, mut browser: TcpStream) -> Result<(), Error> {
    let _global = gateway.streams.clone().try_acquire_owned()?;
    let (host, prefix) = read_sni(&mut browser).await?;
    let tunnel = gateway
        .tunnels
        .lock()
        .await
        .get(&host)
        .cloned()
        .ok_or("no tunnel")?;
    let _installation = tunnel.streams.clone().try_acquire_owned()?;
    if !gateway
        .store
        .tunnel_is_current(tunnel.id, &gateway.gateway_id, tunnel.generation)
        .await?
    {
        return Err("stale tunnel".into());
    }
    let ticket = Uuid::new_v4().to_string();
    let (claim, receiver) = oneshot::channel();
    gateway.tickets.lock().await.insert(
        ticket.clone(),
        Ticket {
            host: host.clone(),
            id: tunnel.id,
            generation: tunnel.generation,
            deadline: Instant::now() + Duration::from_secs(10),
            claim,
        },
    );
    let event = TunnelEvent::Open {
        version: WIRE_VERSION,
        ticket: ticket.clone(),
        connection_id: Uuid::new_v4(),
        hostname: host,
        generation: tunnel.generation,
        expires_at_ms: now_ms() + 10_000,
    };
    let message = format!("{}\n", serde_json::to_string(&event)?);
    timeout(
        Duration::from_secs(10),
        send_data(&mut *tunnel.control.lock().await, Bytes::from(message)),
    )
    .await??;
    let result = timeout(Duration::from_secs(10), receiver).await;
    gateway.tickets.lock().await.remove(&ticket);
    let (incoming, outgoing) = result??;
    timeout(
        Duration::from_secs(1800),
        bridge(browser, prefix, incoming, outgoing),
    )
    .await??;
    Ok(())
}

async fn read_sni(browser: &mut TcpStream) -> Result<(String, Vec<u8>), Error> {
    timeout(Duration::from_secs(5), async {
        let mut parser = Acceptor::default();
        let mut prefix = Vec::with_capacity(4096);
        loop {
            let mut chunk = [0u8; 4096];
            let count = browser.read(&mut chunk).await?;
            if count == 0 || prefix.len() + count > MAX_CLIENT_HELLO {
                return Err("ClientHello incomplete or too large".into());
            }
            prefix.extend_from_slice(&chunk[..count]);
            parser.read_tls(&mut Cursor::new(&chunk[..count]))?;
            if let Some(hello) = parser.accept().map_err(|_| "malformed ClientHello")? {
                let host = hello
                    .client_hello()
                    .server_name()
                    .ok_or("missing SNI")?
                    .to_owned();
                validate_hostname(&host)?;
                return Ok((host, prefix));
            }
        }
    })
    .await?
}

async fn send_data(stream: &mut SendStream<Bytes>, mut bytes: Bytes) -> Result<(), Error> {
    while !bytes.is_empty() {
        stream.reserve_capacity(bytes.len().min(16_384));
        while stream.capacity() == 0 {
            poll_fn(|cx| stream.poll_capacity(cx))
                .await
                .ok_or("h2 stream closed")??;
        }
        let count = stream.capacity().min(bytes.len()).min(16_384);
        stream.send_data(bytes.split_to(count), false)?;
    }
    Ok(())
}

async fn bridge(
    mut browser: TcpStream,
    prefix: Vec<u8>,
    mut inbound: RecvStream,
    mut outbound: SendStream<Bytes>,
) -> Result<(), Error> {
    bloom_relay_observe::add(
        "bloom_relay_browser_to_broker_bytes_total",
        prefix.len() as u64,
    );
    send_data(&mut outbound, Bytes::from(prefix)).await?;
    let mut browser_done = false;
    let mut tunnel_done = false;
    while !(browser_done && tunnel_done) {
        timeout(Duration::from_secs(120), async {
            let mut buffer = [0u8; 16_384];
            tokio::select! {
                read = browser.read(&mut buffer), if !browser_done => {
                    let count = read?;
                    if count == 0 { browser_done = true; outbound.send_data(Bytes::new(), true)?; }
                    else {
                        bloom_relay_observe::add("bloom_relay_browser_to_broker_bytes_total", count as u64);
                        send_data(&mut outbound, Bytes::copy_from_slice(&buffer[..count])).await?;
                    }
                }
                frame = inbound.data(), if !tunnel_done => {
                    match frame {
                        Some(Ok(bytes)) => {
                            bloom_relay_observe::add("bloom_relay_broker_to_browser_bytes_total", bytes.len() as u64);
                            browser.write_all(&bytes).await?;
                            inbound.flow_control().release_capacity(bytes.len())?;
                        }
                        Some(Err(error)) => return Err(error.into()),
                        None => { tunnel_done = true; browser.shutdown().await?; }
                    }
                }
            }
            Ok::<(), Error>(())
        }).await??;
    }
    Ok(())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn ticket_owner_matches(
    active_host: &str,
    active_id: Uuid,
    active_generation: u64,
    ticket_host: &str,
    ticket_id: Uuid,
    ticket_generation: u64,
) -> bool {
    active_host == ticket_host && active_id == ticket_id && active_generation == ticket_generation
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_relay_client::{CEREMONY_UPSTREAM, TunnelClient, TunnelConfig};
    use proptest::prelude::*;
    use rustls::{ClientConfig, ClientConnection, RootCertStore, pki_types::ServerName};
    use sha2::{Digest, Sha256};
    use tokio::sync::watch;

    #[tokio::test]
    async fn fragmented_client_hello_extracts_exact_sni_and_preserves_bytes() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let host = "abcdefghijklmnopqrstuv2345.relay.bloom.directory";
        let config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth(),
        );
        let mut client =
            ClientConnection::new(config, ServerName::try_from(host.to_owned()).unwrap()).unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let bytes = hello.clone();
        let writer = tokio::spawn(async move {
            let mut stream = TcpStream::connect(address).await.unwrap();
            for chunk in bytes.chunks(7) {
                stream.write_all(chunk).await.unwrap();
            }
        });
        let (mut server, _) = listener.accept().await.unwrap();
        let (observed, prefix) = read_sni(&mut server).await.unwrap();
        writer.await.unwrap();
        assert_eq!(observed, host);
        assert_eq!(prefix, hello);
    }

    #[tokio::test]
    async fn malformed_client_hello_fails_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let writer = tokio::spawn(async move {
            let mut stream = TcpStream::connect(address).await.unwrap();
            stream.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        });
        let (mut server, _) = listener.accept().await.unwrap();
        assert!(read_sni(&mut server).await.is_err());
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn pre_auth_admission_sheds_excess_socket_before_tls() {
        let slots = Arc::new(Semaphore::new(1));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let first_client = TcpStream::connect(address).await.unwrap();
        let (first_server, _) = listener.accept().await.unwrap();
        let (first_server, first_permit) = admit_connection(first_server, &slots).unwrap();
        let mut second_client = TcpStream::connect(address).await.unwrap();
        let (second_server, _) = listener.accept().await.unwrap();
        assert!(admit_connection(second_server, &slots).is_none());
        let mut one = [0u8; 1];
        assert_eq!(
            timeout(Duration::from_secs(1), second_client.read(&mut one))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        drop(first_server);
        drop(first_permit);
        drop(first_client);
        assert_eq!(slots.available_permits(), 1);
    }

    #[test]
    fn ingress_quota_bounds_source_and_global_handshakes() {
        let quota = IngressQuota::new();
        let start = Instant::now();
        let first = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 1));
        for _ in 0..120 {
            assert!(quota.allow_at(first, start));
        }
        assert!(!quota.allow_at(first, start));
        for index in 2..=41 {
            let source = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, index));
            for _ in 0..120 {
                assert!(quota.allow_at(source, start));
            }
        }
        let last = IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 1));
        for _ in 0..80 {
            assert!(quota.allow_at(last, start));
        }
        assert!(!quota.allow_at(last, start));
        assert!(quota.allow_at(first, start + Duration::from_secs(60)));
    }

    proptest! {
        #[test]
        fn ingress_quota_never_exceeds_source_or_global_budget(
            sources in proptest::collection::vec(0u16..200, 0..7_000),
        ) {
            let quota = IngressQuota::new();
            let now = Instant::now();
            let mut accepted = [0u32; 200];
            let mut total = 0u32;
            for source in sources {
                let ip = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, (source / 256) as u8, source as u8));
                let allowed = quota.allow_at(ip, now);
                if allowed {
                    accepted[source as usize] += 1;
                    total += 1;
                    prop_assert!(accepted[source as usize] <= 120);
                    prop_assert!(total <= 5_000);
                } else {
                    prop_assert!(accepted[source as usize] == 120 || total == 5_000);
                }
            }
            let next_window = now + Duration::from_secs(60);
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 1));
            prop_assert!(quota.allow_at(ip, next_window));
        }

        #[test]
        fn ticket_owner_requires_exact_host_installation_and_generation(
            host_label in "[a-z0-9]{26}",
            id_bytes in any::<[u8; 16]>(),
            generation in any::<u64>(),
        ) {
            let host = format!("{host_label}.relay.bloom.directory");
            let id = Uuid::from_bytes(id_bytes);
            prop_assert!(ticket_owner_matches(&host, id, generation, &host, id, generation));
            let other_host = format!("x.{host}");
            prop_assert!(!ticket_owner_matches(&host, id, generation, &other_host, id, generation));
            let mut other_id_bytes = id_bytes;
            other_id_bytes[0] ^= 1;
            prop_assert!(!ticket_owner_matches(&host, id, generation, &host, Uuid::from_bytes(other_id_bytes), generation));
            prop_assert!(!ticket_owner_matches(&host, id, generation, &host, id, generation.wrapping_add(1)));
        }
    }

    #[tokio::test]
    async fn opaque_tls_reaches_fixed_upstream_and_reconnect_fences_old_generation() {
        let Ok(url) = std::env::var("BLOOM_RELAY_TEST_DATABASE_URL") else {
            return;
        };
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let store = Store::connect(&url).await.unwrap();
        let allocation = store
            .allocate(Uuid::new_v4(), [7u8; 32], "fixture")
            .await
            .unwrap();
        let id = allocation.installation_id;
        store
            .register_acme_account(id, "https://acme-v02.api.letsencrypt.org/acme/acct/123")
            .await
            .unwrap();
        store.mark_dns_ready(id).await.unwrap();
        let token = "x".repeat(43);
        let hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        store
            .issue_bearer(id, Uuid::new_v4(), "tunnel", hash, 3600)
            .await
            .unwrap();
        let certificate = rcgen::generate_simple_self_signed(vec![
            "relay-control.bloom.directory".into(),
            allocation.hostname.clone(),
        ])
        .unwrap();
        let fixture = std::env::temp_dir().join(format!("bloom-relay-tls-{}", Uuid::new_v4()));
        std::fs::create_dir(&fixture).unwrap();
        let cert_path = fixture.join("cert.pem").to_string_lossy().to_string();
        let key_path = fixture.join("key.pem").to_string_lossy().to_string();
        std::fs::write(&cert_path, certificate.cert.pem()).unwrap();
        std::fs::write(&key_path, certificate.signing_key.serialize_pem()).unwrap();
        let mut roots = RootCertStore::empty();
        let cert = CertificateDer::pem_file_iter(&cert_path)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        roots.add(cert).unwrap();
        let mut client_tls = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"h2".to_vec()];
        let client_tls = Arc::new(client_tls);
        let gateway = Arc::new(Gateway {
            store: store.clone(),
            gateway_id: "fixture".into(),
            tunnels: Mutex::new(HashMap::new()),
            tickets: Mutex::new(HashMap::new()),
            streams: Arc::new(Semaphore::new(
                MAX_GATEWAY_STREAMS.min(BUFFER_BUDGET / (2 * BUFFER_PER_DIRECTION)),
            )),
        });
        let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ingress = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_address = control.local_addr().unwrap();
        let ingress_address = ingress.local_addr().unwrap();
        let server_tls = TlsAcceptor::from(Arc::new(load_tls(&cert_path, &key_path).unwrap()));
        let control_gateway = gateway.clone();
        let control_task = tokio::spawn(async move {
            loop {
                let (tcp, _) = control.accept().await.unwrap();
                let gateway = control_gateway.clone();
                let tls = server_tls.clone();
                tokio::spawn(async move {
                    control_connection(gateway, tls, tcp).await.unwrap();
                });
            }
        });
        let ingress_gateway = gateway.clone();
        let ingress_task = tokio::spawn(async move {
            loop {
                let (tcp, _) = ingress.accept().await.unwrap();
                let gateway = ingress_gateway.clone();
                tokio::spawn(async move {
                    browser_connection(gateway, tcp).await.unwrap();
                });
            }
        });
        let upstream = TcpListener::bind(CEREMONY_UPSTREAM).await.unwrap();
        let upstream_tls = TlsAcceptor::from(Arc::new(load_tls(&cert_path, &key_path).unwrap()));
        let upstream_task = tokio::spawn(async move {
            let (tcp, _) = upstream.accept().await.unwrap();
            let mut tls = upstream_tls.accept(tcp).await.unwrap();
            let mut payload = [0u8; 4];
            tls.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping");
            tls.write_all(b"pong").await.unwrap();
        });
        let credential_path =
            std::env::temp_dir().join(format!("bloom-relay-test-{}.token", Uuid::new_v4()));
        std::fs::write(&credential_path, &token).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&credential_path, std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        let config = TunnelConfig {
            gateway: control_address,
            control_server_name: "relay-control.bloom.directory".into(),
            hostname: allocation.hostname.clone(),
            installation_id: id,
            credential_path: credential_path.clone(),
            tls: client_tls.clone(),
        };
        let (ready, mut watched) = watch::channel(false);
        let (stop, stopped) = oneshot::channel::<()>();
        let first = tokio::spawn(
            TunnelClient::new(config.clone(), CEREMONY_UPSTREAM)
                .unwrap()
                .run_until_ready(
                    async move {
                        let _ = stopped.await;
                    },
                    ready,
                ),
        );
        timeout(Duration::from_secs(5), watched.changed())
            .await
            .unwrap()
            .unwrap();
        assert!(*watched.borrow());
        let first_generation = gateway
            .tunnels
            .lock()
            .await
            .get(&allocation.hostname)
            .unwrap()
            .generation;

        let mut browser_tls = ClientConfig::builder()
            .with_root_certificates({
                let mut roots = RootCertStore::empty();
                let cert = CertificateDer::pem_file_iter(&cert_path)
                    .unwrap()
                    .next()
                    .unwrap()
                    .unwrap();
                roots.add(cert).unwrap();
                roots
            })
            .with_no_client_auth();
        browser_tls.alpn_protocols.clear();
        let tcp = TcpStream::connect(ingress_address).await.unwrap();
        let mut browser = tokio_rustls::TlsConnector::from(Arc::new(browser_tls))
            .connect(
                ServerName::try_from(allocation.hostname.clone()).unwrap(),
                tcp,
            )
            .await
            .unwrap();
        browser.write_all(b"ping").await.unwrap();
        let mut reply = [0u8; 4];
        timeout(Duration::from_secs(5), browser.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply, b"pong");
        upstream_task.await.unwrap();

        let (ready_second, mut watched_second) = watch::channel(false);
        let (stop_second, stopped_second) = oneshot::channel::<()>();
        let second = tokio::spawn(
            TunnelClient::new(config, CEREMONY_UPSTREAM)
                .unwrap()
                .run_until_ready(
                    async move {
                        let _ = stopped_second.await;
                    },
                    ready_second,
                ),
        );
        timeout(Duration::from_secs(5), watched_second.changed())
            .await
            .unwrap()
            .unwrap();
        let second_generation = gateway
            .tunnels
            .lock()
            .await
            .get(&allocation.hostname)
            .unwrap()
            .generation;
        assert!(second_generation > first_generation);
        assert!(
            !store
                .tunnel_is_current(id, "fixture", first_generation)
                .await
                .unwrap()
        );
        assert!(
            store
                .tunnel_is_current(id, "fixture", second_generation)
                .await
                .unwrap()
        );
        let _ = stop.send(());
        let _ = stop_second.send(());
        first.await.unwrap().unwrap();
        second.await.unwrap().unwrap();
        control_task.abort();
        ingress_task.abort();
        std::fs::remove_file(credential_path).unwrap();
        std::fs::remove_dir_all(fixture).unwrap();
    }
}
