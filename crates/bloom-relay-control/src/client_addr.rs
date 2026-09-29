//! The client address the control API's quotas are keyed on.
//!
//! In the packaged topology HAProxy terminates public TLS and opens its own
//! loopback connection to the API, so the TCP peer is always HAProxy. With
//! `BLOOM_RELAY_CONTROL_PROXY_PROTOCOL=v2`, HAProxy's `send-proxy-v2` writes
//! the real client address at the start of each backend connection, before
//! TLS. It is transport data from the one process allowed to connect, not an
//! HTTP header a client could supply, and HAProxy never reuses such a
//! connection for another client. Every connection must then carry the
//! header, and the API must listen on loopback only.

use axum::{Extension, extract::ConnectInfo};
use axum_server::accept::Accept;
use std::{
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    time::Duration,
};
use tokio::{io::AsyncReadExt, net::TcpStream};
use tower_layer::Layer;

const PROXY_ENV: &str = "BLOOM_RELAY_CONTROL_PROXY_PROTOCOL";
const SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
/// Longest address block plus TLVs accepted; HAProxy sends far less.
const MAX_BODY: usize = 512;
const HEADER_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientAddrAcceptor {
    proxy_v2: bool,
}

impl ClientAddrAcceptor {
    /// Clients are the TCP peers.
    pub fn peer() -> Self {
        Self { proxy_v2: false }
    }

    /// Clients come from a PROXY protocol v2 header on every connection.
    pub fn proxy_v2() -> Self {
        Self { proxy_v2: true }
    }

    pub fn from_env(bind: SocketAddr) -> Result<Self, String> {
        match std::env::var(PROXY_ENV).as_deref() {
            Err(std::env::VarError::NotPresent) | Ok("" | "none") => Ok(Self::peer()),
            Ok("v2") if bind.ip().is_loopback() => Ok(Self::proxy_v2()),
            Ok("v2") => Err(format!(
                "{PROXY_ENV}=v2 requires a loopback control bind, not {bind}"
            )),
            _ => Err(format!("{PROXY_ENV} must be v2 or none")),
        }
    }
}

type AcceptFuture<S> = Pin<Box<dyn Future<Output = io::Result<(TcpStream, S)>> + Send>>;

impl<S: Send + 'static> Accept<TcpStream, S> for ClientAddrAcceptor {
    type Stream = TcpStream;
    type Service = axum::middleware::AddExtension<S, ConnectInfo<SocketAddr>>;
    type Future = AcceptFuture<Self::Service>;

    fn accept(&self, mut stream: TcpStream, service: S) -> Self::Future {
        let proxy_v2 = self.proxy_v2;
        Box::pin(async move {
            let peer = stream.peer_addr()?;
            let client = if proxy_v2 {
                tokio::time::timeout(HEADER_TIMEOUT, read_proxy_v2(&mut stream))
                    .await
                    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??
                    .unwrap_or(peer)
            } else {
                peer
            };
            Ok((stream, Extension(ConnectInfo(client)).layer(service)))
        })
    }
}

/// Read exactly one PROXY v2 header, leaving the TLS bytes behind it unread.
async fn read_proxy_v2(stream: &mut TcpStream) -> io::Result<Option<SocketAddr>> {
    let mut prefix = [0u8; 16];
    stream.read_exact(&mut prefix).await?;
    let length = body_length(&prefix)?;
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).await?;
    parse(&prefix, &body)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn body_length(prefix: &[u8; 16]) -> io::Result<usize> {
    if prefix[..12] != SIGNATURE {
        return Err(invalid("connection did not start with a PROXY v2 header"));
    }
    let length = usize::from(u16::from_be_bytes([prefix[14], prefix[15]]));
    if length > MAX_BODY {
        return Err(invalid("PROXY v2 header too long"));
    }
    Ok(length)
}

/// The client address a header names, or `None` for a `LOCAL` connection
/// (one HAProxy opened itself, such as a health check).
fn parse(prefix: &[u8; 16], body: &[u8]) -> io::Result<Option<SocketAddr>> {
    if body_length(prefix)? != body.len() {
        return Err(invalid("PROXY v2 header length mismatch"));
    }
    if prefix[12] >> 4 != 2 {
        return Err(invalid("unsupported PROXY protocol version"));
    }
    match prefix[12] & 0x0f {
        0x0 => return Ok(None),
        0x1 => {}
        _ => return Err(invalid("unsupported PROXY v2 command")),
    }
    match prefix[13] {
        // TCP over IPv4: source, destination, source port, destination port.
        0x11 if body.len() >= 12 => {
            let ip = Ipv4Addr::new(body[0], body[1], body[2], body[3]);
            let port = u16::from_be_bytes([body[8], body[9]]);
            Ok(Some(SocketAddr::new(IpAddr::V4(ip), port)))
        }
        // TCP over IPv6.
        0x21 if body.len() >= 36 => {
            let octets: [u8; 16] = body[..16].try_into().expect("16-byte slice");
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([body[32], body[33]]);
            Ok(Some(SocketAddr::new(ip.to_canonical(), port)))
        }
        _ => Err(invalid("PROXY v2 header is not TCP over IPv4 or IPv6")),
    }
}

#[cfg(test)]
pub(crate) fn header_v4(ip: [u8; 4], port: u16) -> Vec<u8> {
    let mut header = SIGNATURE.to_vec();
    header.extend_from_slice(&[0x21, 0x11, 0, 12]);
    header.extend_from_slice(&ip);
    header.extend_from_slice(&[127, 0, 0, 1]);
    header.extend_from_slice(&port.to_be_bytes());
    header.extend_from_slice(&18443u16.to_be_bytes());
    header
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, routing::get};
    use tokio::io::AsyncWriteExt;

    fn split(header: &[u8]) -> ([u8; 16], &[u8]) {
        (header[..16].try_into().unwrap(), &header[16..])
    }

    #[test]
    fn parses_tcp_over_ipv4_and_ipv6() {
        let header = header_v4([203, 0, 113, 7], 50_000);
        let (prefix, body) = split(&header);
        assert_eq!(
            parse(&prefix, body).unwrap(),
            Some("203.0.113.7:50000".parse().unwrap())
        );

        let mut header = SIGNATURE.to_vec();
        header.extend_from_slice(&[0x21, 0x21, 0, 36]);
        header.extend_from_slice(&"2001:db8::7".parse::<Ipv6Addr>().unwrap().octets());
        header.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        header.extend_from_slice(&443u16.to_be_bytes());
        header.extend_from_slice(&18443u16.to_be_bytes());
        let (prefix, body) = split(&header);
        assert_eq!(
            parse(&prefix, body).unwrap(),
            Some("[2001:db8::7]:443".parse().unwrap())
        );
    }

    #[test]
    fn an_ipv4_mapped_ipv6_client_is_keyed_as_ipv4() {
        let mut header = SIGNATURE.to_vec();
        header.extend_from_slice(&[0x21, 0x21, 0, 36]);
        header.extend_from_slice(&"::ffff:198.51.100.9".parse::<Ipv6Addr>().unwrap().octets());
        header.extend_from_slice(&[0; 16]);
        header.extend_from_slice(&[0, 1, 0, 2]);
        let (prefix, body) = split(&header);
        assert_eq!(
            parse(&prefix, body).unwrap().unwrap().ip(),
            "198.51.100.9".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn a_local_connection_names_no_client() {
        let mut header = SIGNATURE.to_vec();
        header.extend_from_slice(&[0x20, 0x00, 0, 0]);
        let (prefix, body) = split(&header);
        assert_eq!(parse(&prefix, body).unwrap(), None);
    }

    #[test]
    fn malformed_headers_are_rejected() {
        let valid = header_v4([192, 0, 2, 1], 1);
        let reject = |mutate: &dyn Fn(&mut Vec<u8>)| {
            let mut header = valid.clone();
            mutate(&mut header);
            let prefix: [u8; 16] = header[..16].try_into().unwrap();
            parse(&prefix, &header[16..]).is_err()
        };
        assert!(reject(&|header| header[0] = b'G')); // an HTTP or TLS client
        assert!(reject(&|header| header[12] = 0x11)); // version 1
        assert!(reject(&|header| header[12] = 0x22)); // unknown command
        assert!(reject(&|header| header[13] = 0x12)); // UDP
        assert!(reject(&|header| header[13] = 0x31)); // Unix socket
        assert!(reject(&|header| header[15] = 4)); // truncated address block
        assert!(reject(&|header| header.truncate(20))); // length mismatch
        assert!(reject(&|header| header[14] = 0xff)); // oversized
    }

    #[test]
    fn proxy_protocol_requires_a_loopback_bind() {
        // Only checks the bind rule; the environment selector is read by
        // `from_env` and exercised in deployment.
        assert!(ClientAddrAcceptor::proxy_v2().proxy_v2);
        let public: SocketAddr = "192.0.2.1:18443".parse().unwrap();
        let loopback: SocketAddr = "127.0.0.1:18443".parse().unwrap();
        // SAFETY: tests in this module are the only readers of this variable.
        unsafe { std::env::set_var(PROXY_ENV, "v2") };
        assert!(ClientAddrAcceptor::from_env(public).is_err());
        assert_eq!(
            ClientAddrAcceptor::from_env(loopback).unwrap(),
            ClientAddrAcceptor::proxy_v2()
        );
        unsafe { std::env::set_var(PROXY_ENV, "v1") };
        assert!(ClientAddrAcceptor::from_env(loopback).is_err());
        unsafe { std::env::remove_var(PROXY_ENV) };
        assert_eq!(
            ClientAddrAcceptor::from_env(public).unwrap(),
            ClientAddrAcceptor::peer()
        );
    }

    async fn serve(acceptor: ClientAddrAcceptor) -> SocketAddr {
        let app =
            Router::new().route(
                "/",
                get(|ConnectInfo(client): ConnectInfo<SocketAddr>| async move {
                    client.ip().to_string()
                }),
            );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(
            axum_server::from_tcp(listener)
                .unwrap()
                .acceptor(acceptor)
                .serve(app.into_make_service()),
        );
        address
    }

    async fn request(address: SocketAddr, preamble: &[u8]) -> String {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(preamble).await.unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nhost: relay\r\nconnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response).await;
        response
    }

    #[tokio::test]
    async fn handlers_see_the_client_the_header_names() {
        let address = serve(ClientAddrAcceptor::proxy_v2()).await;
        let response = request(address, &header_v4([203, 0, 113, 7], 50_000)).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with("203.0.113.7"), "{response}");
    }

    #[tokio::test]
    async fn a_connection_without_the_header_is_dropped() {
        let address = serve(ClientAddrAcceptor::proxy_v2()).await;
        assert_eq!(request(address, b"").await, "");
    }

    #[tokio::test]
    async fn without_proxy_protocol_handlers_see_the_tcp_peer() {
        let address = serve(ClientAddrAcceptor::peer()).await;
        let response = request(address, b"").await;
        assert!(response.ends_with("127.0.0.1"), "{response}");
    }

    /// HAProxy sets the client address it forwards with `set-src`, so the
    /// test can prove the API sees that address across public TLS,
    /// `send-proxy-v2` and backend TLS with h2, exactly as packaged.
    #[tokio::test]
    #[ignore = "requires Docker and a HAProxy 3.x image"]
    async fn haproxy_send_proxy_v2_reaches_the_api_over_tls() {
        use std::{
            process::{Command, Stdio},
            sync::Arc,
        };
        let _ = rustls::crypto::ring::default_provider().install_default();
        let fixture =
            std::env::temp_dir().join(format!("bloom-relay-proxy-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&fixture).unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Bloom Relay Test CA");
        ca_params
            .key_usages
            .push(rcgen::KeyUsagePurpose::KeyCertSign);
        ca_params.key_usages.push(rcgen::KeyUsagePurpose::CrlSign);
        let ca =
            rcgen::CertifiedIssuer::self_signed(ca_params, rcgen::KeyPair::generate().unwrap())
                .unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params =
            rcgen::CertificateParams::new(vec!["relay-control.bloom.directory".into()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "relay-control.bloom.directory");
        params
            .key_usages
            .push(rcgen::KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
        let certificate = params.signed_by(&key, &ca).unwrap();
        let fullchain = format!("{}{}", certificate.pem(), ca.pem());
        std::fs::write(fixture.join("cert.pem"), &fullchain).unwrap();
        std::fs::write(fixture.join("key.pem"), key.serialize_pem()).unwrap();
        std::fs::write(fixture.join("ca.pem"), ca.pem()).unwrap();
        std::fs::write(
            fixture.join("haproxy.pem"),
            format!("{fullchain}{}", key.serialize_pem()),
        )
        .unwrap();

        // The API, as packaged: TLS over the PROXY v2 acceptor. It listens
        // beyond loopback only so the container can reach it.
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(
            fixture.join("cert.pem"),
            fixture.join("key.pem"),
        )
        .await
        .unwrap();
        let app =
            Router::new().route(
                "/",
                get(|ConnectInfo(client): ConnectInfo<SocketAddr>| async move {
                    client.ip().to_string()
                }),
            );
        let listener = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let api_port = listener.local_addr().unwrap().port();
        tokio::spawn(
            axum_server::from_tcp(listener)
                .unwrap()
                .acceptor(
                    axum_server::tls_rustls::RustlsAcceptor::new(tls)
                        .acceptor(ClientAddrAcceptor::proxy_v2()),
                )
                .serve(app.into_make_service()),
        );

        let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let frontend_port = reserved.local_addr().unwrap().port();
        drop(reserved);
        std::fs::write(
            fixture.join("haproxy.cfg"),
            format!(
                r#"defaults
    mode http
    timeout connect 2s
    timeout client 10s
    timeout server 10s

frontend relay_control
    bind :8443 ssl crt /fixture/haproxy.pem alpn h2,http/1.1
    tcp-request connection set-src ipv4(203.0.113.7)
    default_backend relay_api

backend relay_api
    server api host.docker.internal:{api_port} send-proxy-v2 ssl verify required ca-file /fixture/ca.pem verifyhost relay-control.bloom.directory sni str(relay-control.bloom.directory) alpn h2
"#
            ),
        )
        .unwrap();
        struct Container(String);
        impl Drop for Container {
            fn drop(&mut self) {
                let _ = Command::new("docker")
                    .args(["rm", "--force", &self.0])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
        let name = format!("bloom-relay-proxy-{}", uuid::Uuid::new_v4());
        let image = std::env::var("BLOOM_RELAY_TEST_HAPROXY_IMAGE")
            .unwrap_or_else(|_| "haproxy:3.2-alpine".into());
        let status = Command::new("docker")
            .args([
                "run",
                "--detach",
                "--rm",
                "--name",
                &name,
                "--add-host",
                "host.docker.internal:host-gateway",
                "--publish",
                &format!("127.0.0.1:{frontend_port}:8443"),
                "--volume",
                &format!("{}:/fixture:ro", fixture.to_string_lossy()),
                &image,
                "haproxy",
                "-db",
                "-f",
                "/fixture/haproxy.cfg",
            ])
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "start HAProxy container");
        let _container = Container(name);

        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(ca.der().to_vec()))
            .unwrap();
        let mut client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let last = Arc::new(std::sync::Mutex::new(String::new()));
        let seen = last.clone();
        let response = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if let Ok(tcp) = TcpStream::connect(("127.0.0.1", frontend_port)).await
                    && let Ok(mut tls) = connector
                        .connect(
                            rustls::pki_types::ServerName::try_from("relay-control.bloom.directory")
                                .unwrap(),
                            tcp,
                        )
                        .await
                {
                    tls.write_all(
                        b"GET / HTTP/1.1\r\nhost: relay-control.bloom.directory\r\nconnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap();
                    let mut response = String::new();
                    let _ = tls.read_to_string(&mut response).await;
                    if response.starts_with("HTTP/1.1 200") {
                        break response;
                    }
                    *seen.lock().unwrap() = response;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            let logs = Command::new("docker")
                .args(["logs", &_container.0])
                .output()
                .map(|output| String::from_utf8_lossy(&output.stderr).into_owned())
                .unwrap_or_default();
            panic!(
                "HAProxy did not forward to the API within 20 seconds; last response {:?}; logs:\n{logs}",
                last.lock().unwrap()
            )
        });
        assert!(response.ends_with("203.0.113.7"), "{response}");
        let _ = std::fs::remove_dir_all(fixture);
    }
}
