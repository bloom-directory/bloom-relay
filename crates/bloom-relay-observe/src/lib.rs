//! Private Prometheus instrumentation shared by relay service processes.

use axum::{Router, extract::State, http::StatusCode, routing::get};
use metrics_exporter_prometheus::PrometheusBuilder;
use std::{
    env,
    error::Error,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Clone)]
pub struct HealthHandle(Arc<AtomicBool>);

impl HealthHandle {
    pub fn set_ready(&self, ready: bool) {
        self.0.store(ready, Ordering::Release);
    }
}

fn private_bind(value: &str) -> Result<SocketAddr, Box<dyn Error + Send + Sync>> {
    let bind: SocketAddr = value.parse()?;
    if !bind.ip().is_loopback() {
        return Err("diagnostic listener must bind to loopback".into());
    }
    Ok(bind)
}

pub fn install(service: &'static str) -> Result<HealthHandle, Box<dyn Error + Send + Sync>> {
    let bind = private_bind(&env::var("BLOOM_RELAY_METRICS_BIND")?)?;
    let health_bind = private_bind(&env::var("BLOOM_RELAY_HEALTH_BIND")?)?;
    install_on(service, bind, health_bind)
}

fn install_on(
    service: &'static str,
    bind: SocketAddr,
    health_bind: SocketAddr,
) -> Result<HealthHandle, Box<dyn Error + Send + Sync>> {
    if bind == health_bind {
        return Err("health and metrics listeners must differ".into());
    }
    let health = HealthHandle(Arc::new(AtomicBool::new(false)));
    let listener = std::net::TcpListener::bind(health_bind)?;
    listener.set_nonblocking(true)?;
    let listener = tokio::net::TcpListener::from_std(listener)?;
    let app = Router::new()
        .route("/health/live", get(|| async { StatusCode::OK }))
        .route(
            "/health/ready",
            get(|State(health): State<HealthHandle>| async move {
                if health.0.load(Ordering::Acquire) {
                    StatusCode::OK
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                }
            }),
        )
        .with_state(health.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    PrometheusBuilder::new()
        .with_http_listener(bind)
        .install()?;
    metrics::gauge!("bloom_relay_process_up", "service" => service).set(1.0);
    Ok(health)
}

pub fn count(name: &'static str) {
    metrics::counter!(name).increment(1);
}

pub fn add(name: &'static str, value: u64) {
    metrics::counter!(name).increment(value);
}

pub fn gauge(name: &'static str, value: f64) {
    metrics::gauge!(name).set(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn diagnostics_are_loopback_only() {
        assert!(private_bind("127.0.0.1:9100").is_ok());
        assert!(private_bind("[::1]:9100").is_ok());
        assert!(private_bind("0.0.0.0:9100").is_err());
    }

    #[tokio::test]
    async fn private_health_and_prometheus_listeners_serve_real_requests() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        async fn free_port() -> SocketAddr {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap()
        }
        async fn get(addr: SocketAddr, path: &str) -> String {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            stream
                .write_all(
                    format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                )
                .await
                .unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).await.unwrap();
            String::from_utf8(bytes).unwrap()
        }
        let metrics = free_port().await;
        let health_addr = free_port().await;
        let health = install_on("test", metrics, health_addr).unwrap();
        assert!(
            get(health_addr, "/health/ready")
                .await
                .starts_with("HTTP/1.1 503")
        );
        health.set_ready(true);
        assert!(
            get(health_addr, "/health/ready")
                .await
                .starts_with("HTTP/1.1 200")
        );
        count("bloom_relay_fixture_total");
        let response = get(metrics, "/metrics").await;
        assert!(response.contains("bloom_relay_fixture_total"));
    }
}
