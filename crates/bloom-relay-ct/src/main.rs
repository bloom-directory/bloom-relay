//! Pull a reviewed authenticated CT adapter and deliver durable independent alerts.

use bloom_relay_store::Store;
use serde::Deserialize;
use std::{env, fs, path::PathBuf, time::Duration};
use url::Url;

type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CtBatch {
    source: String,
    entries: Vec<CtEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CtEntry {
    position: u64,
    hostname: String,
    key_fingerprint: String,
}

#[derive(Clone)]
struct Endpoint {
    url: String,
    ca_pem: Vec<u8>,
    token_path: PathBuf,
}

struct Worker {
    store: Store,
    source: String,
    feed: Endpoint,
    alert: Endpoint,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    rustls_provider()?;
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let source = env::var("BLOOM_RELAY_CT_SOURCE")?;
    let feed_url = checked_url(&env::var("BLOOM_RELAY_CT_FEED_ORIGIN")?, true)?;
    let alert_url = checked_url(&env::var("BLOOM_RELAY_CT_ALERT_URL")?, false)?;
    let worker = Worker {
        store: Store::connect_with_witness(
            &env::var("BLOOM_RELAY_DATABASE_URL")?,
            env::var("BLOOM_RELAY_RESTORE_WITNESS_PATH")?.into(),
        )
        .await?,
        source,
        feed: Endpoint {
            url: feed_url,
            ca_pem: fs::read(env::var("BLOOM_RELAY_CT_FEED_CA_PATH")?)?,
            token_path: env::var("BLOOM_RELAY_CT_FEED_TOKEN_PATH")?.into(),
        },
        alert: Endpoint {
            url: alert_url,
            ca_pem: fs::read(env::var("BLOOM_RELAY_CT_ALERT_CA_PATH")?)?,
            token_path: env::var("BLOOM_RELAY_CT_ALERT_TOKEN_PATH")?.into(),
        },
    };
    worker.store.ensure_ct_source(&worker.source).await?;
    loop {
        if let Err(error) = worker.tick().await {
            tracing::error!(%error, "CT worker tick failed");
        }
        if env::var("BLOOM_RELAY_CT_ONCE").ok().as_deref() == Some("1") {
            break;
        }
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
    Ok(())
}

fn rustls_provider() -> Result<(), Error> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| "TLS provider conflict".into())
}

fn checked_url(value: &str, origin_only: bool) -> Result<String, Error> {
    let url = Url::parse(value)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || (origin_only && url.path() != "/")
    {
        return Err("invalid CT endpoint".into());
    }
    Ok(if origin_only {
        url.origin().ascii_serialization()
    } else {
        value.into()
    })
}

impl Worker {
    async fn tick(&self) -> Result<(), Error> {
        let checkpoint = self
            .store
            .ct_checkpoint(&self.source)
            .await?
            .ok_or("missing CT checkpoint")?;
        match self.fetch(checkpoint).await {
            Ok(batch) if batch.source == self.source && batch.entries.len() <= 100 => {
                let mut next = checkpoint;
                let mut contiguous = true;
                for entry in batch.entries {
                    if entry.position != next + 1 {
                        contiguous = false;
                        break;
                    }
                    self.store
                        .observe_ct(
                            &self.source,
                            entry.position,
                            &entry.hostname,
                            &entry.key_fingerprint,
                        )
                        .await?;
                    next = entry.position;
                }
                if contiguous {
                    self.store.mark_ct_feed_healthy(&self.source, next).await?;
                } else {
                    tracing::warn!("noncontiguous CT batch");
                }
            }
            Ok(_) => tracing::warn!("invalid CT batch"),
            Err(error) => tracing::warn!(%error, "CT feed unavailable"),
        }
        self.store.queue_ct_lag_alert(&self.source).await?;
        self.deliver().await
    }

    async fn fetch(&self, checkpoint: u64) -> Result<CtBatch, Error> {
        let endpoint = self.feed.clone();
        tokio::task::spawn_blocking(move || -> Result<CtBatch, Error> {
            let agent = agent(&endpoint.ca_pem)?;
            let token = read_token(&endpoint.token_path)?;
            let url = format!("{}/v1/entries?after={checkpoint}&limit=100", endpoint.url);
            let mut response = agent
                .get(url)
                .header("authorization", format!("Bearer {token}"))
                .call()?;
            Ok(response
                .body_mut()
                .with_config()
                .limit(128 * 1024)
                .read_json()?)
        })
        .await?
    }

    async fn deliver(&self) -> Result<(), Error> {
        for alert in self.store.pending_ct_alerts(&self.source, 100).await? {
            self.post_alert(
                format!("ct:{}:{}", alert.source, alert.id),
                serde_json::json!({
                    "kind":"unexpected_issuance", "source":alert.source, "position":alert.position,
                    "hostname":alert.hostname, "key_fingerprint":alert.fingerprint,
                }),
            )
            .await?;
            self.store.mark_ct_alert_delivered(alert.id).await?;
        }
        for alert in self.store.pending_ct_lag_alerts(&self.source, 100).await? {
            self.post_alert(
                format!("ct-lag:{}:{}", alert.source, alert.id),
                serde_json::json!({
                    "kind":"feed_lag", "source":alert.source, "lag_seconds":alert.lag_seconds,
                }),
            )
            .await?;
            self.store.mark_ct_lag_alert_delivered(alert.id).await?;
        }
        Ok(())
    }

    async fn post_alert(&self, key: String, body: serde_json::Value) -> Result<(), Error> {
        let endpoint = self.alert.clone();
        tokio::task::spawn_blocking(move || -> Result<(), Error> {
            let agent = agent(&endpoint.ca_pem)?;
            let token = read_token(&endpoint.token_path)?;
            let response = agent
                .post(&endpoint.url)
                .header("authorization", format!("Bearer {token}"))
                .header("idempotency-key", key)
                .send_json(body)?;
            if response.status() != 202 {
                return Err("CT alert sink rejected event".into());
            }
            Ok(())
        })
        .await?
    }
}

fn agent(ca_pem: &[u8]) -> Result<ureq::Agent, Error> {
    let cert = ureq::tls::Certificate::from_pem(ca_pem)?;
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

fn read_token(path: &std::path::Path) -> Result<String, Error> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.file_type().is_file() || meta.len() > 256 {
        return Err("invalid CT token file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err("CT token permissions".into());
        }
    }
    let token = fs::read_to_string(path)?.trim().to_owned();
    if token.len() < 16
        || token.len() > 128
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("invalid CT token".into());
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json, Router,
        extract::State,
        http::StatusCode,
        routing::{get, post},
    };
    use bloom_relay_protocol::CertificateMetadata;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use tokio::sync::mpsc;
    use uuid::Uuid;

    struct Fixture {
        source: String,
        hostname: String,
        feed_down: AtomicBool,
        alerts: mpsc::UnboundedSender<serde_json::Value>,
    }

    #[tokio::test]
    async fn executable_worker_consumes_feed_and_delivers_issuance_and_lag_alerts() {
        let Ok(url) = env::var("BLOOM_RELAY_TEST_DATABASE_URL") else {
            return;
        };
        rustls_provider().unwrap();
        let store = Store::connect(&url).await.unwrap();
        let allocation = store
            .allocate(Uuid::new_v4(), [3u8; 32], "fixture")
            .await
            .unwrap();
        let id = allocation.installation_id;
        let account = "https://acme-v02.api.letsencrypt.org/acme/acct/123";
        store.register_acme_account(id, account).await.unwrap();
        store.mark_dns_ready(id).await.unwrap();
        store
            .record_expected_certificate(
                id,
                &CertificateMetadata {
                    hostname: allocation.hostname.clone(),
                    acme_account_uri: account.into(),
                    key_fingerprint: "a".repeat(64),
                    lineage: "fixture".into(),
                    not_before_ms: 1,
                    not_after_ms: 2_000_000_000_000,
                },
            )
            .await
            .unwrap();
        let source = format!("fixture-{}", Uuid::new_v4());
        let (sent, mut received) = mpsc::unbounded_channel();
        let fixture = Arc::new(Fixture {
            source: source.clone(),
            hostname: allocation.hostname,
            feed_down: AtomicBool::new(false),
            alerts: sent,
        });
        let app = Router::new()
            .route("/v1/entries", get(|State(state): State<Arc<Fixture>>| async move {
                if state.feed_down.load(Ordering::Relaxed) { return Err(StatusCode::SERVICE_UNAVAILABLE); }
                Ok(Json(serde_json::json!({"source":state.source,"entries":[
                    {"position":1,"hostname":state.hostname,"key_fingerprint":"a".repeat(64)},
                    {"position":2,"hostname":state.hostname,"key_fingerprint":"b".repeat(64)}
                ]})))
            }))
            .route("/alerts", post(|State(state): State<Arc<Fixture>>, Json(body): Json<serde_json::Value>| async move {
                state.alerts.send(body).unwrap(); StatusCode::ACCEPTED
            }))
            .with_state(fixture.clone());
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let folder = env::temp_dir().join(format!("bloom-ct-fixture-{}", Uuid::new_v4()));
        fs::create_dir(&folder).unwrap();
        let cert_path = folder.join("cert.pem");
        let key_path = folder.join("key.pem");
        let token_path = folder.join("token");
        fs::write(&cert_path, certificate.cert.pem()).unwrap();
        fs::write(&key_path, certificate.signing_key.serialize_pem()).unwrap();
        fs::write(&token_path, "fixturetokenfixturetoken").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path)
            .await
            .unwrap();
        let server = tokio::spawn(async move {
            axum_server::bind_rustls(address, tls)
                .serve(app.into_make_service())
                .await
                .unwrap();
        });
        let endpoint = Endpoint {
            url: format!("https://localhost:{}", address.port()),
            ca_pem: certificate.cert.pem().into_bytes(),
            token_path,
        };
        let worker = Worker {
            store: store.clone(),
            source: source.clone(),
            feed: endpoint.clone(),
            alert: Endpoint {
                url: format!("{}/alerts", endpoint.url),
                ..endpoint
            },
        };
        worker.store.ensure_ct_source(&source).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        worker.tick().await.unwrap();
        assert_eq!(worker.store.ct_checkpoint(&source).await.unwrap(), Some(2));
        assert_eq!(
            received.recv().await.unwrap()["kind"],
            "unexpected_issuance"
        );
        assert!(
            worker
                .store
                .pending_ct_alerts(&source, 10)
                .await
                .unwrap()
                .is_empty()
        );
        fixture.feed_down.store(true, Ordering::Relaxed);
        sqlx::query("UPDATE ct_feed_checkpoints SET observed_at=now()-interval '20 minutes' WHERE source=$1")
            .bind(&source).execute(store.pool()).await.unwrap();
        worker.tick().await.unwrap();
        assert_eq!(received.recv().await.unwrap()["kind"], "feed_lag");
        assert!(
            worker
                .store
                .pending_ct_lag_alerts(&source, 10)
                .await
                .unwrap()
                .is_empty()
        );
        server.abort();
        fs::remove_dir_all(folder).unwrap();
    }
}
