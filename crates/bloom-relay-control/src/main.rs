use axum::{
    Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bloom_relay_protocol::{
    AcmeAccountRequest, AllocateRequest, AllocationReceipt, BootstrapChallenge,
    CertificateMetadata, CredentialIssueReceipt, CredentialIssueRequest, CredentialRenewRequest,
    DnsChallengeDeleteRequest, DnsChallengeRequest, ErrorCode, ErrorEnvelope, Scope, SignedRequest,
    WIRE_VERSION, sha256_hex,
};
use bloom_relay_store::{RestoreWitness, Store};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::{RngCore, rngs::OsRng};
use std::{
    env, fs,
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
mod dns_worker;

struct AppState {
    store: Store,
    receipt_key: SigningKey,
    audience: String,
    placement: String,
}
struct ApiError(StatusCode, ErrorCode, bool);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.0,
            Json(ErrorEnvelope {
                code: self.1,
                request_id: Uuid::new_v4(),
                retryable: self.2,
            }),
        )
            .into_response()
    }
}
fn unauthorized() -> ApiError {
    ApiError(StatusCode::UNAUTHORIZED, ErrorCode::Unauthorized, false)
}
fn unavailable() -> ApiError {
    ApiError(
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::DependencyUnavailable,
        true,
    )
}
fn invalid() -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest, false)
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| "TLS provider conflict")?;
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let bind: SocketAddr = env::var("BLOOM_RELAY_CONTROL_BIND")?.parse()?;
    let audience = env::var("BLOOM_RELAY_CONTROL_AUDIENCE")?;
    if audience != "relay-control.bloom.directory" {
        return Err("invalid control audience".into());
    }
    let placement = env::var("BLOOM_RELAY_PLACEMENT")?;
    let key_bytes = fs::read(env::var("BLOOM_RELAY_RECEIPT_KEY_PATH")?)?;
    let key_bytes: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "receipt key must be 32 raw bytes")?;
    let witness_path = env::var("BLOOM_RELAY_RESTORE_WITNESS_PATH")?;
    let state = Arc::new(AppState {
        store: Store::connect_with_witness(
            &env::var("BLOOM_RELAY_DATABASE_URL")?,
            witness_path.clone().into(),
        )
        .await?,
        receipt_key: SigningKey::from_bytes(&key_bytes),
        audience,
        placement,
    });
    let witness = RestoreWitness::new(witness_path.into())?;
    witness.verify_and_advance(&state.store).await?;
    let witness_store = state.store.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            if let Err(error) = witness.verify_and_advance(&witness_store).await {
                tracing::error!(%error, "restore witness failed; control stopping");
                std::process::exit(78);
            }
        }
    });
    let worker = dns_worker::DnsWorker::configured(state.store.clone()).await?;
    tokio::spawn(worker.run());
    let app = Router::new()
        .route("/health/live", get(|| async { StatusCode::OK }))
        .route("/health/ready", get(ready))
        .route("/v1/bootstrap/challenge", post(challenge))
        .route("/v1/bootstrap/enroll", post(enroll))
        .route("/v1/credentials", post(issue_credential))
        .route("/v1/credentials/renew", post(renew_credential))
        .route("/v1/acme-account", post(register_acme_account))
        .route("/v1/certificates", post(record_certificate))
        .route("/v1/dns/challenge", post(create_dns_challenge))
        .route("/v1/dns/challenge/delete", post(delete_dns_challenge))
        .route(
            "/v1/dns/challenge/{installation}/{lease}",
            get(dns_challenge_ready),
        )
        .layer(DefaultBodyLimit::max(16 * 1024))
        .with_state(state);
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(
        env::var("BLOOM_RELAY_CONTROL_CERT_PATH")?,
        env::var("BLOOM_RELAY_CONTROL_KEY_PATH")?,
    )
    .await?;
    axum_server::bind_rustls(bind, tls)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    Ok(())
}

async fn authenticate_dns(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    installation_id: Uuid,
    generation: Option<u64>,
) -> Result<u64, ApiError> {
    let bearer = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(unauthorized)?;
    let observed = state
        .store
        .authenticate_bearer(installation_id, "dns_challenge", bearer)
        .await
        .map_err(|_| unavailable())?
        .ok_or_else(unauthorized)?;
    if generation.is_some_and(|value| value != observed) {
        return Err(unauthorized());
    }
    Ok(observed)
}

async fn register_acme_account(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SignedRequest<AcmeAccountRequest>>,
) -> Result<StatusCode, ApiError> {
    let installation_id = request.claims.installation_id;
    let Some(bytes) = state
        .store
        .admin_public_key(installation_id)
        .await
        .map_err(|_| unavailable())?
    else {
        return Err(unauthorized());
    };
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| unavailable())?;
    let body = serde_jcs::to_vec(&request.body).map_err(|_| invalid())?;
    request
        .claims
        .verify(
            &body,
            &request.signature,
            &key,
            Scope::SurfaceAdmin,
            &state.audience,
            now_ms(),
        )
        .map_err(|_| unauthorized())?;
    if !state
        .store
        .consume_nonce(installation_id, &request.claims.nonce)
        .await
        .map_err(|_| unavailable())?
    {
        return Err(ApiError(
            StatusCode::GONE,
            ErrorCode::ExpiredOrReplayed,
            false,
        ));
    }
    state
        .store
        .register_acme_account(installation_id, &request.body.account_uri)
        .await
        .map_err(|error| match error {
            bloom_relay_store::StoreError::InvalidRequest => invalid(),
            bloom_relay_store::StoreError::Conflict => {
                ApiError(StatusCode::CONFLICT, ErrorCode::Conflict, false)
            }
            _ => unavailable(),
        })?;
    Ok(StatusCode::ACCEPTED)
}

async fn create_dns_challenge(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(request): Json<DnsChallengeRequest>,
) -> Result<StatusCode, ApiError> {
    if request.version != WIRE_VERSION || request.nonce.len() < 16 || request.nonce.len() > 128 {
        return Err(invalid());
    }
    authenticate_dns(
        &state,
        &headers,
        request.installation_id,
        Some(request.generation),
    )
    .await?;
    if !state
        .store
        .consume_nonce(request.installation_id, &request.nonce)
        .await
        .map_err(|_| unavailable())?
    {
        return Err(ApiError(
            StatusCode::GONE,
            ErrorCode::ExpiredOrReplayed,
            false,
        ));
    }
    state
        .store
        .create_challenge(request.installation_id, request.generation, &request.lease)
        .await
        .map_err(|error| match error {
            bloom_relay_store::StoreError::InvalidRequest => invalid(),
            bloom_relay_store::StoreError::Conflict => {
                ApiError(StatusCode::CONFLICT, ErrorCode::Conflict, false)
            }
            _ => unavailable(),
        })?;
    Ok(StatusCode::ACCEPTED)
}

async fn delete_dns_challenge(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(request): Json<DnsChallengeDeleteRequest>,
) -> Result<StatusCode, ApiError> {
    if request.version != WIRE_VERSION || request.nonce.len() < 16 || request.nonce.len() > 128 {
        return Err(invalid());
    }
    authenticate_dns(
        &state,
        &headers,
        request.installation_id,
        Some(request.generation),
    )
    .await?;
    if !state
        .store
        .consume_nonce(request.installation_id, &request.nonce)
        .await
        .map_err(|_| unavailable())?
    {
        return Err(ApiError(
            StatusCode::GONE,
            ErrorCode::ExpiredOrReplayed,
            false,
        ));
    }
    state
        .store
        .delete_challenge(
            request.installation_id,
            request.generation,
            request.lease_id,
        )
        .await
        .map_err(|_| unavailable())?;
    Ok(StatusCode::ACCEPTED)
}

async fn dns_challenge_ready(
    State(state): State<Arc<AppState>>,
    Path((installation_id, lease_id)): Path<(Uuid, Uuid)>,
    headers: axum::http::HeaderMap,
) -> Result<StatusCode, ApiError> {
    authenticate_dns(&state, &headers, installation_id, None).await?;
    let ready = state
        .store
        .challenge_ready(installation_id, lease_id)
        .await
        .map_err(|_| unavailable())?;
    Ok(if ready {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::ACCEPTED
    })
}

async fn record_certificate(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(certificate): Json<CertificateMetadata>,
) -> Result<StatusCode, ApiError> {
    let installation_id = headers
        .get("x-bloom-installation")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(invalid)?;
    authenticate_dns(&state, &headers, installation_id, None).await?;
    state
        .store
        .record_expected_certificate(installation_id, &certificate)
        .await
        .map_err(|error| match error {
            bloom_relay_store::StoreError::InvalidRequest => invalid(),
            bloom_relay_store::StoreError::Conflict => {
                ApiError(StatusCode::CONFLICT, ErrorCode::Conflict, false)
            }
            _ => unavailable(),
        })?;
    Ok(StatusCode::ACCEPTED)
}

async fn renew_credential(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(request): Json<CredentialRenewRequest>,
) -> Result<Json<CredentialIssueReceipt>, ApiError> {
    if request.version != WIRE_VERSION
        || !matches!(request.scope, Scope::Tunnel | Scope::DnsChallenge)
        || request.expires_at_ms <= now_ms()
        || request.expires_at_ms > now_ms().saturating_add(60_000)
        || request.nonce.len() < 16
        || request.nonce.len() > 128
    {
        return Err(invalid());
    }
    let bearer = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(unauthorized)?;
    let hash = hex::decode(&request.new_token_sha256).map_err(|_| invalid())?;
    let hash: [u8; 32] = hash.try_into().map_err(|_| invalid())?;
    let scope = if request.scope == Scope::Tunnel {
        "tunnel"
    } else {
        "dns_challenge"
    };
    let (generation, expires_at_ms) = state
        .store
        .renew_bearer(
            request.installation_id,
            request.operation_id,
            scope,
            request.generation,
            bearer,
            hash,
        )
        .await
        .map_err(|error| match error {
            bloom_relay_store::StoreError::Conflict => {
                ApiError(StatusCode::CONFLICT, ErrorCode::Conflict, false)
            }
            bloom_relay_store::StoreError::Unauthorized => unauthorized(),
            _ => unavailable(),
        })?;
    Ok(Json(CredentialIssueReceipt {
        version: WIRE_VERSION,
        scope: request.scope,
        generation,
        operation_id: request.operation_id,
        expires_at_ms,
    }))
}

async fn ready(State(state): State<Arc<AppState>>) -> StatusCode {
    match sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(state.store.pool())
        .await
    {
        Ok(1) => StatusCode::OK,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}

async fn challenge(
    State(state): State<Arc<AppState>>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
) -> Result<Json<BootstrapChallenge>, ApiError> {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let nonce = URL_SAFE_NO_PAD.encode(nonce);
    if !state
        .store
        .create_bootstrap_challenge(&nonce, source.ip())
        .await
        .map_err(|_| unavailable())?
    {
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::QuotaExceeded,
            true,
        ));
    }
    Ok(Json(BootstrapChallenge {
        version: WIRE_VERSION,
        nonce,
        expires_at_ms: now_ms() + 60_000,
    }))
}

async fn enroll(
    State(state): State<Arc<AppState>>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    Json(request): Json<SignedRequest<AllocateRequest>>,
) -> Result<Json<AllocationReceipt>, ApiError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(&request.body.admin_public_key)
        .map_err(|_| invalid())?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| invalid())?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| invalid())?;
    let body = serde_jcs::to_vec(&request.body).map_err(|_| invalid())?;
    if request.claims.installation_id != Uuid::nil()
        || request.claims.operation_id != request.body.operation_id
        || request.claims.nonce != request.body.bootstrap_nonce
    {
        return Err(unauthorized());
    }
    request
        .claims
        .verify(
            &body,
            &request.signature,
            &key,
            Scope::SurfaceAdmin,
            &state.audience,
            now_ms(),
        )
        .map_err(|_| unauthorized())?;
    if !state
        .store
        .consume_bootstrap_challenge(&request.body.bootstrap_nonce, source.ip())
        .await
        .map_err(|_| unavailable())?
    {
        return Err(ApiError(
            StatusCode::GONE,
            ErrorCode::ExpiredOrReplayed,
            false,
        ));
    }
    let allocation = state
        .store
        .allocate(request.body.operation_id, bytes, &state.placement)
        .await
        .map_err(|error| {
            if matches!(error, bloom_relay_store::StoreError::Conflict) {
                ApiError(StatusCode::CONFLICT, ErrorCode::Conflict, false)
            } else {
                unavailable()
            }
        })?;
    let mut receipt = AllocationReceipt {
        allocation,
        operation_id: request.body.operation_id,
        admin_key_sha256: sha256_hex(&bytes),
        issued_at_ms: now_ms(),
        signature: String::new(),
    };
    receipt.signature = URL_SAFE_NO_PAD.encode(
        state
            .receipt_key
            .sign(&receipt.signed_bytes().map_err(|_| unavailable())?)
            .to_bytes(),
    );
    Ok(Json(receipt))
}

async fn issue_credential(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SignedRequest<CredentialIssueRequest>>,
) -> Result<Json<CredentialIssueReceipt>, ApiError> {
    if !matches!(request.body.scope, Scope::Tunnel | Scope::DnsChallenge) {
        return Err(invalid());
    }
    let Some(bytes) = state
        .store
        .admin_public_key(request.claims.installation_id)
        .await
        .map_err(|_| unavailable())?
    else {
        return Err(unauthorized());
    };
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| unavailable())?;
    let body = serde_jcs::to_vec(&request.body).map_err(|_| invalid())?;
    request
        .claims
        .verify(
            &body,
            &request.signature,
            &key,
            Scope::SurfaceAdmin,
            &state.audience,
            now_ms(),
        )
        .map_err(|_| unauthorized())?;
    if !state
        .store
        .consume_nonce(request.claims.installation_id, &request.claims.nonce)
        .await
        .map_err(|_| unavailable())?
    {
        return Err(ApiError(
            StatusCode::GONE,
            ErrorCode::ExpiredOrReplayed,
            false,
        ));
    }
    let hash = hex::decode(&request.body.token_sha256).map_err(|_| invalid())?;
    let hash: [u8; 32] = hash.try_into().map_err(|_| invalid())?;
    let scope = if request.body.scope == Scope::Tunnel {
        "tunnel"
    } else {
        "dns_challenge"
    };
    let (generation, expires_at_ms) = state
        .store
        .issue_bearer(
            request.claims.installation_id,
            request.claims.operation_id,
            scope,
            hash,
            request.body.validity_seconds as i32,
        )
        .await
        .map_err(|_| unavailable())?;
    Ok(Json(CredentialIssueReceipt {
        version: WIRE_VERSION,
        scope: request.body.scope,
        generation,
        operation_id: request.claims.operation_id,
        expires_at_ms,
    }))
}
