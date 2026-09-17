use bloom_relay_protocol::{CertificateMetadata, ChallengeLease};
use bloom_relay_store::{RestoreWitness, Store, StoreError, WitnessError};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Run with a disposable PostgreSQL URL. It deliberately exercises committed
/// transactions instead of mocking the generation and outbox boundary.
#[tokio::test]
async fn allocation_rotation_dns_and_fencing() {
    let Ok(url) = std::env::var("BLOOM_RELAY_TEST_DATABASE_URL") else {
        return;
    };
    let store = Store::connect(&url).await.unwrap();
    let operation = Uuid::new_v4();
    let admin = [9u8; 32];
    let allocation = store
        .allocate(operation, admin, "test-shard")
        .await
        .unwrap();
    let duplicate = store
        .allocate(operation, admin, "test-shard")
        .await
        .unwrap();
    assert_eq!(allocation, duplicate);
    assert!(matches!(
        store.allocate(operation, [8u8; 32], "test-shard").await,
        Err(StoreError::Conflict)
    ));
    let id = allocation.installation_id;
    let hostname = allocation.hostname.clone();
    assert_eq!(store.hostname(id).await.unwrap(), None);
    store
        .register_acme_account(id, "https://acme-v02.api.letsencrypt.org/acme/acct/123")
        .await
        .unwrap();
    store.mark_dns_ready(id).await.unwrap();
    assert_eq!(store.hostname(id).await.unwrap(), Some(hostname.clone()));

    let tunnel_token = "t".repeat(43);
    let issue = Uuid::new_v4();
    let hash: [u8; 32] = Sha256::digest(tunnel_token.as_bytes()).into();
    let (credential_generation, expiry) = store
        .issue_bearer(id, issue, "tunnel", hash, 86_400)
        .await
        .unwrap();
    assert_eq!(
        store
            .issue_bearer(id, issue, "tunnel", hash, 86_400)
            .await
            .unwrap(),
        (credential_generation, expiry)
    );
    assert_eq!(
        store
            .authenticate_bearer(id, "tunnel", &tunnel_token)
            .await
            .unwrap(),
        Some(credential_generation)
    );
    assert_eq!(
        store
            .authenticate_bearer(id, "dns_challenge", &tunnel_token)
            .await
            .unwrap(),
        None
    );
    assert!(matches!(
        store.claim_tunnel(id, "wrong-placement", 45).await,
        Err(StoreError::Conflict)
    ));
    let first = store.claim_tunnel(id, "test-shard", 45).await.unwrap();
    let second = store.claim_tunnel(id, "test-shard", 45).await.unwrap();
    assert!(
        !store
            .tunnel_is_current(id, "test-shard", first)
            .await
            .unwrap()
    );
    assert!(
        store
            .tunnel_is_current(id, "test-shard", second)
            .await
            .unwrap()
    );
    let next_token = "n".repeat(43);
    let next_hash: [u8; 32] = Sha256::digest(next_token.as_bytes()).into();
    let renew = Uuid::new_v4();
    let (next_generation, next_expiry) = store
        .renew_bearer(
            id,
            renew,
            "tunnel",
            credential_generation,
            &tunnel_token,
            next_hash,
        )
        .await
        .unwrap();
    assert!(next_generation > credential_generation && next_expiry > expiry - 1000);
    assert_eq!(
        store
            .renew_bearer(
                id,
                renew,
                "tunnel",
                credential_generation,
                &tunnel_token,
                next_hash
            )
            .await
            .unwrap(),
        (next_generation, next_expiry)
    );
    assert_eq!(
        store
            .authenticate_bearer(id, "tunnel", &tunnel_token)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        store
            .authenticate_bearer(id, "tunnel", &next_token)
            .await
            .unwrap(),
        Some(next_generation)
    );
    assert!(
        !store
            .tunnel_is_current(id, "test-shard", second)
            .await
            .unwrap()
    );

    let dns_token = "d".repeat(43);
    let dns_hash: [u8; 32] = Sha256::digest(dns_token.as_bytes()).into();
    let (dns_generation, _) = store
        .issue_bearer(id, Uuid::new_v4(), "dns_challenge", dns_hash, 86_400)
        .await
        .unwrap();
    let lease_id = Uuid::new_v4();
    let lease = ChallengeLease {
        operation_id: lease_id,
        txt_value: "a".repeat(43),
        expires_at_ms: now_ms() + 600_000,
    };
    store
        .create_challenge(id, dns_generation, &lease)
        .await
        .unwrap();
    assert!(!store.challenge_ready(id, lease_id).await.unwrap());
    store.mark_challenge_ready(id, lease_id).await.unwrap();
    assert!(store.challenge_ready(id, lease_id).await.unwrap());
    store
        .delete_challenge(id, dns_generation, lease_id)
        .await
        .unwrap();
    assert!(!store.challenge_ready(id, lease_id).await.unwrap());
    let retire_operation = Uuid::new_v4();
    store.retire(id, retire_operation).await.unwrap();
    store.retire(id, retire_operation).await.unwrap();
    assert!(matches!(
        store.retire(id, issue).await,
        Err(StoreError::Conflict)
    ));
    assert!(matches!(
        store.allocation_status(id).await.unwrap().unwrap().state,
        bloom_relay_protocol::AllocationState::Retired
    ));
    assert_eq!(store.hostname(id).await.unwrap(), None);
    assert_eq!(
        store
            .authenticate_bearer(id, "dns_challenge", &dns_token)
            .await
            .unwrap(),
        None
    );
    let reserved: i64 =
        sqlx::query_scalar("SELECT count(*) FROM hostname_reservations WHERE hostname=$1")
            .bind(hostname)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(reserved, 1);
}

#[tokio::test]
async fn abandoned_pending_and_challenge_leases_are_swept_without_reuse() {
    let Ok(url) = std::env::var("BLOOM_RELAY_TEST_DATABASE_URL") else {
        return;
    };
    let store = Store::connect(&url).await.unwrap();
    let pending = store
        .allocate(Uuid::new_v4(), [6u8; 32], "test-shard")
        .await
        .unwrap();
    sqlx::query(
        "UPDATE installations SET created_at=now()-interval '25 hours' WHERE installation_id=$1",
    )
    .bind(pending.installation_id)
    .execute(store.pool())
    .await
    .unwrap();
    assert!(store.expire_pending_allocations(100).await.unwrap() >= 1);
    assert!(matches!(
        store
            .allocation_status(pending.installation_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        bloom_relay_protocol::AllocationState::Retired
    ));
    let reservation: i64 =
        sqlx::query_scalar("SELECT count(*) FROM hostname_reservations WHERE hostname=$1")
            .bind(&pending.hostname)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(reservation, 1);

    let allocation = store
        .allocate(Uuid::new_v4(), [7u8; 32], "test-shard")
        .await
        .unwrap();
    let id = allocation.installation_id;
    store
        .register_acme_account(id, "https://acme-v02.api.letsencrypt.org/acme/acct/123")
        .await
        .unwrap();
    store.mark_dns_ready(id).await.unwrap();
    let token_hash: [u8; 32] = Sha256::digest(b"d-credential").into();
    let (generation, _) = store
        .issue_bearer(id, Uuid::new_v4(), "dns_challenge", token_hash, 3600)
        .await
        .unwrap();
    let lease_id = Uuid::new_v4();
    store
        .create_challenge(
            id,
            generation,
            &ChallengeLease {
                operation_id: lease_id,
                txt_value: "z".repeat(43),
                expires_at_ms: now_ms() + 60_000,
            },
        )
        .await
        .unwrap();
    sqlx::query("UPDATE challenge_leases SET expires_at=now()-interval '1 second' WHERE installation_id=$1 AND lease_id=$2")
        .bind(id).bind(lease_id).execute(store.pool()).await.unwrap();
    assert!(store.expire_challenge_leases(100).await.unwrap() >= 1);
    assert!(!store.challenge_ready(id, lease_id).await.unwrap());
    let jobs: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM outbox WHERE installation_id=$1 AND kind='remove_txt'",
    )
    .bind(id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(jobs, 1);
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[tokio::test]
async fn placement_move_fences_gateway_and_routes_dns_work() {
    let Ok(url) = std::env::var("BLOOM_RELAY_TEST_DATABASE_URL") else {
        return;
    };
    let store = Store::connect(&url).await.unwrap();
    let first_placement = format!("first-{}", Uuid::new_v4().simple());
    let second_placement = format!("second-{}", Uuid::new_v4().simple());
    let allocation = store
        .allocate(Uuid::new_v4(), [3u8; 32], &first_placement)
        .await
        .unwrap();
    let id = allocation.installation_id;
    assert!(store.claim_job(&second_placement).await.unwrap().is_none());
    let first_job = store.claim_job(&first_placement).await.unwrap().unwrap();
    assert_eq!(first_job.installation_id, id);
    store.complete_job(first_job.id).await.unwrap();
    store
        .register_acme_account(id, "https://acme-v02.api.letsencrypt.org/acme/acct/123")
        .await
        .unwrap();
    store.mark_dns_ready(id).await.unwrap();
    let first_generation = store.claim_tunnel(id, &first_placement, 45).await.unwrap();
    let move_operation = Uuid::new_v4();
    store
        .relocate(id, move_operation, &second_placement)
        .await
        .unwrap();
    store
        .relocate(id, move_operation, &second_placement)
        .await
        .unwrap();
    assert!(matches!(
        store.relocate(id, move_operation, &first_placement).await,
        Err(StoreError::Conflict)
    ));
    assert!(
        !store
            .tunnel_is_current(id, &first_placement, first_generation)
            .await
            .unwrap()
    );
    assert!(matches!(
        store.claim_tunnel(id, &first_placement, 45).await,
        Err(StoreError::Conflict)
    ));
    let second_generation = store.claim_tunnel(id, &second_placement, 45).await.unwrap();
    assert!(second_generation > first_generation);
    assert!(store.claim_job(&first_placement).await.unwrap().is_none());
    let job = store.claim_job(&second_placement).await.unwrap().unwrap();
    assert_eq!(job.installation_id, id);
    assert_eq!(job.kind, "publish_name");
    assert_eq!(
        store.allocation_status(id).await.unwrap().unwrap().hostname,
        allocation.hostname
    );
}

#[tokio::test]
async fn stale_database_revision_is_rejected_by_external_witness() {
    let Ok(url) = std::env::var("BLOOM_RELAY_TEST_DATABASE_URL") else {
        return;
    };
    let store = Store::connect(&url).await.unwrap();
    let revision = store.restore_revision().await.unwrap();
    let missing = std::env::temp_dir().join(format!("bloom-relay-missing-{}", Uuid::new_v4()));
    assert!(matches!(
        Store::connect_with_witness(&url, missing).await,
        Err(StoreError::Witness(_))
    ));
    let path = std::env::temp_dir().join(format!("bloom-relay-witness-test-{}", Uuid::new_v4()));
    std::fs::write(&path, format!("{revision}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let witness = RestoreWitness::new(path.clone()).unwrap();
    witness.verify_and_advance(&store).await.unwrap();
    let guarded = Store::connect_with_witness(&url, path.clone())
        .await
        .unwrap();
    guarded
        .allocate(Uuid::new_v4(), [4u8; 32], "test-shard")
        .await
        .unwrap();
    let advanced = store.restore_revision().await.unwrap();
    assert!(advanced > revision);
    let marker: u64 = std::fs::read_to_string(&path)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(marker > revision && marker <= advanced);
    let (first, second) = tokio::join!(
        guarded.allocate(Uuid::new_v4(), [1u8; 32], "test-shard"),
        guarded.allocate(Uuid::new_v4(), [2u8; 32], "test-shard")
    );
    first.unwrap();
    second.unwrap();
    let concurrent_marker: u64 = std::fs::read_to_string(&path)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(concurrent_marker >= marker + 2);
    std::fs::write(&path, format!("{}\n", advanced + 1_000_000)).unwrap();
    assert!(matches!(
        witness.verify_and_advance(&store).await,
        Err(WitnessError::StaleDatabase)
    ));
    assert!(matches!(
        guarded
            .allocate(Uuid::new_v4(), [6u8; 32], "test-shard")
            .await,
        Err(StoreError::Witness(_))
    ));
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn ct_fixture_flags_unexpected_issuance_and_preserves_checkpoint() {
    let Ok(url) = std::env::var("BLOOM_RELAY_TEST_DATABASE_URL") else {
        return;
    };
    let store = Store::connect(&url).await.unwrap();
    let allocation = store
        .allocate(Uuid::new_v4(), [5u8; 32], "test-shard")
        .await
        .unwrap();
    let id = allocation.installation_id;
    let account = "https://acme-v02.api.letsencrypt.org/acme/acct/123";
    store.register_acme_account(id, account).await.unwrap();
    store.mark_dns_ready(id).await.unwrap();
    let expected_key = "a".repeat(64);
    store
        .record_expected_certificate(
            id,
            &CertificateMetadata {
                hostname: allocation.hostname.clone(),
                acme_account_uri: account.into(),
                key_fingerprint: expected_key.clone(),
                lineage: "fixture-lineage".into(),
                not_before_ms: now_ms() - 1000,
                not_after_ms: now_ms() + 86_400_000,
            },
        )
        .await
        .unwrap();
    let source = format!("fixture-{}", Uuid::new_v4());
    assert!(
        store
            .observe_ct(&source, 1, &allocation.hostname, &expected_key)
            .await
            .unwrap()
    );
    assert!(
        store
            .observe_ct(&source, 1, &allocation.hostname, &expected_key)
            .await
            .unwrap()
    );
    assert!(matches!(
        store
            .observe_ct(&source, 3, &allocation.hostname, &expected_key)
            .await,
        Err(StoreError::Conflict)
    ));
    assert!(
        !store
            .observe_ct(&source, 2, &allocation.hostname, &"b".repeat(64))
            .await
            .unwrap()
    );
    let alerts: i64 = sqlx::query_scalar("SELECT count(*) FROM ct_alerts WHERE source=$1")
        .bind(&source)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(alerts, 1);
    assert!(store.ct_feed_lag_seconds(&source).await.unwrap().unwrap() < 15);
}
