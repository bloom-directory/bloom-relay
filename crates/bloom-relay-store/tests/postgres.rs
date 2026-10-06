use bloom_relay_protocol::{AcmeEnvironment, CertificateMetadata};
use bloom_relay_store::{DnsJobScope, RestoreWitness, Store, StoreError, WitnessError};
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
    let value = "a".repeat(43);
    let ensured = store
        .ensure_challenge_value(id, dns_generation, &value)
        .await
        .unwrap();
    assert!(
        !store
            .challenge_value_ready(id, &value, ensured.revision)
            .await
            .unwrap()
    );
    assert!(
        store
            .mark_challenge_reconciled(id, ensured.revision)
            .await
            .unwrap()
    );
    assert!(
        store
            .challenge_value_ready(id, &value, ensured.revision)
            .await
            .unwrap()
    );
    let retire_operation = Uuid::new_v4();
    store.retire(id, retire_operation).await.unwrap();
    store.retire(id, retire_operation).await.unwrap();
    assert!(
        !store
            .challenge_value_ready(id, &value, ensured.revision)
            .await
            .unwrap()
    );
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
async fn acme_registration_is_restricted_to_configured_environment() {
    let Ok(url) = std::env::var("BLOOM_RELAY_TEST_DATABASE_URL") else {
        return;
    };
    let production = Store::connect(&url).await.unwrap();
    let staging = production
        .clone()
        .with_acme_environment(AcmeEnvironment::Staging);
    let production_uri = "https://acme-v02.api.letsencrypt.org/acme/acct/123";
    let staging_uri = "https://acme-staging-v02.api.letsencrypt.org/acme/acct/456";

    let production_id = production
        .allocate(Uuid::new_v4(), [21; 32], "test-shard")
        .await
        .unwrap()
        .installation_id;
    production
        .register_acme_account(production_id, production_uri)
        .await
        .unwrap();
    assert!(matches!(
        production
            .register_acme_account(production_id, staging_uri)
            .await,
        Err(StoreError::InvalidRequest)
    ));
    assert_eq!(
        production
            .dns_identity(production_id)
            .await
            .unwrap()
            .unwrap()
            .1,
        production_uri
    );

    let staging_id = staging
        .allocate(Uuid::new_v4(), [22; 32], "test-shard")
        .await
        .unwrap()
        .installation_id;
    staging
        .register_acme_account(staging_id, staging_uri)
        .await
        .unwrap();
    assert!(matches!(
        staging
            .register_acme_account(staging_id, production_uri)
            .await,
        Err(StoreError::InvalidRequest)
    ));
    assert!(matches!(
        staging
            .register_acme_account(staging_id, "https://example.com/acme/acct/456")
            .await,
        Err(StoreError::InvalidRequest)
    ));
    let overlong = format!(
        "{}{}",
        AcmeEnvironment::Staging.account_uri_prefix(),
        "1".repeat(
            bloom_relay_protocol::MAX_ACME_ACCOUNT_URI_LEN + 1
                - AcmeEnvironment::Staging.account_uri_prefix().len()
        )
    );
    assert!(matches!(
        staging.register_acme_account(staging_id, &overlong).await,
        Err(StoreError::InvalidRequest)
    ));
    assert_eq!(
        staging.dns_identity(staging_id).await.unwrap().unwrap().1,
        staging_uri
    );
}

#[tokio::test]
async fn abandoned_pending_allocations_and_challenge_values_are_swept_without_reuse() {
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
    let value = "z".repeat(43);
    let ensured = store
        .ensure_challenge_value(id, generation, &value)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE challenge_values SET expires_at=now()-interval '1 second' WHERE installation_id=$1",
    )
    .bind(id)
    .execute(store.pool())
    .await
    .unwrap();
    assert!(store.expire_challenge_values(100).await.unwrap() >= 1);
    assert!(
        !store
            .challenge_value_ready(id, &value, ensured.revision)
            .await
            .unwrap()
    );
    let (revision, values) = store.challenge_target(id).await.unwrap();
    assert!(values.is_empty());
    assert_eq!(revision, ensured.revision + 1);
    let jobs: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM outbox WHERE installation_id=$1 AND kind='reconcile_txt'",
    )
    .bind(id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(jobs, 2, "one reconciliation per membership change");
}

#[tokio::test]
async fn challenge_values_form_a_bounded_refreshable_set_with_revisioned_readiness() {
    let Ok(url) = std::env::var("BLOOM_RELAY_TEST_DATABASE_URL") else {
        return;
    };
    let store = Store::connect(&url).await.unwrap();
    let allocation = store
        .allocate(Uuid::new_v4(), [5u8; 32], "challenge-set-test")
        .await
        .unwrap();
    let id = allocation.installation_id;
    let a = "a".repeat(43);
    let b = "b".repeat(43);
    let c = "c".repeat(43);
    // Only a dns_ready installation may publish challenges.
    assert!(matches!(
        store.ensure_challenge_value(id, 1, &a).await,
        Err(StoreError::Conflict)
    ));
    store
        .register_acme_account(id, "https://acme-v02.api.letsencrypt.org/acme/acct/123")
        .await
        .unwrap();
    store.mark_dns_ready(id).await.unwrap();
    // Only a current DNS-challenge credential may change the set.
    assert!(matches!(
        store.ensure_challenge_value(id, 1, &a).await,
        Err(StoreError::Unauthorized)
    ));
    let (generation, _) = store
        .issue_bearer(
            id,
            Uuid::new_v4(),
            "dns_challenge",
            Sha256::digest(b"challenge-set-token").into(),
            3600,
        )
        .await
        .unwrap();
    assert!(matches!(
        store
            .ensure_challenge_value(id, generation, "not-a-dns-01-value")
            .await,
        Err(StoreError::InvalidRequest)
    ));

    // Adding a value advances the revision; refreshing it does not, so a
    // client refreshing while it waits never resets readiness.
    let first = store
        .ensure_challenge_value(id, generation, &a)
        .await
        .unwrap();
    assert!(
        store
            .mark_challenge_reconciled(id, first.revision)
            .await
            .unwrap()
    );
    let refreshed = store
        .ensure_challenge_value(id, generation, &a)
        .await
        .unwrap();
    assert_eq!(refreshed.revision, first.revision);
    assert!(refreshed.expires_at_ms >= first.expires_at_ms);
    assert!(
        store
            .challenge_value_ready(id, &a, first.revision)
            .await
            .unwrap()
    );

    // An interrupted attempt's value and its replacement coexist.
    let second = store
        .ensure_challenge_value(id, generation, &b)
        .await
        .unwrap();
    assert_eq!(second.revision, first.revision + 1);
    assert_eq!(
        store.challenge_target(id).await.unwrap(),
        (second.revision, vec![a.clone(), b.clone()])
    );
    // The set changed, so neither value is ready until the new revision is
    // observed; a worker that finished the old revision cannot claim it.
    assert!(
        !store
            .challenge_value_ready(id, &a, first.revision)
            .await
            .unwrap()
    );
    assert!(
        !store
            .mark_challenge_reconciled(id, first.revision)
            .await
            .unwrap()
    );
    assert!(
        store
            .mark_challenge_reconciled(id, second.revision)
            .await
            .unwrap()
    );
    assert!(
        store
            .challenge_value_ready(id, &b, second.revision)
            .await
            .unwrap()
    );
    // A value the client never ensured is not ready, whatever the revision.
    assert!(
        !store
            .challenge_value_ready(id, &c, second.revision)
            .await
            .unwrap()
    );

    // A third distinct value is refused while two are live; refreshing one of
    // them still works at capacity.
    assert!(matches!(
        store.ensure_challenge_value(id, generation, &c).await,
        Err(StoreError::Conflict)
    ));
    assert_eq!(
        store
            .ensure_challenge_value(id, generation, &b)
            .await
            .unwrap()
            .revision,
        second.revision
    );

    // Once a value lapses it stops counting, before any sweep: the third value
    // joins, the lapsed one leaves the published set, and a lapsed value is
    // never reported ready.
    sqlx::query("UPDATE challenge_values SET expires_at=now()-interval '1 second' WHERE installation_id=$1 AND txt_value=$2")
        .bind(id).bind(&a).execute(store.pool()).await.unwrap();
    assert!(
        !store
            .challenge_value_ready(id, &a, second.revision)
            .await
            .unwrap()
    );
    // A lapsed value stays in the published set, at the same revision, until
    // an ensure or the sweep removes it (other tests sweep concurrently), and
    // is never reported ready. Membership and revision always move together.
    let (revision, published) = store.challenge_target(id).await.unwrap();
    if published.contains(&a) {
        assert_eq!(
            (revision, published),
            (second.revision, vec![a.clone(), b.clone()])
        );
    } else {
        assert_eq!(
            (revision, published),
            (second.revision + 1, vec![b.clone()])
        );
    }
    let third = store
        .ensure_challenge_value(id, generation, &c)
        .await
        .unwrap();
    assert_eq!(
        store.challenge_target(id).await.unwrap(),
        (third.revision, vec![b.clone(), c.clone()])
    );
    // Re-ensuring a lapsed value republishes it as a new member.
    sqlx::query("UPDATE challenge_values SET expires_at=now()-interval '1 second' WHERE installation_id=$1 AND txt_value=$2")
        .bind(id).bind(&b).execute(store.pool()).await.unwrap();
    let revived = store
        .ensure_challenge_value(id, generation, &b)
        .await
        .unwrap();
    assert!(revived.revision > third.revision);

    let jobs: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM outbox WHERE installation_id=$1 AND kind='reconcile_txt'",
    )
    .bind(id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    let (final_revision, _) = store.challenge_target(id).await.unwrap();
    assert_eq!(
        jobs as u64, final_revision,
        "every membership change queues its own reconciliation"
    );

    // An out-of-range revision is refused rather than wrapped to a negative
    // BIGINT, and a revoked credential can no longer change the set.
    assert!(matches!(
        store.challenge_value_ready(id, &c, u64::MAX).await,
        Err(StoreError::InvalidRequest)
    ));
    sqlx::query("UPDATE scoped_bearer_credentials SET revoked_at=now() WHERE installation_id=$1 AND scope='dns_challenge'")
        .bind(id).execute(store.pool()).await.unwrap();
    assert!(matches!(
        store.ensure_challenge_value(id, generation, &c).await,
        Err(StoreError::Unauthorized)
    ));
}

#[tokio::test]
async fn epoch_metric_aggregates_decode_empty_and_populated_results_as_f64() {
    let Ok(url) = std::env::var("BLOOM_RELAY_TEST_DATABASE_URL") else {
        return;
    };
    let store = Store::connect(&url).await.unwrap();

    let empty_min: Option<f64> = sqlx::query_scalar(
        "SELECT min(value)::double precision FROM (SELECT extract(epoch FROM now()-now()) AS value WHERE false) values",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    let empty_max: Option<f64> = sqlx::query_scalar(
        "SELECT max(value)::double precision FROM (SELECT extract(epoch FROM now()-now()) AS value WHERE false) values",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(empty_min, None);
    assert_eq!(empty_max, None);

    let value_min: Option<f64> = sqlx::query_scalar(
        "SELECT min(value)::double precision FROM (VALUES (1::numeric), (2::numeric)) values(value)",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    let value_max: Option<f64> = sqlx::query_scalar(
        "SELECT max(value)::double precision FROM (VALUES (1::numeric), (2::numeric)) values(value)",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(value_min, Some(1.0));
    assert_eq!(value_max, Some(2.0));
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
    assert!(
        store
            .claim_job(&second_placement, DnsJobScope::Serving)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .claim_job(&first_placement, DnsJobScope::Challenge)
            .await
            .unwrap()
            .is_none()
    );
    let claim = || async {
        store
            .claim_job(&first_placement, DnsJobScope::Serving)
            .await
            .unwrap()
    };
    let first_job = claim().await.unwrap();
    assert_eq!(first_job.job.installation_id, id);
    let job_id = first_job.job.id;
    // A claim holds the job for its whole attempt: no other worker takes it,
    // however long the attempt runs.
    assert!(claim().await.is_none(), "a held job is not claimed twice");
    // An attempt that ends without recording an outcome (worker crash,
    // dropped connection) frees the job for an immediate retry.
    drop(first_job);
    let retried = claim().await.expect("a released job is claimable again");
    assert_eq!(retried.job.id, job_id);
    // Deferring records the attempt: 5 s after the first, doubling.
    let schedule = || async {
        sqlx::query_as::<_, (i32, f64)>(
            "SELECT attempts, extract(epoch FROM next_attempt_at-now())::double precision FROM outbox WHERE id=$1",
        )
        .bind(job_id)
        .fetch_one(store.pool())
        .await
        .unwrap()
    };
    let make_due = || async {
        sqlx::query("UPDATE outbox SET next_attempt_at=now() WHERE id=$1")
            .bind(job_id)
            .execute(store.pool())
            .await
            .unwrap();
    };
    retried.defer(&store).await.unwrap();
    let (attempts, retry_in) = schedule().await;
    assert_eq!(attempts, 1);
    assert!((3.0..=5.5).contains(&retry_in), "{retry_in}");
    assert!(
        claim().await.is_none(),
        "a deferred job waits for its retry"
    );
    make_due().await;
    // The backoff runs from the end of the attempt, however long it took.
    let slow = claim().await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    slow.defer(&store).await.unwrap();
    let (attempts, retry_in) = schedule().await;
    assert_eq!(attempts, 2);
    assert!((9.0..=10.5).contains(&retry_in), "{retry_in}");
    make_due().await;
    // A held job also holds its installation lock, so a placement move waits
    // for the attempt to finish.
    let held = claim().await.unwrap();
    let mut mover = store.pool().begin().await.unwrap();
    sqlx::query("SET LOCAL lock_timeout='200ms'")
        .execute(&mut *mover)
        .await
        .unwrap();
    assert!(
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(id.to_string())
            .execute(&mut *mover)
            .await
            .is_err(),
        "the installation lock is held for the attempt"
    );
    mover.rollback().await.unwrap();
    held.complete(&store).await.unwrap();
    let completed: bool =
        sqlx::query_scalar("SELECT completed_at IS NOT NULL FROM outbox WHERE id=$1")
            .bind(job_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert!(completed);
    assert!(claim().await.is_none());
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
    assert!(
        store
            .claim_job(&first_placement, DnsJobScope::Serving)
            .await
            .unwrap()
            .is_none()
    );
    let job = store
        .claim_job(&second_placement, DnsJobScope::Serving)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(job.job.installation_id, id);
    assert_eq!(job.job.kind, "publish_name");
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
    Store::connect_runtime_with_witness(&url, path.clone())
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
    // A DNS attempt claimed before the witness goes stale records nothing.
    let placement = format!("witness-{}", Uuid::new_v4().simple());
    guarded
        .allocate(Uuid::new_v4(), [7u8; 32], &placement)
        .await
        .unwrap();
    let claimed = guarded
        .claim_job(&placement, DnsJobScope::Serving)
        .await
        .unwrap()
        .unwrap();
    let job_id = claimed.job.id;
    std::fs::write(&path, format!("{}\n", advanced + 1_000_000)).unwrap();
    assert!(matches!(
        claimed.defer(&guarded).await,
        Err(StoreError::Witness(_))
    ));
    let (attempts, due): (i32, bool) =
        sqlx::query_as("SELECT attempts, next_attempt_at<=now() FROM outbox WHERE id=$1")
            .bind(job_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(
        (attempts, due),
        (0, true),
        "a refused deferral is rolled back"
    );
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

/// Every restore-fence trigger fires at commit. Mid-transaction fence updates
/// let concurrent security transitions deadlock on the fence row (40P01).
#[tokio::test]
async fn restore_fence_triggers_advance_at_commit() {
    let Ok(url) = std::env::var("BLOOM_RELAY_TEST_DATABASE_URL") else {
        return;
    };
    let store = Store::connect(&url).await.unwrap();
    // Two transitions taking the installation row and the fence in opposite
    // orders. With the fence advanced mid-transaction, the first holds the
    // fence and waits for the row while the second holds the row and waits
    // for the fence: PostgreSQL aborts one with 40P01. Deferred to commit,
    // the second commits first and the first follows.
    let id = store
        .allocate(Uuid::new_v4(), [11u8; 32], "test-shard")
        .await
        .unwrap()
        .installation_id;
    let before = store.restore_revision().await.unwrap();
    let audit = "INSERT INTO security_audit(installation_id,event) VALUES ($1,'fence_probe')";
    let touch = "UPDATE installations SET generation=generation WHERE installation_id=$1";
    let mut first = store.pool().begin().await.unwrap();
    let mut second = store.pool().begin().await.unwrap();
    sqlx::query(audit)
        .bind(id)
        .execute(&mut *first)
        .await
        .unwrap();
    sqlx::query(touch)
        .bind(id)
        .execute(&mut *second)
        .await
        .unwrap();
    let first = async move {
        sqlx::query(touch).bind(id).execute(&mut *first).await?;
        first.commit().await
    };
    let second = async move {
        sqlx::query(audit).bind(id).execute(&mut *second).await?;
        second.commit().await
    };
    let (first, second) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(first, second)
    })
    .await
    .expect("opposite-order transitions finish");
    first.unwrap();
    second.unwrap();
    assert!(store.restore_revision().await.unwrap() >= before + 2);

    let triggers: Vec<(String, bool, bool)> = sqlx::query_as(
        "SELECT tgname::text, tgdeferrable, tginitdeferred FROM pg_trigger
         WHERE NOT tgisinternal AND tgname LIKE '%restore_fence' ORDER BY 1",
    )
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(
        triggers,
        [
            "ct_alert_restore_fence",
            "ct_checkpoint_restore_fence",
            "ct_health_alert_restore_fence",
            "security_audit_restore_fence",
        ]
        .map(|name| (name.to_owned(), true, true))
    );
}

/// A Broker that slept through its renewal window renews on wake: the newest
/// credential may renew within the grace period after expiry, but an expired
/// credential never opens a tunnel, and a superseded or long-expired one
/// never renews.
#[tokio::test]
async fn the_newest_credential_renews_within_the_grace_period_after_expiry() {
    let Ok(url) = std::env::var("BLOOM_RELAY_TEST_DATABASE_URL") else {
        return;
    };
    let store = Store::connect(&url).await.unwrap();
    let id = store
        .allocate(Uuid::new_v4(), [21u8; 32], "test-shard")
        .await
        .unwrap()
        .installation_id;
    store
        .register_acme_account(id, "https://acme-v02.api.letsencrypt.org/acme/acct/123")
        .await
        .unwrap();
    store.mark_dns_ready(id).await.unwrap();
    let token = |byte: char| byte.to_string().repeat(43);
    let hash = |token: &str| -> [u8; 32] { Sha256::digest(token.as_bytes()).into() };
    let expire = |generation: u64, ago: &'static str| {
        let pool = store.pool().clone();
        async move {
            sqlx::query(
                "UPDATE scoped_bearer_credentials SET expires_at=now()-$3::text::interval \
                 WHERE installation_id=$1 AND scope='tunnel' AND generation=$2",
            )
            .bind(id)
            .bind(generation as i64)
            .bind(ago)
            .execute(&pool)
            .await
            .unwrap();
        }
    };

    // Asleep through the window: expired an hour ago, still the newest.
    let (generation, _) = store
        .issue_bearer(id, Uuid::new_v4(), "tunnel", hash(&token('a')), 3600)
        .await
        .unwrap();
    expire(generation, "1 hour").await;
    assert_eq!(
        store
            .authenticate_bearer(id, "tunnel", &token('a'))
            .await
            .unwrap(),
        None,
        "an expired credential never opens a tunnel"
    );
    let (renewed, _) = store
        .renew_bearer(
            id,
            Uuid::new_v4(),
            "tunnel",
            generation,
            &token('a'),
            hash(&token('b')),
        )
        .await
        .unwrap();
    assert!(renewed > generation);
    assert_eq!(
        store
            .authenticate_bearer(id, "tunnel", &token('b'))
            .await
            .unwrap(),
        Some(renewed)
    );
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_audit WHERE installation_id=$1 AND event='credential_renewed_after_expiry'",
    )
    .bind(id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(audited, 1);
    // The renewal revoked the old credential: it cannot renew twice.
    assert!(matches!(
        store
            .renew_bearer(
                id,
                Uuid::new_v4(),
                "tunnel",
                generation,
                &token('a'),
                hash(&token('c'))
            )
            .await,
        Err(StoreError::Unauthorized)
    ));

    // Past the grace period nothing renews.
    expire(renewed, "8 days").await;
    assert!(matches!(
        store
            .renew_bearer(
                id,
                Uuid::new_v4(),
                "tunnel",
                renewed,
                &token('b'),
                hash(&token('d'))
            )
            .await,
        Err(StoreError::Unauthorized)
    ));

    // A newer credential supersedes an older unrevoked one, even in grace.
    let (older, _) = store
        .issue_bearer(id, Uuid::new_v4(), "tunnel", hash(&token('e')), 3600)
        .await
        .unwrap();
    let (_newer, _) = store
        .issue_bearer(id, Uuid::new_v4(), "tunnel", hash(&token('f')), 3600)
        .await
        .unwrap();
    expire(older, "1 hour").await;
    assert!(matches!(
        store
            .renew_bearer(
                id,
                Uuid::new_v4(),
                "tunnel",
                older,
                &token('e'),
                hash(&token('g'))
            )
            .await,
        Err(StoreError::Unauthorized)
    ));
}

#[tokio::test]
async fn consumed_bootstrap_challenges_stay_counted_until_pruned() {
    let Ok(url) = std::env::var("BLOOM_RELAY_TEST_DATABASE_URL") else {
        return;
    };
    let store = Store::connect(&url).await.unwrap();
    let octets = Uuid::new_v4().into_bytes();
    let busy: std::net::IpAddr = [10, octets[0], octets[1], octets[2]].into();
    let enrolled: std::net::IpAddr = [10, octets[3], octets[4], octets[5]].into();
    let nonce = |i: usize| format!("{}-{i}", Uuid::new_v4());

    // Ten per source per minute; consuming them does not free the quota.
    let issued: Vec<String> = (0..10).map(nonce).collect();
    for value in &issued {
        assert!(store.create_bootstrap_challenge(value, busy).await.unwrap());
    }
    assert!(
        !store
            .create_bootstrap_challenge(&nonce(10), busy)
            .await
            .unwrap()
    );
    for value in &issued {
        assert!(
            store
                .consume_bootstrap_challenge(value, busy)
                .await
                .unwrap()
        );
        assert!(
            !store
                .consume_bootstrap_challenge(value, busy)
                .await
                .unwrap()
        );
    }
    assert!(
        !store
            .create_bootstrap_challenge(&nonce(11), busy)
            .await
            .unwrap()
    );

    // Twenty completed enrollments per source per day.
    for i in 0..20 {
        sqlx::query("INSERT INTO bootstrap_challenges(nonce,source_ip,expires_at,created_at,consumed_at) VALUES ($1,$2::inet,now()-interval '119 minutes',now()-interval '2 hours',now()-interval '2 hours')")
            .bind(nonce(i)).bind(enrolled.to_string()).execute(store.pool()).await.unwrap();
    }
    assert!(
        !store
            .create_bootstrap_challenge(&nonce(20), enrolled)
            .await
            .unwrap()
    );

    // History older than two days and expired replay nonces are pruned.
    sqlx::query("UPDATE bootstrap_challenges SET created_at=now()-interval '3 days' WHERE source_ip=$1::inet")
        .bind(enrolled.to_string()).execute(store.pool()).await.unwrap();
    let allocation = store
        .allocate(Uuid::new_v4(), [6u8; 32], "bootstrap-prune-test")
        .await
        .unwrap();
    let stale = nonce(30);
    assert!(
        store
            .consume_nonce(allocation.installation_id, &stale)
            .await
            .unwrap()
    );
    sqlx::query("UPDATE used_nonces SET expires_at=now()-interval '1 second' WHERE nonce=$1")
        .bind(&stale)
        .execute(store.pool())
        .await
        .unwrap();
    while store.prune_bootstrap_and_nonces(10_000).await.unwrap() > 0 {}
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM bootstrap_challenges WHERE source_ip=$1::inet")
            .bind(enrolled.to_string())
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(remaining, 0);
    assert!(
        store
            .create_bootstrap_challenge(&nonce(21), enrolled)
            .await
            .unwrap()
    );
    let kept: i64 =
        sqlx::query_scalar("SELECT count(*) FROM bootstrap_challenges WHERE source_ip=$1::inet")
            .bind(busy.to_string())
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(kept, 10);
    let nonces: i64 = sqlx::query_scalar("SELECT count(*) FROM used_nonces WHERE nonce=$1")
        .bind(&stale)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(nonces, 0);
}

#[tokio::test]
async fn concurrent_dns_renewal_and_challenge_ensure_never_deadlock() {
    let Ok(url) = std::env::var("BLOOM_RELAY_TEST_DATABASE_URL") else {
        return;
    };
    let store = Store::connect(&url).await.unwrap();
    let id = store
        .allocate(Uuid::new_v4(), [9u8; 32], "lock-order-test")
        .await
        .unwrap()
        .installation_id;
    store
        .register_acme_account(id, "https://acme-v02.api.letsencrypt.org/acme/acct/123")
        .await
        .unwrap();
    store.mark_dns_ready(id).await.unwrap();
    let mut token = "r".repeat(43);
    let (mut generation, _) = store
        .issue_bearer(
            id,
            Uuid::new_v4(),
            "dns_challenge",
            Sha256::digest(token.as_bytes()).into(),
            3600,
        )
        .await
        .unwrap();
    // Renewal locks the credential and the installation; ensure locks both
    // too. Each round races them; a lock-order inversion surfaces as a
    // PostgreSQL deadlock error (StoreError::Unavailable) from one of them.
    let value = "v".repeat(43);
    for round in 0..25u8 {
        let next = format!("{}{round:02}", "n".repeat(41));
        let renew = store.renew_bearer(
            id,
            Uuid::new_v4(),
            "dns_challenge",
            generation,
            &token,
            Sha256::digest(next.as_bytes()).into(),
        );
        let ensure = store.ensure_challenge_value(id, generation, &value);
        let (renewed, ensured) = tokio::join!(renew, ensure);
        let (renewed_generation, _) = renewed.expect("renewal must not deadlock");
        assert!(
            matches!(ensured, Ok(_) | Err(StoreError::Unauthorized)),
            "ensure must succeed or see the revocation, not fail: {ensured:?}"
        );
        generation = renewed_generation;
        token = next;
    }
}
