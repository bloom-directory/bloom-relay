//! Remote restore witness against a real database revision. Run with a
//! disposable PostgreSQL URL in `BLOOM_RELAY_TEST_DATABASE_URL`.

use bloom_relay_store::{
    RemoteRevision, RemoteWitness, RemoteWrite, RestoreWitness, Store, WitnessError, WitnessFuture,
};
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use uuid::Uuid;

/// In-memory stand-in for the S3 object: a revision with a version counter
/// playing the ETag, and the same compare-and-swap rule.
#[derive(Default)]
struct FakeRemote {
    object: Mutex<Option<(u64, u64)>>,
    reads: AtomicUsize,
    writes: AtomicUsize,
    conflict_next_write: AtomicBool,
}

impl FakeRemote {
    fn holding(revision: u64) -> Self {
        let remote = Self::default();
        *remote.object.lock().unwrap() = Some((revision, 1));
        remote
    }

    fn revision(&self) -> Option<u64> {
        self.object.lock().unwrap().map(|(revision, _)| revision)
    }
}

impl RemoteWitness for FakeRemote {
    fn read(&self) -> WitnessFuture<'_, Option<RemoteRevision>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let current = *self.object.lock().unwrap();
        Box::pin(async move {
            Ok(current.map(|(revision, version)| RemoteRevision {
                revision,
                version_tag: version.to_string(),
            }))
        })
    }

    fn write<'a>(
        &'a self,
        revision: u64,
        replacing: Option<&'a RemoteRevision>,
    ) -> WitnessFuture<'a, RemoteWrite> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let mut object = self.object.lock().unwrap();
            if self.conflict_next_write.swap(false, Ordering::SeqCst) {
                // Another writer got there first.
                let version = object.map_or(1, |(_, version)| version + 1);
                *object = Some((object.map_or(0, |(value, _)| value), version));
                return Ok(RemoteWrite::Conflict);
            }
            let current_tag = object.map(|(_, version)| version.to_string());
            if current_tag.as_deref() != replacing.map(|value| value.version_tag.as_str()) {
                return Ok(RemoteWrite::Conflict);
            }
            let version = object.map_or(1, |(_, version)| version + 1);
            *object = Some((revision, version));
            Ok(RemoteWrite::Written(RemoteRevision {
                revision,
                version_tag: version.to_string(),
            }))
        })
    }
}

fn local_path() -> PathBuf {
    std::env::temp_dir().join(format!("bloom-relay-remote-witness-{}", Uuid::new_v4()))
}

fn write_local(path: &PathBuf, revision: u64) {
    std::fs::write(path, format!("{revision}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn read_local(path: &PathBuf) -> u64 {
    std::fs::read_to_string(path)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

fn cleanup(path: &PathBuf) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(path.with_extension("lock"));
}

async fn store() -> Option<Store> {
    let url = std::env::var("BLOOM_RELAY_TEST_DATABASE_URL").ok()?;
    let store = Store::connect(&url).await.unwrap();
    // An established database: at least one security transition recorded.
    store
        .allocate(Uuid::new_v4(), [3u8; 32], "test-shard")
        .await
        .unwrap();
    Some(store)
}

#[tokio::test]
async fn a_replacement_host_starts_from_the_remote_witness() {
    let Some(store) = store().await else { return };
    let revision = store.restore_revision().await.unwrap();
    let remote = Arc::new(FakeRemote::holding(revision));
    let path = local_path();

    // No local file, but the remote witness vouches for this database.
    let witness = RestoreWitness::new(path.clone())
        .unwrap()
        .with_remote(remote.clone());
    witness.verify_and_advance(&store).await.unwrap();
    assert!(read_local(&path) >= revision);

    // Later transitions advance both copies.
    store
        .allocate(Uuid::new_v4(), [4u8; 32], "test-shard")
        .await
        .unwrap();
    witness.verify_and_advance(&store).await.unwrap();
    let advanced = remote.revision().unwrap();
    assert!(advanced > revision);
    assert_eq!(read_local(&path), advanced);
    cleanup(&path);
}

#[tokio::test]
async fn a_whole_host_rollback_below_the_remote_witness_fails_closed() {
    let Some(store) = store().await else { return };
    let revision = store.restore_revision().await.unwrap();
    // The remote witness saw more than this database holds: the database
    // and the local file were both restored from an older image.
    let remote = Arc::new(FakeRemote::holding(revision + 1_000_000));
    let path = local_path();
    write_local(&path, revision);
    let witness = RestoreWitness::new(path.clone())
        .unwrap()
        .with_remote(remote.clone());
    assert!(matches!(
        witness.verify_and_advance(&store).await,
        Err(WitnessError::StaleDatabase)
    ));
    assert_eq!(remote.writes.load(Ordering::SeqCst), 0);
    assert_eq!(read_local(&path), revision);
    cleanup(&path);
}

#[tokio::test]
async fn an_established_database_with_no_witness_anywhere_fails_closed() {
    let Some(store) = store().await else { return };
    let remote = Arc::new(FakeRemote::default());
    let path = local_path();
    let witness = RestoreWitness::new(path.clone())
        .unwrap()
        .with_remote(remote.clone());
    assert!(matches!(
        witness.verify_and_advance(&store).await,
        Err(WitnessError::Missing)
    ));
    assert_eq!(remote.revision(), None);
    assert!(!path.exists());
    cleanup(&path);
}

#[tokio::test]
async fn enabling_the_remote_witness_publishes_the_local_revision() {
    let Some(store) = store().await else { return };
    let revision = store.restore_revision().await.unwrap();
    let remote = Arc::new(FakeRemote::default());
    let path = local_path();
    write_local(&path, revision);
    let witness = RestoreWitness::new(path.clone())
        .unwrap()
        .with_remote(remote.clone());
    witness.verify_and_advance(&store).await.unwrap();
    let published = remote.revision().unwrap();
    assert!(published >= revision);
    assert_eq!(read_local(&path), published);
    cleanup(&path);
}

#[tokio::test]
async fn a_lost_write_race_rereads_and_retries() {
    let Some(store) = store().await else { return };
    let revision = store.restore_revision().await.unwrap();
    let remote = Arc::new(FakeRemote::holding(revision));
    let path = local_path();
    write_local(&path, revision);
    let witness = RestoreWitness::new(path.clone())
        .unwrap()
        .with_remote(remote.clone());
    store
        .allocate(Uuid::new_v4(), [5u8; 32], "test-shard")
        .await
        .unwrap();
    remote.conflict_next_write.store(true, Ordering::SeqCst);
    witness.verify_and_advance(&store).await.unwrap();
    assert!(remote.writes.load(Ordering::SeqCst) >= 2);
    assert!(remote.revision().unwrap() > revision);
    cleanup(&path);
}

#[tokio::test]
async fn an_unchanged_revision_needs_no_remote_call() {
    let Some(store) = store().await else { return };
    let revision = store.restore_revision().await.unwrap();
    let remote = Arc::new(FakeRemote::holding(revision));
    let path = local_path();
    write_local(&path, revision);
    let witness = RestoreWitness::new(path.clone())
        .unwrap()
        .with_remote(remote.clone());
    witness.verify_and_advance(&store).await.unwrap();
    let reads = remote.reads.load(Ordering::SeqCst);
    // Other tests share the database and may advance it; only a quiet
    // interval proves the cache.
    if store.restore_revision().await.unwrap() == remote.revision().unwrap() {
        witness.verify_and_advance(&store).await.unwrap();
        if store.restore_revision().await.unwrap() == remote.revision().unwrap() {
            assert_eq!(remote.reads.load(Ordering::SeqCst), reads);
        }
    }
    cleanup(&path);
}
