//! High-water witness kept outside PostgreSQL backups.
//!
//! The local file catches a database restored beneath this host. An optional
//! remote copy (see [`crate::s3_witness`]) survives losing or rolling back the
//! whole host: a replacement host with no local file starts only from a
//! database at or above the remote revision.

use crate::{Store, StoreError};
use fs4::{FileExt, TryLockError};
use std::{
    fs,
    future::Future,
    io::{self, Write},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

/// Conditional writes that lose a race re-read and retry this many times.
const REMOTE_ATTEMPTS: usize = 4;

pub type WitnessFuture<'a, T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send + 'a>>;

/// A revision read from the remote witness, with the opaque version tag the
/// next conditional write must name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteRevision {
    pub revision: u64,
    pub version_tag: String,
}

#[derive(Debug, Eq, PartialEq)]
pub enum RemoteWrite {
    Written(RemoteRevision),
    /// Another writer changed the witness since it was read.
    Conflict,
}

/// Off-host witness storage with compare-and-swap writes.
pub trait RemoteWitness: Send + Sync {
    /// The current revision, or `None` when no witness was ever written.
    fn read(&self) -> WitnessFuture<'_, Option<RemoteRevision>>;

    /// Write `revision` only if the witness is still `replacing`, or still
    /// absent when `replacing` is `None`.
    fn write<'a>(
        &'a self,
        revision: u64,
        replacing: Option<&'a RemoteRevision>,
    ) -> WitnessFuture<'a, RemoteWrite>;
}

pub struct RestoreWitness {
    path: PathBuf,
    remote: Option<Arc<dyn RemoteWitness>>,
    /// Last remote revision this process read or wrote. While the database
    /// and local file both still equal it, acknowledging needs no remote
    /// call; any movement re-reads before writing.
    remote_seen: Mutex<Option<RemoteRevision>>,
}

impl RestoreWitness {
    pub fn new(path: PathBuf) -> Result<Self, io::Error> {
        if !path.is_absolute() || path.file_name().is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid witness path",
            ));
        }
        Ok(Self {
            path,
            remote: None,
            remote_seen: Mutex::new(None),
        })
    }

    pub fn with_remote(mut self, remote: Arc<dyn RemoteWitness>) -> Self {
        self.remote = Some(remote);
        self
    }

    /// The local witness at `path`, plus the S3 witness when
    /// `BLOOM_RELAY_RESTORE_WITNESS_S3_BUCKET` is configured.
    pub async fn from_env(path: PathBuf) -> Result<Self, io::Error> {
        let witness = Self::new(path)?;
        Ok(match crate::s3_witness::S3Witness::from_env().await? {
            Some(remote) => witness.with_remote(Arc::new(remote)),
            None => witness,
        })
    }

    pub async fn verify_and_advance(&self, store: &Store) -> Result<(), WitnessError> {
        let lock_path = self.path.with_extension("lock");
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o660);
        }
        let lock = options.open(lock_path)?;
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                match FileExt::try_lock(&lock) {
                    Ok(()) => break Ok(()),
                    Err(TryLockError::WouldBlock) => {
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await
                    }
                    Err(TryLockError::Error(error)) => break Err(error),
                }
            }
        })
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        for _ in 0..REMOTE_ATTEMPTS {
            let revision = store.restore_revision().await?;
            let local = read_revision(&self.path)?;
            let remote = match &self.remote {
                None => None,
                Some(remote) => {
                    let seen = self.remote_seen.lock().map_err(poisoned)?.clone();
                    match seen {
                        Some(seen) if seen.revision == revision && local == Some(revision) => {
                            return Ok(());
                        }
                        _ => Some(remote.read().await?),
                    }
                }
            };
            let remote_revision = remote.as_ref().and_then(|value| value.as_ref());
            // A replacement host has no local file; the remote witness then
            // stands in for it. With neither, only a new database may start.
            let prior = local.max(remote_revision.map(|value| value.revision));
            if prior.is_none() && (revision != 1 || !store.restore_pristine().await?) {
                return Err(WitnessError::Missing);
            }
            if prior.is_some_and(|value| value > revision) {
                return Err(WitnessError::StaleDatabase);
            }
            if let Some(backend) = &self.remote {
                let current = if remote_revision.map(|value| value.revision) == Some(revision) {
                    remote_revision.cloned()
                } else {
                    match backend.write(revision, remote_revision).await? {
                        RemoteWrite::Written(written) => Some(written),
                        RemoteWrite::Conflict => {
                            *self.remote_seen.lock().map_err(poisoned)? = None;
                            continue;
                        }
                    }
                };
                *self.remote_seen.lock().map_err(poisoned)? = current;
            }
            if local != Some(revision) {
                write_revision(&self.path, revision)?;
            }
            return Ok(());
        }
        Err(WitnessError::RemoteContention)
    }
}

fn poisoned<T>(_: std::sync::PoisonError<T>) -> io::Error {
    io::Error::other("witness state lock poisoned")
}

#[derive(Debug, thiserror::Error)]
pub enum WitnessError {
    #[error("restore witness missing for established database")]
    Missing,
    #[error("database revision below external restore witness")]
    StaleDatabase,
    #[error("remote restore witness kept changing during a write")]
    RemoteContention,
    #[error("restore witness storage unavailable")]
    Io(#[from] io::Error),
    #[error("database unavailable")]
    Store(#[from] StoreError),
}

fn read_revision(path: &Path) -> io::Result<Option<u64>> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.file_type().is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "witness is not a file",
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if meta.permissions().mode() & 0o007 != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "witness permissions",
                    ));
                }
            }
            parse_revision(&fs::read(path)?).map(Some)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// A witness body: one decimal revision, optionally newline-terminated.
pub(crate) fn parse_revision(bytes: &[u8]) -> io::Result<u64> {
    if bytes.len() > 24 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "witness too large",
        ));
    }
    std::str::from_utf8(bytes)
        .map_err(|_| io::ErrorKind::InvalidData)?
        .trim_end_matches('\n')
        .parse::<u64>()
        .map_err(|_| io::ErrorKind::InvalidData.into())
}

fn write_revision(path: &Path, revision: u64) -> io::Result<()> {
    let parent = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
    let temporary = parent.join(format!(".bloom-relay-witness-{}", Uuid::new_v4()));
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o660);
        }
        let mut file = options.open(&temporary)?;
        writeln!(file, "{revision}")?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}
