//! Local high-water witness kept outside PostgreSQL backups.

use crate::{Store, StoreError};
use fs4::{FileExt, TryLockError};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub struct RestoreWitness {
    path: PathBuf,
}

impl RestoreWitness {
    pub fn new(path: PathBuf) -> Result<Self, io::Error> {
        if !path.is_absolute() || path.file_name().is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid witness path",
            ));
        }
        Ok(Self { path })
    }

    pub async fn verify_and_advance(&self, store: &Store) -> Result<(), WitnessError> {
        let lock_path = self.path.with_extension("lock");
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
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
        let revision = store.restore_revision().await?;
        let prior = read_revision(&self.path)?;
        if prior.is_none() && (revision != 1 || !store.restore_pristine().await?) {
            return Err(WitnessError::Missing);
        }
        if prior.is_some_and(|value| value > revision) {
            return Err(WitnessError::StaleDatabase);
        }
        if prior != Some(revision) {
            write_revision(&self.path, revision)?;
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WitnessError {
    #[error("restore witness missing for established database")]
    Missing,
    #[error("database revision below external restore witness")]
    StaleDatabase,
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
                if meta.permissions().mode() & 0o077 != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "witness permissions",
                    ));
                }
            }
            let bytes = fs::read(path)?;
            if bytes.len() > 24 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "witness too large",
                ));
            }
            let value = std::str::from_utf8(&bytes)
                .map_err(|_| io::ErrorKind::InvalidData)?
                .trim_end_matches('\n')
                .parse::<u64>()
                .map_err(|_| io::ErrorKind::InvalidData)?;
            Ok(Some(value))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
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
            options.mode(0o600);
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
