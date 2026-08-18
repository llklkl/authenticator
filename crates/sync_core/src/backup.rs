use std::{
    fmt, fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use tempfile::NamedTempFile;

use crate::{BackupStore, Result, SyncError};

/// Stores already-encrypted KDBX snapshots using atomic local writes.
pub struct FileBackupStore {
    directory: PathBuf,
    retain: usize,
    write_lock: Mutex<()>,
}

impl FileBackupStore {
    pub fn new(directory: PathBuf, retain: usize) -> Result<Self> {
        if retain == 0 {
            return Err(SyncError::InvalidConfiguration);
        }
        Ok(Self {
            directory,
            retain,
            write_lock: Mutex::new(()),
        })
    }

    fn backup_paths(&self) -> Result<Vec<PathBuf>> {
        let mut paths = fs::read_dir(&self.directory)
            .map_err(|_| SyncError::Backup)?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "kdbx")
            })
            .collect::<Vec<_>>();
        paths.sort_unstable();
        Ok(paths)
    }

    fn rotate(&self) -> Result<()> {
        let paths = self.backup_paths()?;
        let excess = paths.len().saturating_sub(self.retain);
        for path in paths.into_iter().take(excess) {
            fs::remove_file(path).map_err(|_| SyncError::Backup)?;
        }
        Ok(())
    }
}

impl fmt::Debug for FileBackupStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileBackupStore")
            .field("directory", &"[REDACTED]")
            .field("retain", &self.retain)
            .finish()
    }
}

impl BackupStore for FileBackupStore {
    fn store(&self, encrypted_snapshot: &[u8]) -> Result<()> {
        let _guard = self.write_lock.lock().map_err(|_| SyncError::Backup)?;
        fs::create_dir_all(&self.directory).map_err(|_| SyncError::Backup)?;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| SyncError::Backup)?
            .as_nanos();
        let mut temporary =
            NamedTempFile::new_in(&self.directory).map_err(|_| SyncError::Backup)?;
        temporary
            .write_all(encrypted_snapshot)
            .and_then(|_| temporary.as_file().sync_all())
            .map_err(|_| SyncError::Backup)?;
        let destination = self.directory.join(format!("snapshot-{timestamp}.kdbx"));
        temporary
            .persist(destination)
            .map_err(|_| SyncError::Backup)?;
        sync_directory(&self.directory)?;
        self.rotate()
    }
}

fn sync_directory(path: &Path) -> Result<()> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| SyncError::Backup)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retains_only_the_newest_encrypted_snapshots() {
        let directory = tempfile::tempdir().unwrap();
        let store = FileBackupStore::new(directory.path().to_owned(), 2).unwrap();
        store.store(b"encrypted-one").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1));
        store.store(b"encrypted-two").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1));
        store.store(b"encrypted-three").unwrap();
        let paths = store.backup_paths().unwrap();
        assert_eq!(paths.len(), 2);
        assert!(
            paths
                .iter()
                .any(|path| fs::read(path).unwrap() == b"encrypted-three")
        );
    }

    #[test]
    fn debug_redacts_backup_path() {
        let store = FileBackupStore::new(PathBuf::from("private/location"), 10).unwrap();
        assert!(!format!("{store:?}").contains("private/location"));
    }
}
