use std::{
    fmt, fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use tempfile::NamedTempFile;

use crate::{BackupStore, Result, SyncError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupOrigin {
    RemoteBeforeMerge,
    LocalBeforeInstall,
    LocalBeforeRestore,
    Legacy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupDescriptor {
    pub id: String,
    pub created_at_unix_ms: i64,
    pub encrypted_size: u64,
    pub origin: BackupOrigin,
}

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

    pub fn store_labeled(&self, snapshot: &[u8], origin: BackupOrigin) -> Result<BackupDescriptor> {
        let _guard = self.write_lock.lock().map_err(|_| SyncError::Backup)?;
        fs::create_dir_all(&self.directory).map_err(|_| SyncError::Backup)?;
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| SyncError::Backup)?;
        let created_at_unix_ms =
            i64::try_from(duration.as_millis()).map_err(|_| SyncError::Backup)?;
        let label = match origin {
            BackupOrigin::RemoteBeforeMerge => "remote-before-merge",
            BackupOrigin::LocalBeforeInstall => "local-before-install",
            BackupOrigin::LocalBeforeRestore => "local-before-restore",
            BackupOrigin::Legacy => "legacy",
        };
        let id = format!(
            "{created_at_unix_ms}-{label}-{}.kdbx",
            duration.subsec_nanos()
        );
        let mut temporary =
            NamedTempFile::new_in(&self.directory).map_err(|_| SyncError::Backup)?;
        temporary
            .write_all(snapshot)
            .and_then(|_| temporary.as_file().sync_all())
            .map_err(|_| SyncError::Backup)?;
        temporary
            .persist(self.directory.join(&id))
            .map_err(|_| SyncError::Backup)?;
        sync_directory(&self.directory)?;
        self.rotate()?;
        Ok(BackupDescriptor {
            id,
            created_at_unix_ms,
            encrypted_size: u64::try_from(snapshot.len()).unwrap_or(u64::MAX),
            origin,
        })
    }

    pub fn list(&self) -> Result<Vec<BackupDescriptor>> {
        if !self.directory.exists() {
            return Ok(Vec::new());
        }
        let mut records = fs::read_dir(&self.directory)
            .map_err(|_| SyncError::Backup)?
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| {
                let path = entry.path();
                let id = path.file_name()?.to_str()?.to_owned();
                if path.extension().is_none_or(|extension| extension != "kdbx") {
                    return None;
                }
                let metadata = entry.metadata().ok()?;
                let created_at_unix_ms = metadata
                    .modified()
                    .ok()?
                    .duration_since(UNIX_EPOCH)
                    .ok()
                    .and_then(|value| i64::try_from(value.as_millis()).ok())?;
                let origin = if id.contains("remote-before-merge") {
                    BackupOrigin::RemoteBeforeMerge
                } else if id.contains("local-before-install") {
                    BackupOrigin::LocalBeforeInstall
                } else if id.contains("local-before-restore") {
                    BackupOrigin::LocalBeforeRestore
                } else {
                    BackupOrigin::Legacy
                };
                Some(BackupDescriptor {
                    id,
                    created_at_unix_ms,
                    encrypted_size: metadata.len(),
                    origin,
                })
            })
            .collect::<Vec<_>>();
        records.sort_by_key(|record| std::cmp::Reverse(record.created_at_unix_ms));
        Ok(records)
    }

    pub fn read(&self, id: &str) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        if Path::new(id).file_name().and_then(|value| value.to_str()) != Some(id)
            || !id.ends_with(".kdbx")
        {
            return Err(SyncError::Backup);
        }
        fs::read(self.directory.join(id))
            .map(zeroize::Zeroizing::new)
            .map_err(|_| SyncError::Backup)
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
        self.store_labeled(encrypted_snapshot, BackupOrigin::RemoteBeforeMerge)
            .map(|_| ())
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

    #[test]
    fn lists_and_reads_labeled_backups_without_path_traversal() {
        let directory = tempfile::tempdir().unwrap();
        let store = FileBackupStore::new(directory.path().to_owned(), 3).unwrap();
        let descriptor = store
            .store_labeled(b"encrypted", BackupOrigin::LocalBeforeRestore)
            .unwrap();
        assert_eq!(
            store.list().unwrap()[0].origin,
            BackupOrigin::LocalBeforeRestore
        );
        assert_eq!(&*store.read(&descriptor.id).unwrap(), b"encrypted");
        assert_eq!(store.read("../outside.kdbx"), Err(SyncError::Backup));
    }
}
