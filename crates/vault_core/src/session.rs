use std::{
    fmt,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    EntrySecretField, KdbxDatabase, KdbxEngine, KdbxEntryRecord, OtpCode, QuickUnlockEnrollment,
    Result, VaultEntry, VaultError, prepare_quick_unlock, unseal_quick_unlock,
};

/// An unlocked, file-backed vault. Decrypted contents and the master password stay in Rust.
/// Every mutation is serialized to a sibling temporary file and atomically replaces the KDBX.
pub struct FileVaultSession {
    path: PathBuf,
    password: Zeroizing<String>,
    database: KdbxDatabase,
    baseline_sha256: [u8; 32],
    engine: KdbxEngine,
}

impl fmt::Debug for FileVaultSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileVaultSession")
            .field("path", &"[REDACTED]")
            .field("password", &"[REDACTED]")
            .field("database", &self.database)
            .finish()
    }
}

impl FileVaultSession {
    pub fn create(path: impl AsRef<Path>, root_name: &str, password: String) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if password.is_empty() || path.exists() {
            return Err(VaultError::VaultWrite);
        }
        let engine = KdbxEngine;
        let database = engine.create(root_name)?;
        let encrypted = engine.save(&database, &password)?;
        atomic_write(&path, &encrypted)?;
        Ok(Self {
            path,
            password: Zeroizing::new(password),
            database,
            baseline_sha256: sha256(&encrypted),
            engine,
        })
    }

    pub fn open(path: impl AsRef<Path>, password: String) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let encrypted = Zeroizing::new(fs::read(&path).map_err(|_| VaultError::VaultRead)?);
        let engine = KdbxEngine;
        let database = engine.open(&encrypted, &password)?;
        Ok(Self {
            path,
            password: Zeroizing::new(password),
            database,
            baseline_sha256: sha256(&encrypted),
            engine,
        })
    }

    /// Validate an external KDBX and atomically install it at an app-owned path.
    /// The source is never modified and an existing destination is never overwritten.
    pub fn import(
        source: impl AsRef<Path>,
        destination: impl AsRef<Path>,
        password: String,
    ) -> Result<Self> {
        let source = source.as_ref();
        let destination = destination.as_ref().to_path_buf();
        if destination.exists() {
            return Err(VaultError::VaultWrite);
        }
        let encrypted = Zeroizing::new(fs::read(source).map_err(|_| VaultError::VaultRead)?);
        let engine = KdbxEngine;
        let database = engine.open(&encrypted, &password)?;
        atomic_write(&destination, &encrypted)?;
        Ok(Self {
            path: destination,
            password: Zeroizing::new(password),
            database,
            baseline_sha256: sha256(&encrypted),
            engine,
        })
    }

    pub fn open_with_quick_unlock(
        path: impl AsRef<Path>,
        workspace_id: Uuid,
        envelope: &[u8],
        key: &[u8],
    ) -> Result<Self> {
        let password = unseal_quick_unlock(envelope, workspace_id, key)?;
        Self::open(path, password.to_string())
    }

    pub fn prepare_quick_unlock(
        &self,
        workspace_id: Uuid,
        existing_keyring: Option<&[u8]>,
    ) -> Result<QuickUnlockEnrollment> {
        prepare_quick_unlock(&self.password, workspace_id, existing_keyring)
    }

    pub fn entries(&self) -> Vec<KdbxEntryRecord> {
        self.engine.entries(&self.database)
    }

    pub fn add_entry(&mut self, entry: &VaultEntry) -> Result<Uuid> {
        self.mutate(|engine, database| engine.add_entry(database, entry))?;
        Ok(entry.id)
    }

    pub fn add_entries(&mut self, entries: &[VaultEntry]) -> Result<()> {
        self.mutate(|engine, database| {
            for entry in entries {
                engine.add_entry(database, entry)?;
            }
            Ok(())
        })
    }

    pub fn update_entry(&mut self, entry: &VaultEntry) -> Result<()> {
        self.mutate(|engine, database| engine.update_entry(database, entry))
    }

    pub fn remove_entry(&mut self, id: Uuid) -> Result<()> {
        self.mutate(|engine, database| engine.remove_entry(database, id))
    }

    pub fn reveal_field(&self, id: Uuid, field: EntrySecretField) -> Result<Zeroizing<String>> {
        self.engine.reveal_field(&self.database, id, field)
    }

    pub fn current_otp(&self, id: Uuid, unix_seconds: i64) -> Result<OtpCode> {
        self.engine
            .otp_config(&self.database, id)?
            .code_at(unix_seconds)
    }

    pub fn otp_config(&self, id: Uuid) -> Result<crate::OtpConfig> {
        self.engine.otp_config(&self.database, id)
    }

    pub fn merge_encrypted_snapshots(
        &self,
        local: &[u8],
        remote: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.engine.merge_encrypted(local, remote, &self.password)
    }

    /// Return the encrypted file for synchronization. No decrypted value is exposed.
    pub fn encrypted_snapshot(&self) -> Result<Zeroizing<Vec<u8>>> {
        let encrypted = Zeroizing::new(fs::read(&self.path).map_err(|_| VaultError::VaultRead)?);
        if sha256(&encrypted) != self.baseline_sha256 {
            return Err(VaultError::VaultRead);
        }
        Ok(encrypted)
    }

    /// Install an already-verified synchronized snapshot after validating the vault key.
    pub fn install_synced_snapshot(&mut self, encrypted: &[u8]) -> Result<()> {
        let database = self.engine.open(encrypted, &self.password)?;
        self.backup_current_file()?;
        atomic_write(&self.path, encrypted)?;
        self.database = database;
        self.baseline_sha256 = sha256(encrypted);
        Ok(())
    }

    fn mutate(
        &mut self,
        mutation: impl FnOnce(&KdbxEngine, &mut KdbxDatabase) -> Result<()>,
    ) -> Result<()> {
        let disk_bytes = Zeroizing::new(fs::read(&self.path).map_err(|_| VaultError::VaultRead)?);
        let mut working = if sha256(&disk_bytes) == self.baseline_sha256 {
            self.database.clone()
        } else {
            let mut disk_database = self.engine.open(&disk_bytes, &self.password)?;
            self.engine.merge(&mut disk_database, &self.database)?;
            disk_database
        };
        mutation(&self.engine, &mut working)?;
        let encrypted = self.engine.save(&working, &self.password)?;

        self.backup_bytes(&disk_bytes)?;
        atomic_write(&self.path, &encrypted)?;
        self.database = working;
        self.baseline_sha256 = sha256(&encrypted);
        Ok(())
    }

    fn backup_current_file(&self) -> Result<()> {
        let bytes = Zeroizing::new(fs::read(&self.path).map_err(|_| VaultError::VaultRead)?);
        self.backup_bytes(&bytes)
    }

    fn backup_bytes(&self, encrypted: &[u8]) -> Result<()> {
        let file_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(VaultError::VaultWrite)?;
        let backup_path = self.path.with_file_name(format!("{file_name}.bak"));
        atomic_write(&backup_path, encrypted)
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or(VaultError::VaultWrite)?;
    fs::create_dir_all(parent).map_err(|_| VaultError::VaultWrite)?;
    let mut temporary = NamedTempFile::new_in(parent).map_err(|_| VaultError::VaultWrite)?;
    temporary
        .write_all(bytes)
        .and_then(|()| temporary.flush())
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|_| VaultError::VaultWrite)?;
    temporary
        .persist(path)
        .map_err(|_| VaultError::VaultWrite)?;
    sync_directory(parent)?;
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| VaultError::VaultWrite)
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EntryKind, OtpConfig};

    fn entry(title: &str) -> VaultEntry {
        VaultEntry::new(
            EntryKind::Login,
            title.into(),
            "alice".into(),
            Zeroizing::new("password".into()),
            "https://example.com".into(),
            Zeroizing::new("notes".into()),
            vec!["test".into()],
            Some(
                OtpConfig::from_uri(
                    "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example",
                )
                .unwrap(),
            ),
            1,
        )
    }

    #[test]
    fn persists_crud_and_reopens_after_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("personal.kdbx");
        let mut session =
            FileVaultSession::create(&path, "Personal", "master password".into()).unwrap();
        let mut value = entry("Original");
        session.add_entry(&value).unwrap();
        assert!(path.with_file_name("personal.kdbx.bak").exists());

        value.title = "Updated".into();
        value.modified_at_unix_ms = 2;
        session.update_entry(&value).unwrap();
        drop(session);

        let mut reopened = FileVaultSession::open(&path, "master password".into()).unwrap();
        assert_eq!(reopened.entries()[0].title, "Updated");
        assert_eq!(
            &*reopened
                .reveal_field(value.id, EntrySecretField::Password)
                .unwrap(),
            "password"
        );
        assert_eq!(reopened.current_otp(value.id, 0).unwrap().value.len(), 6);
        reopened.remove_entry(value.id).unwrap();
        assert!(reopened.entries().is_empty());
    }

    #[test]
    fn rejects_wrong_password_and_existing_create_target() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("personal.kdbx");
        FileVaultSession::create(&path, "Personal", "master password".into()).unwrap();
        assert!(matches!(
            FileVaultSession::open(&path, "wrong".into()),
            Err(VaultError::KdbxOpen)
        ));
        assert!(matches!(
            FileVaultSession::create(&path, "Personal", "other".into()),
            Err(VaultError::VaultWrite)
        ));
    }

    #[test]
    fn merges_an_external_change_before_local_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("personal.kdbx");
        let mut first =
            FileVaultSession::create(&path, "Personal", "master password".into()).unwrap();
        let mut second = FileVaultSession::open(&path, "master password".into()).unwrap();
        first.add_entry(&entry("First device")).unwrap();
        second.add_entry(&entry("Second device")).unwrap();

        let reopened = FileVaultSession::open(&path, "master password".into()).unwrap();
        let titles: Vec<_> = reopened
            .entries()
            .into_iter()
            .map(|entry| entry.title)
            .collect();
        assert!(titles.contains(&"First device".to_owned()));
        assert!(titles.contains(&"Second device".to_owned()));
    }

    #[test]
    fn validates_a_synced_snapshot_before_replacing_local_file() {
        let directory = tempfile::tempdir().unwrap();
        let first_path = directory.path().join("first.kdbx");
        let second_path = directory.path().join("second.kdbx");
        let mut first =
            FileVaultSession::create(&first_path, "First", "same password".into()).unwrap();
        let mut second =
            FileVaultSession::create(&second_path, "Second", "same password".into()).unwrap();
        second.add_entry(&entry("Remote")).unwrap();
        let snapshot = second.encrypted_snapshot().unwrap();
        first.install_synced_snapshot(&snapshot).unwrap();
        assert_eq!(first.entries()[0].title, "Remote");

        let before = fs::read(&first_path).unwrap();
        assert!(first.install_synced_snapshot(b"not a kdbx").is_err());
        assert_eq!(fs::read(&first_path).unwrap(), before);
    }

    #[test]
    fn imports_only_after_validation_without_overwriting_destination() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.kdbx");
        let destination = directory.path().join("internal").join("imported.kdbx");
        FileVaultSession::create(&source, "Imported", "master password".into()).unwrap();

        assert!(FileVaultSession::import(&source, &destination, "wrong".into()).is_err());
        assert!(!destination.exists());
        let imported =
            FileVaultSession::import(&source, &destination, "master password".into()).unwrap();
        assert!(imported.entries().is_empty());
        assert!(destination.exists());
        assert!(matches!(
            FileVaultSession::import(&source, &destination, "master password".into()),
            Err(VaultError::VaultWrite)
        ));
    }
}
