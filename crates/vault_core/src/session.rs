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
    EntrySecretField, KdbxContentSnapshot, KdbxDatabase, KdbxEngine, KdbxEntryRecord,
    MAX_ATTACHMENT_BYTES, OtpCode, PasswordHealthPolicy, PasswordHealthReport,
    QuickUnlockEnrollment, Result, VaultEntry, VaultError, prepare_quick_unlock,
    unseal_quick_unlock,
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

    pub fn content_snapshot(&self) -> KdbxContentSnapshot {
        self.engine.content_snapshot(&self.database)
    }

    pub fn add_entry(&mut self, entry: &VaultEntry) -> Result<Uuid> {
        self.mutate(|engine, database| engine.add_entry(database, entry))?;
        Ok(entry.id)
    }

    pub fn add_entry_to_group(&mut self, group_id: Uuid, entry: &VaultEntry) -> Result<Uuid> {
        self.mutate(|engine, database| engine.add_entry_to_group(database, group_id, entry))?;
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

    pub fn create_group(&mut self, parent_id: Uuid, name: &str) -> Result<Uuid> {
        self.mutate(|engine, database| engine.create_group(database, parent_id, name))
    }

    pub fn create_group_with_icon(
        &mut self,
        parent_id: Uuid,
        name: &str,
        icon_id: Option<u32>,
    ) -> Result<Uuid> {
        self.mutate(|engine, database| {
            engine.create_group_with_icon(database, parent_id, name, icon_id)
        })
    }

    pub fn rename_group(&mut self, group_id: Uuid, name: &str) -> Result<()> {
        self.mutate(|engine, database| engine.rename_group(database, group_id, name))
    }

    pub fn set_group_icon(&mut self, group_id: Uuid, icon_id: Option<u32>) -> Result<()> {
        self.mutate(|engine, database| engine.set_group_icon(database, group_id, icon_id))
    }

    pub fn custom_icon(&self, icon_id: Uuid) -> Result<Vec<u8>> {
        self.engine.custom_icon(&self.database, icon_id)
    }

    pub fn set_entry_favorite(&mut self, entry_id: Uuid, favorite: bool) -> Result<()> {
        self.mutate(|engine, database| engine.set_entry_favorite(database, entry_id, favorite))
    }

    /// Read an attachment from disk inside Rust and persist it as protected KDBX data.
    pub fn add_attachment_from_path(
        &mut self,
        entry_id: Uuid,
        attachment_name: &str,
        source_path: impl AsRef<Path>,
        replace: bool,
    ) -> Result<()> {
        let source_path = source_path.as_ref();
        let metadata = fs::metadata(source_path).map_err(|_| VaultError::VaultRead)?;
        if !metadata.is_file()
            || metadata.len() > u64::try_from(MAX_ATTACHMENT_BYTES).unwrap_or(u64::MAX)
        {
            return Err(VaultError::AttachmentLimitExceeded);
        }
        let bytes = Zeroizing::new(fs::read(source_path).map_err(|_| VaultError::VaultRead)?);
        self.mutate(|engine, database| {
            engine.add_attachment(database, entry_id, attachment_name, bytes.to_vec(), replace)
        })
    }

    /// Export an attachment through a sibling temporary file and atomic rename.
    pub fn export_attachment(
        &self,
        entry_id: Uuid,
        attachment_name: &str,
        destination_path: impl AsRef<Path>,
        overwrite: bool,
    ) -> Result<()> {
        let bytes = self
            .engine
            .attachment(&self.database, entry_id, attachment_name)?;
        atomic_export(destination_path.as_ref(), &bytes, overwrite)
    }

    pub fn rename_attachment(
        &mut self,
        entry_id: Uuid,
        old_name: &str,
        new_name: &str,
    ) -> Result<()> {
        self.mutate(|engine, database| {
            engine.rename_attachment(database, entry_id, old_name, new_name)
        })
    }

    pub fn remove_attachment(&mut self, entry_id: Uuid, name: &str) -> Result<()> {
        self.mutate(|engine, database| engine.remove_attachment(database, entry_id, name))
    }

    pub fn audit_password_health(&self, policy: PasswordHealthPolicy) -> PasswordHealthReport {
        self.engine.audit_password_health(&self.database, policy)
    }

    pub fn move_group(&mut self, group_id: Uuid, destination_id: Uuid) -> Result<()> {
        self.mutate(|engine, database| engine.move_group(database, group_id, destination_id))
    }

    pub fn move_entry(&mut self, entry_id: Uuid, destination_id: Uuid) -> Result<()> {
        self.mutate(|engine, database| engine.move_entry(database, entry_id, destination_id))
    }

    pub fn enable_recycle_bin(&mut self) -> Result<Uuid> {
        self.mutate(|engine, database| engine.enable_recycle_bin(database))
    }

    pub fn trash_entry(&mut self, entry_id: Uuid) -> Result<()> {
        self.mutate(|engine, database| engine.trash_entry(database, entry_id))
    }

    pub fn trash_group(&mut self, group_id: Uuid) -> Result<()> {
        self.mutate(|engine, database| engine.trash_group(database, group_id))
    }

    pub fn restore_entry(&mut self, entry_id: Uuid) -> Result<()> {
        self.mutate(|engine, database| engine.restore_entry(database, entry_id))
    }

    pub fn restore_group(&mut self, group_id: Uuid) -> Result<()> {
        self.mutate(|engine, database| engine.restore_group(database, group_id))
    }

    pub fn remove_group_permanently(&mut self, group_id: Uuid) -> Result<()> {
        self.mutate(|engine, database| engine.remove_group_permanently(database, group_id))
    }

    pub fn empty_recycle_bin(&mut self) -> Result<()> {
        self.mutate(|engine, database| engine.empty_recycle_bin(database))
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

    fn mutate<T>(
        &mut self,
        mutation: impl FnOnce(&KdbxEngine, &mut KdbxDatabase) -> Result<T>,
    ) -> Result<T> {
        let disk_bytes = Zeroizing::new(fs::read(&self.path).map_err(|_| VaultError::VaultRead)?);
        let mut working = if sha256(&disk_bytes) == self.baseline_sha256 {
            self.database.clone()
        } else {
            let mut disk_database = self.engine.open(&disk_bytes, &self.password)?;
            self.engine.merge(&mut disk_database, &self.database)?;
            disk_database
        };
        let output = mutation(&self.engine, &mut working)?;
        let encrypted = self.engine.save(&working, &self.password)?;

        self.backup_bytes(&disk_bytes)?;
        atomic_write(&self.path, &encrypted)?;
        self.database = working;
        self.baseline_sha256 = sha256(&encrypted);
        Ok(output)
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

fn atomic_export(path: &Path, bytes: &[u8], overwrite: bool) -> Result<()> {
    let parent = path.parent().ok_or(VaultError::VaultWrite)?;
    if !parent.is_dir() || (path.exists() && !overwrite) {
        return Err(VaultError::VaultWrite);
    }
    let mut temporary = NamedTempFile::new_in(parent).map_err(|_| VaultError::VaultWrite)?;
    temporary
        .write_all(bytes)
        .and_then(|()| temporary.flush())
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|_| VaultError::VaultWrite)?;
    if overwrite {
        temporary
            .persist(path)
            .map_err(|_| VaultError::VaultWrite)?;
    } else {
        temporary
            .persist_noclobber(path)
            .map_err(|_| VaultError::VaultWrite)?;
    }
    sync_directory(parent)
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
    fn imports_and_atomically_exports_protected_attachments() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("personal.kdbx");
        let source = directory.path().join("source.txt");
        fs::write(&source, b"attachment secret").unwrap();
        let mut session =
            FileVaultSession::create(&path, "Personal", "master password".into()).unwrap();
        let value = entry("Attachment");
        session.add_entry(&value).unwrap();
        session
            .add_attachment_from_path(value.id, "source.txt", &source, false)
            .unwrap();

        let destination = directory.path().join("exported.txt");
        session
            .export_attachment(value.id, "source.txt", &destination, false)
            .unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"attachment secret");
        assert_eq!(
            session.export_attachment(value.id, "source.txt", &destination, false),
            Err(VaultError::VaultWrite)
        );

        session
            .rename_attachment(value.id, "source.txt", "renamed.txt")
            .unwrap();
        drop(session);
        let mut reopened = FileVaultSession::open(&path, "master password".into()).unwrap();
        assert_eq!(reopened.entries()[0].attachments[0].name, "renamed.txt");
        reopened.remove_attachment(value.id, "renamed.txt").unwrap();
        assert!(reopened.entries()[0].attachments.is_empty());
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
