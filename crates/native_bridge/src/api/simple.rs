use std::{
    collections::BTreeMap,
    fmt,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock, Mutex, RwLock},
};

use flutter_rust_bridge::frb;
use sync_core::{FileBackupStore, SyncEngine, SyncError, VaultMerger, WebDavProvider};
use uuid::Uuid;
use vault_core::{
    EntryKind, EntrySecretField, FileVaultSession, OtpConfig, VaultEntry, VaultError,
    quick_unlock_key, remove_quick_unlock,
};
use zeroize::Zeroizing;

static OTP_SESSIONS: LazyLock<RwLock<OtpSessions>> =
    LazyLock::new(|| RwLock::new(OtpSessions::default()));
static VAULT_SESSIONS: LazyLock<RwLock<VaultSessions>> =
    LazyLock::new(|| RwLock::new(VaultSessions::default()));

#[frb(ignore)]
#[derive(Default)]
struct OtpSessions {
    next_id: u64,
    configs: BTreeMap<u64, OtpConfig>,
}

#[frb(ignore)]
#[derive(Default)]
struct VaultSessions {
    next_id: u64,
    sessions: BTreeMap<u64, Arc<Mutex<FileVaultSession>>>,
    paths: BTreeMap<PathBuf, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpHandle {
    pub id: u64,
    pub issuer: String,
    pub account: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpPreview {
    pub code: String,
    pub valid_for_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultHandle {
    pub id: u64,
}

pub struct QuickUnlockEnrollment {
    pub envelope: Vec<u8>,
    pub updated_keyring: Vec<u8>,
}

impl fmt::Debug for QuickUnlockEnrollment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QuickUnlockEnrollment")
            .field("envelope", &"[REDACTED]")
            .field("updated_keyring", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct QuickUnlockRequest {
    pub workspace_id: String,
    pub path: String,
    pub envelope: Vec<u8>,
}

impl fmt::Debug for QuickUnlockRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QuickUnlockRequest")
            .field("workspace_id", &self.workspace_id)
            .field("path", &"[REDACTED]")
            .field("envelope", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuickUnlockOpened {
    pub workspace_id: String,
    pub handle_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuickUnlockBatchResult {
    pub opened: Vec<QuickUnlockOpened>,
    pub failed_workspace_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultEntryKind {
    Login,
    Otp,
    RecoveryCodes,
    SecureNote,
}

#[derive(Clone, PartialEq, Eq)]
pub struct VaultEntryInput {
    pub kind: VaultEntryKind,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub tags: Vec<String>,
    pub otp_uri: Option<String>,
    /// Keep the existing protected OTP field during an update without exposing its seed.
    pub preserve_existing_otp: bool,
    pub modified_at_unix_ms: i64,
}

impl fmt::Debug for VaultEntryInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultEntryInput")
            .field("kind", &self.kind)
            .field("title", &self.title)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("url", &self.url)
            .field("notes", &"[REDACTED]")
            .field("tags", &self.tags)
            .field("otp_uri", &self.otp_uri.as_ref().map(|_| "[REDACTED]"))
            .field("preserve_existing_otp", &self.preserve_existing_otp)
            .field("modified_at_unix_ms", &self.modified_at_unix_ms)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultEntryView {
    pub id: String,
    pub kind: VaultEntryKind,
    pub title: String,
    pub username: String,
    pub url: String,
    pub has_password: bool,
    pub has_otp: bool,
    pub tags: Vec<String>,
    pub modified_at_unix_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitiveField {
    Password,
    Notes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeError {
    InvalidInput,
    InvalidOtp,
    OtpNotFound,
    VaultNotFound,
    VaultAlreadyOpen,
    EntryNotFound,
    FieldUnavailable,
    WrongPasswordOrInvalidVault,
    FileRead,
    FileWrite,
    SessionUnavailable,
    SyncFailed,
    QuickUnlockFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncResult {
    pub attempts: u32,
    pub merged: bool,
}

/// Create and unlock a new KDBX workspace. Existing files are never overwritten.
pub fn create_vault(
    path: String,
    name: String,
    master_password: String,
) -> Result<VaultHandle, BridgeError> {
    if master_password.chars().count() < 12 {
        return Err(BridgeError::InvalidInput);
    }
    let identity = path_identity(Path::new(&path), false)?;
    let mut sessions = write_vault_sessions()?;
    ensure_path_available(&sessions, &identity)?;
    let session = FileVaultSession::create(&identity, name.trim(), master_password)?;
    insert_vault_session(&mut sessions, identity, session)
}

/// Unlock an existing KDBX workspace. Existing vault passwords have no length policy.
pub fn open_vault(path: String, master_password: String) -> Result<VaultHandle, BridgeError> {
    let identity = path_identity(Path::new(&path), true)?;
    let mut sessions = write_vault_sessions()?;
    ensure_path_available(&sessions, &identity)?;
    let session = FileVaultSession::open(&identity, master_password)?;
    insert_vault_session(&mut sessions, identity, session)
}

/// Return a cryptographically random stable workspace identifier.
#[frb(sync)]
pub fn generate_workspace_id() -> String {
    Uuid::new_v4().to_string()
}

/// Validate and copy an external vault into app-owned storage before opening it.
pub fn import_vault(
    source_path: String,
    destination_path: String,
    name: String,
    master_password: String,
) -> Result<VaultHandle, BridgeError> {
    if name.trim().is_empty() {
        return Err(BridgeError::InvalidInput);
    }
    let source = path_identity(Path::new(&source_path), true)?;
    let destination = path_identity(Path::new(&destination_path), false)?;
    if source == destination {
        return Err(BridgeError::InvalidInput);
    }
    let mut sessions = write_vault_sessions()?;
    ensure_path_available(&sessions, &destination)?;
    let session = FileVaultSession::import(source, &destination, master_password)?;
    insert_vault_session(&mut sessions, destination, session)
}

pub fn prepare_quick_unlock_enrollment(
    handle_id: u64,
    workspace_id: String,
    existing_keyring: Option<Vec<u8>>,
) -> Result<QuickUnlockEnrollment, BridgeError> {
    let workspace_id = parse_uuid(&workspace_id)?;
    let existing_keyring = existing_keyring.map(Zeroizing::new);
    let session = get_vault(handle_id)?;
    let session = session
        .lock()
        .map_err(|_| BridgeError::SessionUnavailable)?;
    let enrollment = session.prepare_quick_unlock(
        workspace_id,
        existing_keyring.as_ref().map(|value| value.as_slice()),
    )?;
    Ok(QuickUnlockEnrollment {
        envelope: enrollment.envelope.to_vec(),
        updated_keyring: enrollment.updated_keyring.to_vec(),
    })
}

pub fn remove_quick_unlock_material(
    workspace_id: String,
    keyring: Vec<u8>,
) -> Result<Vec<u8>, BridgeError> {
    let workspace_id = parse_uuid(&workspace_id)?;
    let keyring = Zeroizing::new(keyring);
    Ok(remove_quick_unlock(&keyring, workspace_id)?.to_vec())
}

/// Unlock multiple independent workspaces after one platform biometric prompt.
/// Individual failures are isolated and reported without exposing their cause.
pub fn open_vaults_with_quick_unlock(
    requests: Vec<QuickUnlockRequest>,
    keyring: Vec<u8>,
) -> Result<QuickUnlockBatchResult, BridgeError> {
    let keyring = Zeroizing::new(keyring);
    let mut sessions = write_vault_sessions()?;
    let mut opened = Vec::new();
    let mut failed_workspace_ids = Vec::new();

    for request in requests {
        let result = (|| {
            let workspace_id = parse_uuid(&request.workspace_id)?;
            let path = path_identity(Path::new(&request.path), true)?;
            ensure_path_available(&sessions, &path)?;
            let key = quick_unlock_key(&keyring, workspace_id)?;
            let session = FileVaultSession::open_with_quick_unlock(
                &path,
                workspace_id,
                &request.envelope,
                &*key,
            )?;
            let handle = insert_vault_session(&mut sessions, path, session)?;
            Ok::<_, BridgeError>(QuickUnlockOpened {
                workspace_id: request.workspace_id.clone(),
                handle_id: handle.id,
            })
        })();
        match result {
            Ok(value) => opened.push(value),
            Err(_) => failed_workspace_ids.push(request.workspace_id),
        }
    }

    Ok(QuickUnlockBatchResult {
        opened,
        failed_workspace_ids,
    })
}

#[frb(sync)]
pub fn close_vault(handle_id: u64) -> Result<(), BridgeError> {
    let mut sessions = write_vault_sessions()?;
    sessions
        .sessions
        .remove(&handle_id)
        .ok_or(BridgeError::VaultNotFound)?;
    sessions.paths.retain(|_, id| *id != handle_id);
    Ok(())
}

/// Drop all decrypted databases and zeroize all stored master passwords.
#[frb(sync)]
pub fn lock_all_vaults() -> Result<(), BridgeError> {
    let mut sessions = write_vault_sessions()?;
    sessions.sessions.clear();
    sessions.paths.clear();
    Ok(())
}

#[frb(sync)]
pub fn list_entries(handle_id: u64) -> Result<Vec<VaultEntryView>, BridgeError> {
    let session = get_vault(handle_id)?;
    let session = session
        .lock()
        .map_err(|_| BridgeError::SessionUnavailable)?;
    Ok(session
        .entries()
        .into_iter()
        .map(|entry| VaultEntryView {
            id: entry.id.to_string(),
            kind: entry.kind.into(),
            title: entry.title,
            username: entry.username,
            url: entry.url,
            has_password: entry.has_password,
            has_otp: entry.has_otp,
            tags: entry.tags,
            modified_at_unix_ms: entry.modified_at_unix_ms,
        })
        .collect())
}

pub fn create_entry(handle_id: u64, input: VaultEntryInput) -> Result<String, BridgeError> {
    let entry = input.into_entry(None, None)?;
    let id = entry.id;
    with_vault_mut(handle_id, |session| session.add_entry(&entry))?;
    Ok(id.to_string())
}

pub fn update_entry(
    handle_id: u64,
    entry_id: String,
    input: VaultEntryInput,
) -> Result<(), BridgeError> {
    let id = parse_uuid(&entry_id)?;
    let session = get_vault(handle_id)?;
    let mut session = session
        .lock()
        .map_err(|_| BridgeError::SessionUnavailable)?;
    let preserved_otp = if input.preserve_existing_otp && input.otp_uri.is_none() {
        Some(session.otp_config(id)?)
    } else {
        None
    };
    let entry = input.into_entry(Some(id), preserved_otp)?;
    session.update_entry(&entry).map_err(BridgeError::from)
}

pub fn delete_entry(handle_id: u64, entry_id: String) -> Result<(), BridgeError> {
    let id = parse_uuid(&entry_id)?;
    with_vault_mut(handle_id, |session| session.remove_entry(id))
}

#[frb(sync)]
pub fn reveal_entry_field(
    handle_id: u64,
    entry_id: String,
    field: SensitiveField,
) -> Result<String, BridgeError> {
    let id = parse_uuid(&entry_id)?;
    let session = get_vault(handle_id)?;
    let session = session
        .lock()
        .map_err(|_| BridgeError::SessionUnavailable)?;
    let value = session.reveal_field(id, field.into())?;
    Ok(value.to_string())
}

#[frb(sync)]
pub fn current_entry_otp(
    handle_id: u64,
    entry_id: String,
    unix_seconds: i64,
) -> Result<OtpPreview, BridgeError> {
    let id = parse_uuid(&entry_id)?;
    let session = get_vault(handle_id)?;
    let session = session
        .lock()
        .map_err(|_| BridgeError::SessionUnavailable)?;
    let code = session.current_otp(id, unix_seconds)?;
    Ok(OtpPreview {
        code: code.value,
        valid_for_seconds: code.valid_for_seconds,
    })
}

pub fn import_otp_to_vault(
    handle_id: u64,
    uri: String,
    modified_at_unix_ms: i64,
) -> Result<String, BridgeError> {
    let configs = if uri.starts_with("otpauth-migration://") {
        OtpConfig::from_migration_uri(&uri)?
    } else {
        vec![OtpConfig::from_uri(&uri)?]
    };
    let entries: Vec<_> = configs
        .into_iter()
        .map(|otp| {
            let title = if otp.issuer().is_empty() {
                otp.account().to_owned()
            } else {
                otp.issuer().to_owned()
            };
            VaultEntry::new(
                EntryKind::Otp,
                title,
                otp.account().to_owned(),
                Zeroizing::new(String::new()),
                String::new(),
                Zeroizing::new(String::new()),
                Vec::new(),
                Some(otp),
                modified_at_unix_ms,
            )
        })
        .collect();
    let id = entries.first().ok_or(BridgeError::InvalidOtp)?.id;
    with_vault_mut(handle_id, |session| session.add_entries(&entries))?;
    Ok(id.to_string())
}

/// Synchronize one unlocked vault using conditional WebDAV writes, encrypted
/// backups, KDBX merge, and post-upload verification.
pub fn sync_webdav(
    handle_id: u64,
    endpoint: String,
    username: String,
    password: String,
    allow_insecure_http: bool,
    backup_directory: String,
) -> Result<SyncResult, BridgeError> {
    let provider = WebDavProvider::new(&endpoint, username, password, allow_insecure_http)?;
    let backups = FileBackupStore::new(PathBuf::from(backup_directory), 10)?;
    let session = get_vault(handle_id)?;
    let mut session = session
        .lock()
        .map_err(|_| BridgeError::SessionUnavailable)?;
    let local = session.encrypted_snapshot()?;
    let outcome = {
        let engine = SyncEngine::new(provider, SessionVaultMerger(&session), backups);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| BridgeError::SyncFailed)?;
        runtime.block_on(engine.synchronize(&local))?
    };
    session.install_synced_snapshot(&outcome.encrypted_bytes)?;
    Ok(SyncResult {
        attempts: u32::try_from(outcome.attempts).map_err(|_| BridgeError::SyncFailed)?,
        merged: outcome.merged,
    })
}

/// Legacy ephemeral OTP import retained for the locked-vault preview flow.
#[frb(sync)]
pub fn import_otp_uri(uri: String) -> Result<OtpHandle, BridgeError> {
    let config = OtpConfig::from_uri(&uri)?;
    let issuer = config.issuer().to_owned();
    let account = config.account().to_owned();
    let mut sessions = OTP_SESSIONS
        .write()
        .map_err(|_| BridgeError::SessionUnavailable)?;
    sessions.next_id = sessions
        .next_id
        .checked_add(1)
        .ok_or(BridgeError::SessionUnavailable)?;
    let id = sessions.next_id;
    sessions.configs.insert(id, config);
    Ok(OtpHandle {
        id,
        issuer,
        account,
    })
}

#[frb(sync)]
pub fn current_otp(handle_id: u64, unix_seconds: i64) -> Result<OtpPreview, BridgeError> {
    let sessions = OTP_SESSIONS
        .read()
        .map_err(|_| BridgeError::SessionUnavailable)?;
    let config = sessions
        .configs
        .get(&handle_id)
        .ok_or(BridgeError::OtpNotFound)?;
    let code = config.code_at(unix_seconds)?;
    Ok(OtpPreview {
        code: code.value,
        valid_for_seconds: code.valid_for_seconds,
    })
}

#[frb(sync)]
pub fn remove_otp(handle_id: u64) -> Result<(), BridgeError> {
    let mut sessions = OTP_SESSIONS
        .write()
        .map_err(|_| BridgeError::SessionUnavailable)?;
    sessions
        .configs
        .remove(&handle_id)
        .ok_or(BridgeError::OtpNotFound)?;
    Ok(())
}

#[frb(init)]
pub fn init_app() {
    flutter_rust_bridge::setup_default_user_utils();
}

impl VaultEntryInput {
    fn into_entry(
        self,
        id: Option<Uuid>,
        preserved_otp: Option<OtpConfig>,
    ) -> Result<VaultEntry, BridgeError> {
        if self.title.trim().is_empty() {
            return Err(BridgeError::InvalidInput);
        }
        let otp = self
            .otp_uri
            .filter(|uri| !uri.trim().is_empty())
            .map(|uri| OtpConfig::from_uri(&uri))
            .transpose()?
            .or(preserved_otp);
        let mut entry = VaultEntry::new(
            self.kind.into(),
            self.title.trim().to_owned(),
            self.username,
            Zeroizing::new(self.password),
            self.url,
            Zeroizing::new(self.notes),
            self.tags,
            otp,
            self.modified_at_unix_ms,
        );
        if let Some(id) = id {
            entry.id = id;
        }
        Ok(entry)
    }
}

fn insert_vault_session(
    sessions: &mut VaultSessions,
    path: PathBuf,
    session: FileVaultSession,
) -> Result<VaultHandle, BridgeError> {
    sessions.next_id = sessions
        .next_id
        .checked_add(1)
        .ok_or(BridgeError::SessionUnavailable)?;
    let id = sessions.next_id;
    sessions.sessions.insert(id, Arc::new(Mutex::new(session)));
    sessions.paths.insert(path, id);
    Ok(VaultHandle { id })
}

fn ensure_path_available(sessions: &VaultSessions, path: &Path) -> Result<(), BridgeError> {
    if sessions.paths.contains_key(path) {
        Err(BridgeError::VaultAlreadyOpen)
    } else {
        Ok(())
    }
}

fn path_identity(path: &Path, must_exist: bool) -> Result<PathBuf, BridgeError> {
    if path.as_os_str().is_empty() {
        return Err(BridgeError::InvalidInput);
    }
    if must_exist {
        return path.canonicalize().map_err(|_| BridgeError::FileRead);
    }
    let parent = path.parent().ok_or(BridgeError::InvalidInput)?;
    let parent = parent.canonicalize().map_err(|_| BridgeError::FileWrite)?;
    let file_name = path.file_name().ok_or(BridgeError::InvalidInput)?;
    Ok(parent.join(file_name))
}

fn parse_uuid(value: &str) -> Result<Uuid, BridgeError> {
    Uuid::parse_str(value).map_err(|_| BridgeError::InvalidInput)
}

fn read_vault_sessions() -> Result<std::sync::RwLockReadGuard<'static, VaultSessions>, BridgeError>
{
    VAULT_SESSIONS
        .read()
        .map_err(|_| BridgeError::SessionUnavailable)
}

fn write_vault_sessions() -> Result<std::sync::RwLockWriteGuard<'static, VaultSessions>, BridgeError>
{
    VAULT_SESSIONS
        .write()
        .map_err(|_| BridgeError::SessionUnavailable)
}

fn get_vault(handle_id: u64) -> Result<Arc<Mutex<FileVaultSession>>, BridgeError> {
    read_vault_sessions()?
        .sessions
        .get(&handle_id)
        .cloned()
        .ok_or(BridgeError::VaultNotFound)
}

fn with_vault_mut<T>(
    handle_id: u64,
    operation: impl FnOnce(&mut FileVaultSession) -> vault_core::Result<T>,
) -> Result<T, BridgeError> {
    let session = get_vault(handle_id)?;
    let mut session = session
        .lock()
        .map_err(|_| BridgeError::SessionUnavailable)?;
    operation(&mut session).map_err(BridgeError::from)
}

struct SessionVaultMerger<'a>(&'a FileVaultSession);

impl VaultMerger for SessionVaultMerger<'_> {
    fn merge(&self, local: &[u8], remote: &[u8]) -> sync_core::Result<Zeroizing<Vec<u8>>> {
        self.0
            .merge_encrypted_snapshots(local, remote)
            .map_err(|_| SyncError::Merge)
    }
}

impl From<EntryKind> for VaultEntryKind {
    fn from(value: EntryKind) -> Self {
        match value {
            EntryKind::Login => Self::Login,
            EntryKind::Otp => Self::Otp,
            EntryKind::RecoveryCodes => Self::RecoveryCodes,
            EntryKind::SecureNote => Self::SecureNote,
        }
    }
}

impl From<VaultEntryKind> for EntryKind {
    fn from(value: VaultEntryKind) -> Self {
        match value {
            VaultEntryKind::Login => Self::Login,
            VaultEntryKind::Otp => Self::Otp,
            VaultEntryKind::RecoveryCodes => Self::RecoveryCodes,
            VaultEntryKind::SecureNote => Self::SecureNote,
        }
    }
}

impl From<SensitiveField> for EntrySecretField {
    fn from(value: SensitiveField) -> Self {
        match value {
            SensitiveField::Password => Self::Password,
            SensitiveField::Notes => Self::Notes,
        }
    }
}

impl From<VaultError> for BridgeError {
    fn from(error: VaultError) -> Self {
        match error {
            VaultError::InvalidOtpUri
            | VaultError::UnsupportedOtpType
            | VaultError::UnsupportedOtpAlgorithm
            | VaultError::InvalidOtpDigits
            | VaultError::InvalidOtpPeriod
            | VaultError::InvalidOtpSecret
            | VaultError::InvalidHotpCounter
            | VaultError::InvalidTimestamp => Self::InvalidOtp,
            VaultError::KdbxOpen | VaultError::InvalidKdbx => Self::WrongPasswordOrInvalidVault,
            VaultError::KdbxSave | VaultError::VaultWrite => Self::FileWrite,
            VaultError::VaultRead => Self::FileRead,
            VaultError::EntryNotFound => Self::EntryNotFound,
            VaultError::FieldUnavailable => Self::FieldUnavailable,
            VaultError::VaultAlreadyOpen => Self::VaultAlreadyOpen,
            VaultError::QuickUnlock => Self::QuickUnlockFailed,
            VaultError::DuplicateWorkspace
            | VaultError::WorkspaceNotFound
            | VaultError::InvalidWorkspace => Self::InvalidInput,
        }
    }
}

impl From<SyncError> for BridgeError {
    fn from(_: SyncError) -> Self {
        Self::SyncFailed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static VAULT_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn input() -> VaultEntryInput {
        VaultEntryInput {
            kind: VaultEntryKind::Login,
            title: "Example".into(),
            username: "alice".into(),
            password: "entry-password".into(),
            url: "https://example.com".into(),
            notes: "private notes".into(),
            tags: vec!["personal".into()],
            otp_uri: Some(
                "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example".into(),
            ),
            preserve_existing_otp: false,
            modified_at_unix_ms: 1,
        }
    }

    #[test]
    fn persistent_vault_api_crud_and_lock() {
        let _test_guard = VAULT_TEST_LOCK.lock().unwrap();
        lock_all_vaults().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.kdbx");
        let handle = create_vault(
            path.to_string_lossy().into_owned(),
            "Personal".into(),
            "a sufficiently long password".into(),
        )
        .unwrap();
        let id = create_entry(handle.id, input()).unwrap();
        assert_eq!(list_entries(handle.id).unwrap().len(), 1);
        assert_eq!(
            reveal_entry_field(handle.id, id.clone(), SensitiveField::Password).unwrap(),
            "entry-password"
        );
        assert_eq!(
            current_entry_otp(handle.id, id.clone(), 0)
                .unwrap()
                .code
                .len(),
            6
        );
        delete_entry(handle.id, id).unwrap();
        assert!(list_entries(handle.id).unwrap().is_empty());
        lock_all_vaults().unwrap();
        assert_eq!(list_entries(handle.id), Err(BridgeError::VaultNotFound));
    }

    #[test]
    fn sensitive_input_debug_is_redacted() {
        let debug = format!("{:?}", input());
        assert!(!debug.contains("entry-password"));
        assert!(!debug.contains("private notes"));
        assert!(!debug.contains("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn imported_seed_stays_behind_opaque_handle() {
        let handle = import_otp_uri(
            "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example".into(),
        )
        .unwrap();
        assert_eq!(handle.issuer, "Example");
        assert_eq!(handle.account, "alice");
        let preview = current_otp(handle.id, 0).unwrap();
        assert_eq!(preview.code.len(), 6);
        remove_otp(handle.id).unwrap();
    }

    #[test]
    fn imports_into_internal_path_and_quick_unlocks_multiple_workspaces() {
        let _test_guard = VAULT_TEST_LOCK.lock().unwrap();
        lock_all_vaults().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let first_path = directory.path().join("first.kdbx");
        let source_path = directory.path().join("source.kdbx");
        let imported_path = directory.path().join("internal").join("second.kdbx");
        std::fs::create_dir_all(imported_path.parent().unwrap()).unwrap();
        let first_id = generate_workspace_id();
        let second_id = generate_workspace_id();
        let password = "a sufficiently long password";

        let first = create_vault(
            first_path.to_string_lossy().into_owned(),
            "First".into(),
            password.into(),
        )
        .unwrap();
        FileVaultSession::create(&source_path, "Second", password.into()).unwrap();
        let second = import_vault(
            source_path.to_string_lossy().into_owned(),
            imported_path.to_string_lossy().into_owned(),
            "Second".into(),
            password.into(),
        )
        .unwrap();
        let first_enrollment =
            prepare_quick_unlock_enrollment(first.id, first_id.clone(), None).unwrap();
        let second_enrollment = prepare_quick_unlock_enrollment(
            second.id,
            second_id.clone(),
            Some(first_enrollment.updated_keyring),
        )
        .unwrap();
        lock_all_vaults().unwrap();

        let result = open_vaults_with_quick_unlock(
            vec![
                QuickUnlockRequest {
                    workspace_id: first_id.clone(),
                    path: first_path.to_string_lossy().into_owned(),
                    envelope: first_enrollment.envelope,
                },
                QuickUnlockRequest {
                    workspace_id: second_id.clone(),
                    path: imported_path.to_string_lossy().into_owned(),
                    envelope: second_enrollment.envelope,
                },
                QuickUnlockRequest {
                    workspace_id: generate_workspace_id(),
                    path: imported_path.to_string_lossy().into_owned(),
                    envelope: vec![0],
                },
            ],
            second_enrollment.updated_keyring,
        )
        .unwrap();
        assert_eq!(result.opened.len(), 2);
        assert_eq!(result.failed_workspace_ids.len(), 1);
        assert!(
            result
                .opened
                .iter()
                .any(|value| value.workspace_id == first_id)
        );
        assert!(
            result
                .opened
                .iter()
                .any(|value| value.workspace_id == second_id)
        );
        lock_all_vaults().unwrap();
    }
}
