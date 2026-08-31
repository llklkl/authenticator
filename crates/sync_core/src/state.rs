use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

use crate::{Result, SyncAction, SyncError};

const STATE_VERSION: u32 = 2;
const DIAGNOSTIC_VERSION: u32 = 1;
const MAX_DIAGNOSTIC_EVENTS: usize = 500;
const DIAGNOSTIC_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncSuspension {
    RestorePending,
    AttachmentConflict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedSyncState {
    pub version: u32,
    pub last_success_unix_ms: Option<i64>,
    pub last_action: Option<String>,
    pub pending_conflicts: u32,
    pub suspension: Option<SyncSuspension>,
    #[serde(default)]
    pub remote_location_fingerprint: Option<String>,
    #[serde(default)]
    pub base_commit_id: Option<String>,
    #[serde(default)]
    pub base_sha256: Option<String>,
}

pub struct BoundSyncBase {
    pub encrypted: Option<Zeroizing<Vec<u8>>>,
    pub commit_id: Option<String>,
}

impl std::fmt::Debug for BoundSyncBase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BoundSyncBase")
            .field("encrypted", &self.encrypted.as_ref().map(|_| "[REDACTED]"))
            .field("commit_id", &self.commit_id.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl Default for PersistedSyncState {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            last_success_unix_ms: None,
            last_action: None,
            pending_conflicts: 0,
            suspension: None,
            remote_location_fingerprint: None,
            base_commit_id: None,
            base_sha256: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticEvent {
    pub version: u32,
    pub timestamp_unix_ms: i64,
    pub stage: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub attempts: u32,
    pub duration_ms: u64,
    pub auto_merged_objects: u32,
    pub created_conflicts: u32,
    pub pending_conflicts: u32,
}

impl DiagnosticEvent {
    pub fn success(
        action: SyncAction,
        attempts: u32,
        duration_ms: u64,
        auto_merged_objects: u32,
        created_conflicts: u32,
        pending_conflicts: u32,
    ) -> Self {
        Self {
            version: DIAGNOSTIC_VERSION,
            timestamp_unix_ms: now_unix_ms(),
            stage: "complete".to_owned(),
            outcome: action_name(action).to_owned(),
            error_code: None,
            attempts,
            duration_ms,
            auto_merged_objects,
            created_conflicts,
            pending_conflicts,
        }
    }

    pub fn failure(code: &str, duration_ms: u64) -> Self {
        Self {
            version: DIAGNOSTIC_VERSION,
            timestamp_unix_ms: now_unix_ms(),
            stage: "sync".to_owned(),
            outcome: "failure".to_owned(),
            error_code: Some(code.to_owned()),
            attempts: 0,
            duration_ms,
            auto_merged_objects: 0,
            created_conflicts: 0,
            pending_conflicts: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FileSyncStateStore {
    directory: PathBuf,
}

impl FileSyncStateStore {
    pub fn new(directory: PathBuf) -> Self {
        Self { directory }
    }

    pub fn load_base(&self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let path = self.base_path();
        match fs::read(path) {
            Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(SyncError::State),
        }
    }

    pub fn commit_base(&self, encrypted: &[u8]) -> Result<()> {
        atomic_write(&self.base_path(), encrypted)
    }

    pub fn load_bound_base(&self, location_fingerprint: &str) -> Result<BoundSyncBase> {
        let state = self.load_state()?;
        if state.remote_location_fingerprint.as_deref() != Some(location_fingerprint) {
            return Ok(BoundSyncBase {
                encrypted: None,
                commit_id: None,
            });
        }
        let Some(base) = self.load_base()? else {
            return Ok(BoundSyncBase {
                encrypted: None,
                commit_id: None,
            });
        };
        let hash = hex(&Sha256::digest(&base));
        if state.base_sha256.as_deref() != Some(hash.as_str()) {
            return Ok(BoundSyncBase {
                encrypted: None,
                commit_id: None,
            });
        }
        Ok(BoundSyncBase {
            encrypted: Some(base),
            commit_id: state.base_commit_id,
        })
    }

    pub fn commit_bound_base(
        &self,
        encrypted: &[u8],
        location_fingerprint: String,
        base_commit_id: Option<String>,
    ) -> Result<()> {
        self.commit_base(encrypted)?;
        let mut state = self.load_state()?;
        state.remote_location_fingerprint = Some(location_fingerprint);
        state.base_commit_id = base_commit_id;
        state.base_sha256 = Some(hex(&Sha256::digest(encrypted)));
        self.store_state(&state)
    }

    pub fn invalidate_base(&self) -> Result<()> {
        match fs::remove_file(self.base_path()) {
            Ok(()) => sync_directory(&self.directory),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(SyncError::State),
        }
    }

    pub fn load_state(&self) -> Result<PersistedSyncState> {
        let path = self.state_path();
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(PersistedSyncState::default());
            }
            Err(_) => return Err(SyncError::State),
        };
        let state: PersistedSyncState =
            serde_json::from_slice(&bytes).map_err(|_| SyncError::State)?;
        if state.version != 1 && state.version != STATE_VERSION {
            return Err(SyncError::State);
        }
        let mut state = state;
        state.version = STATE_VERSION;
        Ok(state)
    }

    pub fn store_state(&self, state: &PersistedSyncState) -> Result<()> {
        let bytes = serde_json::to_vec(state).map_err(|_| SyncError::State)?;
        atomic_write(&self.state_path(), &bytes)
    }

    pub fn record_success(&self, action: SyncAction, pending_conflicts: u32) -> Result<()> {
        let mut state = self.load_state()?;
        state.last_success_unix_ms = Some(now_unix_ms());
        state.last_action = Some(action_name(action).to_owned());
        state.pending_conflicts = pending_conflicts;
        state.suspension = None;
        self.store_state(&state)
    }

    pub fn suspend(&self, reason: SyncSuspension) -> Result<()> {
        let mut state = self.load_state()?;
        state.suspension = Some(reason);
        self.store_state(&state)
    }

    pub fn clear_suspension(&self) -> Result<()> {
        let mut state = self.load_state()?;
        state.suspension = None;
        self.store_state(&state)
    }

    pub fn append_diagnostic(&self, event: DiagnosticEvent) -> Result<()> {
        let mut events = self.load_diagnostics()?;
        let cutoff = now_unix_ms().saturating_sub(DIAGNOSTIC_RETENTION_MS);
        events.retain(|item| item.timestamp_unix_ms >= cutoff);
        events.push(event);
        if events.len() > MAX_DIAGNOSTIC_EVENTS {
            events.drain(..events.len() - MAX_DIAGNOSTIC_EVENTS);
        }
        let bytes = serde_json::to_vec(&events).map_err(|_| SyncError::Diagnostics)?;
        atomic_write(&self.diagnostics_path(), &bytes).map_err(|_| SyncError::Diagnostics)
    }

    pub fn load_diagnostics(&self) -> Result<Vec<DiagnosticEvent>> {
        match fs::read(self.diagnostics_path()) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| SyncError::Diagnostics),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(_) => Err(SyncError::Diagnostics),
        }
    }

    pub fn export_diagnostics(&self, destination: &Path, overwrite: bool) -> Result<()> {
        if destination.exists() && !overwrite {
            return Err(SyncError::Diagnostics);
        }
        let events = self.load_diagnostics()?;
        let bytes = serde_json::to_vec_pretty(&events).map_err(|_| SyncError::Diagnostics)?;
        atomic_write(destination, &bytes).map_err(|_| SyncError::Diagnostics)
    }

    pub fn clear_diagnostics(&self) -> Result<()> {
        match fs::remove_file(self.diagnostics_path()) {
            Ok(()) => sync_directory(&self.directory),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(SyncError::Diagnostics),
        }
    }

    fn base_path(&self) -> PathBuf {
        self.directory.join("base.kdbx")
    }

    fn state_path(&self) -> PathBuf {
        self.directory.join("state.json")
    }

    fn diagnostics_path(&self) -> PathBuf {
        self.directory.join("diagnostics.json")
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or(SyncError::State)?;
    fs::create_dir_all(parent).map_err(|_| SyncError::State)?;
    let mut temporary = NamedTempFile::new_in(parent).map_err(|_| SyncError::State)?;
    temporary
        .write_all(bytes)
        .and_then(|_| temporary.as_file().sync_all())
        .map_err(|_| SyncError::State)?;
    temporary.persist(path).map_err(|_| SyncError::State)?;
    sync_directory(parent)
}

fn sync_directory(path: &Path) -> Result<()> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| SyncError::State)
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or_default()
}

fn action_name(action: SyncAction) -> &'static str {
    match action {
        SyncAction::CreatedRemote => "created_remote",
        SyncAction::Uploaded => "uploaded",
        SyncAction::Downloaded => "downloaded",
        SyncAction::Merged => "merged",
        SyncAction::Unchanged => "unchanged",
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_and_diagnostics_round_trip_without_user_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let store = FileSyncStateStore::new(directory.path().to_owned());
        store.commit_base(b"encrypted kdbx").unwrap();
        store.record_success(SyncAction::Merged, 2).unwrap();
        store
            .append_diagnostic(DiagnosticEvent::success(SyncAction::Merged, 2, 40, 3, 1, 2))
            .unwrap();
        store.suspend(SyncSuspension::RestorePending).unwrap();
        assert_eq!(
            store.load_state().unwrap().suspension,
            Some(SyncSuspension::RestorePending)
        );
        store.clear_suspension().unwrap();
        assert_eq!(store.load_state().unwrap().suspension, None);
        assert_eq!(&*store.load_base().unwrap().unwrap(), b"encrypted kdbx");
        store
            .commit_bound_base(
                b"encrypted kdbx",
                "location-fingerprint".into(),
                Some("commit-id".into()),
            )
            .unwrap();
        let bound = store.load_bound_base("location-fingerprint").unwrap();
        assert_eq!(&*bound.encrypted.unwrap(), b"encrypted kdbx");
        assert_eq!(bound.commit_id.as_deref(), Some("commit-id"));
        store.commit_base(b"tampered encrypted kdbx").unwrap();
        assert!(
            store
                .load_bound_base("location-fingerprint")
                .unwrap()
                .encrypted
                .is_none()
        );
        assert!(
            store
                .load_bound_base("other-location")
                .unwrap()
                .encrypted
                .is_none()
        );
        assert_eq!(store.load_state().unwrap().pending_conflicts, 2);
        let encoded = fs::read_to_string(directory.path().join("diagnostics.json")).unwrap();
        assert!(!encoded.contains("password"));
        assert!(!encoded.contains("http"));
    }
}
