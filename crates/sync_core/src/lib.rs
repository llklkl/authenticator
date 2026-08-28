//! Provider-neutral synchronization contracts.

mod backup;
mod engine;
mod error;
mod provider;
mod state;
mod webdav;

pub use backup::{BackupDescriptor, BackupOrigin, FileBackupStore};
pub use engine::{SyncEngine, SyncOutcome};
pub use error::{Result, SyncError};
pub use provider::{
    BackupStore, ConditionalUpload, MergeOutput, MergeReport, RemoteObject, RemoteRevision,
    SyncAction, SyncProvider, VaultMerger,
};
pub use state::{DiagnosticEvent, FileSyncStateStore, PersistedSyncState, SyncSuspension};
pub use webdav::WebDavProvider;
