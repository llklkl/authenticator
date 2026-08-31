//! Provider-neutral synchronization contracts.

mod append;
mod backup;
mod cos;
mod engine;
mod error;
mod provider;
mod state;
mod vfs;
mod webdav;

pub use append::AppendOnlySyncEngine;
pub use backup::{BackupDescriptor, BackupOrigin, FileBackupStore};
pub use cos::TencentCosVfs;
pub use engine::{SyncEngine, SyncOutcome};
pub use error::{Result, SyncError};
pub use provider::{
    BackupStore, ConditionalUpload, MergeOutput, MergeReport, RemoteObject, RemoteRevision,
    SyncAction, SyncProvider, VaultMerger,
};
pub use state::{
    BoundSyncBase, DiagnosticEvent, FileSyncStateStore, PersistedSyncState, SyncSuspension,
};
pub use vfs::{
    RemoteVfs, VfsCapabilities, VfsListEntry, VfsListPage, VfsObject, VfsPath, VfsRevision,
    WriteCondition,
};
pub use webdav::WebDavProvider;
