//! Provider-neutral synchronization contracts.

mod backup;
mod engine;
mod error;
mod provider;
mod webdav;

pub use backup::FileBackupStore;
pub use engine::{SyncEngine, SyncOutcome};
pub use error::{Result, SyncError};
pub use provider::{
    BackupStore, ConditionalUpload, RemoteObject, RemoteRevision, SyncProvider, VaultMerger,
};
pub use webdav::WebDavProvider;
