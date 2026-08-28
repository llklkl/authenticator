use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncAction {
    CreatedRemote,
    Uploaded,
    Downloaded,
    Merged,
    Unchanged,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MergeReport {
    pub auto_merged_objects: u32,
    pub created_conflicts: u32,
    pub pending_conflicts: u32,
    pub baseline_rebuilt: bool,
}

pub struct MergeOutput {
    pub encrypted_bytes: Zeroizing<Vec<u8>>,
    pub report: MergeReport,
    pub requires_upload: bool,
}

impl std::fmt::Debug for MergeOutput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MergeOutput")
            .field("encrypted_bytes", &"[REDACTED]")
            .field("report", &self.report)
            .field("requires_upload", &self.requires_upload)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteRevision {
    pub etag: String,
    pub content_sha256: [u8; 32],
    pub content_length: u64,
}

pub struct RemoteObject {
    pub revision: RemoteRevision,
    pub encrypted_bytes: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for RemoteObject {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RemoteObject")
            .field("revision", &self.revision)
            .field("encrypted_bytes", &"[REDACTED]")
            .finish()
    }
}

pub struct ConditionalUpload<'a> {
    /// `Some` updates an existing object with If-Match. `None` creates with
    /// If-None-Match: * so an unknown remote object can never be overwritten.
    pub expected_etag: Option<&'a str>,
    pub encrypted_bytes: &'a [u8],
}

#[async_trait]
pub trait SyncProvider: Send + Sync {
    async fn download(&self) -> Result<RemoteObject>;
    async fn conditional_upload(&self, request: ConditionalUpload<'_>) -> Result<RemoteRevision>;
}

pub trait VaultMerger: Send + Sync {
    /// Merge encrypted KDBX snapshots using an already-authorized vault session.
    fn merge(&self, base: Option<&[u8]>, local: &[u8], remote: &[u8]) -> Result<MergeOutput>;
}

pub trait BackupStore: Send + Sync {
    fn store(&self, encrypted_snapshot: &[u8]) -> Result<()>;
}
