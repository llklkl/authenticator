use thiserror::Error;

pub type Result<T> = std::result::Result<T, SyncError>;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SyncError {
    #[error("the remote vault does not exist")]
    RemoteNotFound,
    #[error("the remote revision changed")]
    PreconditionFailed,
    #[error("the sync provider failed")]
    Provider,
    #[error("the vault merge failed")]
    Merge,
    #[error("the encrypted backup failed")]
    Backup,
    #[error("the uploaded vault could not be verified")]
    VerificationFailed,
    #[error("synchronization did not converge")]
    RetryLimitReached,
    #[error("the sync provider configuration is invalid")]
    InvalidConfiguration,
    #[error("the sync provider does not support safe conditional writes")]
    ConditionalWritesUnsupported,
    #[error("the remote storage operation is unsupported")]
    UnsupportedOperation,
    #[error("the remote storage history is invalid")]
    InvalidRemoteHistory,
    #[error("the remote storage versioning configuration is unsafe")]
    UnsafeBucketVersioning,
    #[error("synchronization state could not be persisted")]
    State,
    #[error("synchronization diagnostics could not be persisted")]
    Diagnostics,
    #[error("the remote vault belongs to a different workspace")]
    RemoteVaultMismatch,
    #[error("attachment changes require a future merge implementation")]
    AttachmentConflictUnsupported,
    #[error("restored data requires an explicit synchronization decision")]
    RestoreDecisionRequired,
}
