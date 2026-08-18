//! Security-sensitive domain core for Authenticator Vault.

mod entry;
mod error;
mod kdbx;
mod otp;
mod session;
mod workspace;

pub use entry::{EntryKind, EntrySummary, VaultEntry};
pub use error::{Result, VaultError};
pub use kdbx::{EntrySecretField, KdbxDatabase, KdbxEngine, KdbxEntryRecord};
pub use otp::{OtpAlgorithm, OtpCode, OtpConfig, OtpKind};
pub use session::FileVaultSession;
pub use workspace::{SyncProviderKind, WorkspaceId, WorkspaceMetadata, WorkspaceRegistry};
