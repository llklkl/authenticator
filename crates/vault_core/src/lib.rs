//! Security-sensitive domain core for Authenticator Vault.

mod entry;
mod error;
mod kdbx;
mod otp;
mod password;
mod quick_unlock;
mod session;
mod workspace;

pub use entry::{EntryKind, EntrySummary, VaultEntry};
pub use error::{Result, VaultError};
pub use kdbx::{
    EntrySecretField, KdbxAttachmentRecord, KdbxContentSnapshot, KdbxDatabase, KdbxEngine,
    KdbxEntryRecord, KdbxGroupRecord, KdbxIconRecord, MAX_ATTACHMENT_BYTES,
    MAX_TOTAL_ATTACHMENT_BYTES, PasswordHealthFinding, PasswordHealthPolicy, PasswordHealthReport,
    PasswordHealthRisk,
};
pub use otp::{OtpAlgorithm, OtpCode, OtpConfig, OtpKind};
pub use password::{
    DEFAULT_PASSWORD_SYMBOLS, GeneratedPassword, PasswordGeneratorRequest, generate_password,
    normalize_symbol_characters,
};
pub use quick_unlock::{
    QuickUnlockEnrollment, prepare_quick_unlock, quick_unlock_key, remove_quick_unlock,
    unseal_quick_unlock,
};
pub use session::FileVaultSession;
pub use workspace::{SyncProviderKind, WorkspaceId, WorkspaceMetadata, WorkspaceRegistry};
