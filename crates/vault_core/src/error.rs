use thiserror::Error;

pub type Result<T> = std::result::Result<T, VaultError>;

/// Redacted public failures. Error messages intentionally omit user input.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VaultError {
    #[error("the OTP URI is invalid")]
    InvalidOtpUri,
    #[error("the OTP type is not supported")]
    UnsupportedOtpType,
    #[error("the OTP algorithm is not supported")]
    UnsupportedOtpAlgorithm,
    #[error("the OTP digit count is invalid")]
    InvalidOtpDigits,
    #[error("the OTP period is invalid")]
    InvalidOtpPeriod,
    #[error("the OTP secret is invalid")]
    InvalidOtpSecret,
    #[error("the HOTP counter is missing or invalid")]
    InvalidHotpCounter,
    #[error("the requested time is invalid")]
    InvalidTimestamp,
    #[error("a workspace with this id already exists")]
    DuplicateWorkspace,
    #[error("the workspace does not exist")]
    WorkspaceNotFound,
    #[error("the workspace metadata is invalid")]
    InvalidWorkspace,
    #[error("the KDBX database could not be opened")]
    KdbxOpen,
    #[error("the KDBX database could not be saved")]
    KdbxSave,
    #[error("the KDBX database structure is invalid")]
    InvalidKdbx,
    #[error("the vault file could not be read")]
    VaultRead,
    #[error("the vault file could not be written safely")]
    VaultWrite,
    #[error("the vault entry does not exist")]
    EntryNotFound,
    #[error("the vault group does not exist")]
    GroupNotFound,
    #[error("the recycle bin is disabled")]
    RecycleBinDisabled,
    #[error("the requested vault object is protected")]
    ProtectedVaultObject,
    #[error("the requested vault move is invalid")]
    InvalidVaultMove,
    #[error("the requested vault icon is invalid")]
    InvalidVaultIcon,
    #[error("the attachment does not exist")]
    AttachmentNotFound,
    #[error("the attachment name is invalid or already used")]
    InvalidAttachmentName,
    #[error("the attachment exceeds the configured vault limits")]
    AttachmentLimitExceeded,
    #[error("the password generator request is invalid")]
    InvalidGeneratorRequest,
    #[error("the requested entry field is unavailable")]
    FieldUnavailable,
    #[error("the vault file is already open")]
    VaultAlreadyOpen,
    #[error("quick unlock material is invalid or unavailable")]
    QuickUnlock,
}
