# Architecture

Authenticator Vault is local-first. The canonical user data for a workspace is
one independently encrypted KDBX 4.1 file. The application does not introduce a
hosted identity or recovery service.

Flutter owns rendering, navigation, platform lifecycle, secure-storage adapters,
clipboard integration, and system autofill integrations. Rust owns parsing,
cryptographic transformations, OTP calculation, KDBX mutation, merge decisions,
and synchronization transactions.

Each workspace has a distinct KDBX file, master password, sync configuration,
backup history, and lock state. A device may wrap several independent vault keys
with an operating-system-bound key, allowing one biometric prompt to release the
selected workspaces without combining their keys at rest.

The offline alpha stores only workspace IDs, display names, and local KDBX paths
in a JSON registry in the platform application-support directory. Master
passwords are never stored there. An unlocked workspace is represented across
FFI by an opaque integer handle; the decrypted database and a zeroizing master
password remain in a Rust `FileVaultSession`. Every mutation clones the in-memory
database, merges an externally changed disk replica when needed, writes an
encrypted sibling backup, and then performs a temporary-file/fsync/atomic-replace
transaction.

The synchronization engine never performs an unconditional remote overwrite. It
downloads the current revision, merges UUIDs/history/deletion records, stores an
encrypted backup, uploads against the observed ETag, and downloads again to
verify the committed ciphertext.

WebDAV credentials are currently entered per synchronization attempt and are
not persisted. Remote creation uses `If-None-Match: *`; updates use a strong
ETag with `If-Match`. A successful transaction returns the verified final
ciphertext to the vault session, which validates the KDBX password before
installing it locally.
