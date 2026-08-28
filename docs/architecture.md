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

The versioned workspace registry stores workspace UUIDs, display names, internal
KDBX paths, the auto-lock setting, and optional authenticated quick-unlock
envelopes in the platform application-support directory. Imported vaults are
validated and atomically copied into that internal directory. Plaintext master
passwords are never stored in the registry. An unlocked workspace is represented across
FFI by an opaque integer handle; the decrypted database and a zeroizing master
password remain in a Rust `FileVaultSession`. Every mutation clones the in-memory
database, merges an externally changed disk replica when needed, writes an
encrypted sibling backup, and then performs a temporary-file/fsync/atomic-replace
transaction.

The UI consumes a purpose-built content snapshot containing only group
relationships and non-secret entry summaries. Nested folders map directly to
KDBX groups. Recycle-bin deletion is a tracked KDBX move that records the prior
parent; restoration uses that parent when it still exists and falls back to the
root otherwise. Root and recycle-bin groups are protected from ordinary rename,
move, and delete operations.

The synchronization engine never performs an unconditional remote overwrite. A
successful verified ciphertext is stored as an independent per-workspace merge
baseline. The next transaction downloads the current revision, validates the
root workspace UUID, performs a three-way field merge, preserves unresolved
same-field and delete/edit conflicts inside the encrypted KDBX, stores encrypted
remote and local backups, uploads against the observed ETag, and downloads again
to verify the committed ciphertext. Attachment divergence fails closed.

WebDAV credentials may optionally be stored in the operating-system credential
store and are never written to the workspace registry or diagnostics. Remote
creation uses `If-None-Match: *`; updates use a strong
ETag with `If-Match`. A successful transaction returns the verified final
ciphertext to the vault session, which validates the KDBX password before
installing it locally.

Restoring an encrypted backup invalidates the merge baseline and persists a
restore-pending suspension. Sync cannot resume until the user explicitly chooses
safe merge or replace-remote. Replace-remote still downloads and backs up the
remote, uses its strong ETag for a conditional write, and verifies the committed
ciphertext. Diagnostics contain only versioned stages, stable error codes,
durations, attempts, and aggregate conflict counts.

On Android, a platform channel isolates BiometricPrompt, Android Keystore,
screen-off events, and window protection from shared Flutter code. One strong
biometric prompt decrypts an opaque Rust keyring and can unlock a user-selected
set of workspaces; partial failures do not prevent independent workspaces from
opening. Background elapsed time is measured monotonically, and the privacy
overlay is removed only after any required lock has completed.
