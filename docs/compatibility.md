# Compatibility notes

The core reads existing KDBX databases supported by `keepass` 0.13.x. It only
writes an already-KDBX-4.1 database; KDBX 4.0 and other versions are exposed as
read-only and are never silently upgraded. New workspaces use KDBX 4.1. Application
entry metadata uses the unprotected custom fields
`Authenticator.EntryKind` and `Authenticator.ModifiedAtUnixMs`; passwords,
notes, OTP URIs, and recovery codes are protected KDBX fields.

Read-modify-write tests cover unknown protected fields, entry history, UUID
merge, deletion records, independent-field three-way merge, same-field and
delete/edit conflict preservation, independently added entries, nested-group
moves, and recycle-bin trash/restore/empty behavior. Attachment-bearing
divergence fails closed before upload because upstream does not yet safely merge
attachment histories. Before a stable release, the
compatibility suite must also exercise versioned fixtures opened and saved by
current KeePass and KeePassXC releases, including custom icons and attachments.

Google Authenticator migration payloads support SHA-1, SHA-256, SHA-512,
six/eight digits, HOTP, TOTP, and multiple OTP parameters in a single payload.
Multi-QR batch collection is not yet implemented; each supplied migration URI
is imported as its own atomic KDBX transaction.

Android builds use application ID `top.llklkl.authenticatorvault`, require API
24 or newer, and use `BIOMETRIC_STRONG` without device-credential fallback.
Quick-unlock envelopes and sealed keyrings are independently versioned; unknown
versions fail closed and the KDBX remains unlockable with its master password.
