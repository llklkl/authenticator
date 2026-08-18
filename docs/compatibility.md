# Compatibility notes

The core reads existing KDBX 3/4 databases supported by `keepass` 0.13.x and
writes KDBX 4.1. New workspaces use the library's KDBX 4 defaults. Application
entry metadata uses the unprotected custom fields
`Authenticator.EntryKind` and `Authenticator.ModifiedAtUnixMs`; passwords,
notes, OTP URIs, and recovery codes are protected KDBX fields.

Read-modify-write tests cover unknown protected fields, entry history, UUID
merge, deletion records, and independently added entries. Before a stable
release, the compatibility suite must also exercise versioned fixtures opened
and saved by current KeePass and KeePassXC releases, including custom icons,
attachments, nested groups, and recycle-bin behavior.

Google Authenticator migration payloads support SHA-1, SHA-256, SHA-512,
six/eight digits, HOTP, TOTP, and multiple OTP parameters in a single payload.
Multi-QR batch collection is not yet implemented; each supplied migration URI
is imported as its own atomic KDBX transaction.

Android builds use application ID `top.llklkl.authenticatorvault`, require API
24 or newer, and use `BIOMETRIC_STRONG` without device-credential fallback.
Quick-unlock envelopes and sealed keyrings are independently versioned; unknown
versions fail closed and the KDBX remains unlockable with its master password.
