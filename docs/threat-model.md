# Threat model

Protected assets include KDBX master keys, passwords, secure notes, recovery
codes, OTP seeds, provider credentials, clipboard contents, and unlocked
sessions.

The first release protects against stolen encrypted files, untrusted storage and
networks, malformed inputs, local clipboard readers, and concurrent clients. It
cannot protect a secret after the operating system or unlocked application
process has been compromised.

Required mitigations are Argon2id for new KDBX 4.1 files, OS-bound secure storage,
redacted diagnostics, automatic locking, timed clipboard clearing, atomic local
writes, encrypted backups, conditional remote writes, post-upload verification,
and explicit conflict reporting.

Implemented in the offline alpha are redacted Rust errors/debug output,
Rust-owned unlocked sessions, five-minute background locking, conditional
WebDAV writes, post-upload verification, encrypted local/sync backups, and
atomic KDBX replacement. The UI intentionally does not persist WebDAV or master
passwords. OS-bound quick-unlock wrapping and screenshot blocking are release
gates that are not yet implemented; until then users must enter each workspace
master password after a restart or lock.
