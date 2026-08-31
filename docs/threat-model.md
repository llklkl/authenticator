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

Implemented in the Android alpha are redacted Rust errors/debug output,
Rust-owned unlocked sessions, configurable background locking (immediate to 15
minutes), immediate screen-off locking, conditional WebDAV writes,
create-only append-log COS writes, post-upload verification, encrypted local/sync backups, and atomic KDBX
replacement. The UI never writes provider secret credentials to the workspace
registry.

COS bucket, region, and prefix are non-secret configuration. SecretId and
SecretKey are provider credentials and are stored only in OS secure storage when
the user opts in. COS hosts are derived from validated configuration, redirects
are disabled, response bodies are discarded on error, and bucket versioning or
malformed remote history causes synchronization to fail closed.

Quick unlock is disabled by default and opt-in per workspace. Rust encrypts each
master password under an independent KEK; Android Keystore protects the opaque
keyring and permits only strong biometric authentication. Device PIN/password
fallback is excluded. A biometric enrollment change invalidates and removes the
quick-unlock material but never deletes the KDBX. Unlocked screens and sensitive
dialogs set `FLAG_SECURE`, hide overlays where supported, and reject obscured
touches. The locked idle screen remains screenshot-capable by product policy.

The design does not defend against a compromised OS, accessibility service with
equivalent privilege, process-memory inspection after successful authentication,
or a camera photographing the display. Clipboard exposure remains bounded rather
than eliminated; copied values are conditionally cleared after 30 seconds.
