# Authenticator Vault

An offline-first, open-source password and OTP vault for Android, iOS, Linux,
macOS, and Windows. Data is stored in independent KDBX 4.1 workspace files and
can be synchronized through storage controlled by the user.

## Status

The current offline alpha includes:

- RFC 4226/6238 OTP calculation in Rust with redacted secret handling.
- Persistent KDBX 4.1 workspaces with create/import/unlock/lock flows, atomic
  writes, encrypted backups, external-change merge, and restart-safe metadata.
- Login, OTP, recovery-code, and secure-note CRUD with protected fields kept in
  Rust-owned unlocked sessions.
- Standard `otpauth` and Google Authenticator migration-payload import.
- Provider-neutral conditional synchronization with ETag retry, encrypted
  backup hooks, remote creation protection, and post-upload verification.
- On-demand WebDAV sync with credentials retained only for the active request.
- A responsive Flutter interface for arbitrary independent workspaces, timed
  clipboard clearing, lifecycle locking, and cross-platform KDBX file picking.
- Android strong-biometric quick unlock for explicitly selected workspaces,
  backed by Android Keystore with enrollment invalidation and no device-PIN
  fallback.
- Configurable background auto-lock, immediate screen-off locking, privacy
  overlay, screenshot blocking while sensitive content is active, and disabled
  Android backups.

Camera/image QR decoding, platform autofill, browser companion extensions, and
attachment support remain under active development.

## Architecture

- Flutter owns the cross-platform user interface and platform integrations.
- Rust owns OTP, KDBX, vault sessions, merge behavior, and synchronization.
- Each workspace is a separate encrypted KDBX file.
- The initial sync provider is WebDAV; no hosted account is required.

See [`AGENTS.md`](AGENTS.md) for engineering and security rules.

## Development

Prerequisites are the stable Flutter and Rust toolchains plus native platform
SDKs for each target. The standard checks are:

```sh
cargo test --workspace
(cd apps/client && flutter analyze)
(cd apps/client && flutter test)
```

## License

MIT, copyright llklkl.
