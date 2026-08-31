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
- Native nested KDBX folders, entry/folder moves, and a recoverable recycle bin
  with restore, permanent-delete, and empty-bin operations.
- KeePass built-in/custom icon display, folder icon presets, favorites, tags,
  recent items, encrypted attachment management, and local password-health
  checks that expose only entry IDs and risk types to Flutter.
- Standard `otpauth` and Google Authenticator migration-payload import.
- Provider-neutral three-way synchronization with a per-workspace encrypted
  baseline, ETag retry, encrypted backup rotation, remote-workspace identity
  checks, restore workflow, conflict preservation, and post-upload verification.
- Per-workspace foreground WebDAV auto-sync with conditional writes and Tencent
  Cloud COS synchronization through an immutable commit graph, readable
  status, retry/backoff, optional non-metered-network policy, and passwords
  stored only through the operating-system credential store when requested.
- Rust-backed random-password and BIP39-wordlist passphrase generation.
- A responsive Flutter interface with a compact KeePassXC-inspired desktop
  tree/table/detail layout, separate password/OTP/other views, multi-workspace
  switching, a mobile folder/list/detail flow, system light/dark themes, and a
  custom desktop title bar with native fallback.
- Passwords hidden by default with explicit reveal, automatic 30-second hiding,
  timed clipboard clearing, lifecycle locking, and cross-platform KDBX picking.
- Android strong-biometric quick unlock for explicitly selected workspaces,
  backed by Android Keystore with enrollment invalidation and no device-PIN
  fallback.
- Configurable background auto-lock, immediate screen-off locking, privacy
  overlay, screenshot blocking while sensitive content is active, and disabled
  Android backups.

Camera/image QR decoding, platform autofill, browser companion extensions,
attachment preview/merge, and locked background sync remain under active
development. KDBX 4.0 opens read-only; an explicit 4.0-to-4.1 conversion flow is
intentionally deferred.

## Architecture

- Flutter owns the cross-platform user interface and platform integrations.
- Rust owns OTP, KDBX, vault sessions, merge behavior, and synchronization.
- Each workspace is a separate encrypted KDBX file.
- Remote providers share a Rust VFS contract. WebDAV and Tencent Cloud COS are
  supported; no hosted application account is required.

See [`AGENTS.md`](AGENTS.md) for engineering and security rules.
See [`docs/synchronization.md`](docs/synchronization.md) for the conflict,
backup, recovery, and two-device verification workflow.

## Development

Prerequisites are the stable Flutter and Rust toolchains plus native platform
SDKs for each target. Linux also requires the `libsecret-1-dev` (Debian/Ubuntu)
or `libsecret-devel` (Fedora) development package for secure credential
storage. The standard checks are:

```sh
cargo test --workspace
(cd apps/client && flutter analyze)
(cd apps/client && flutter test)
```

## License

MIT, copyright llklkl.
