# Repository instructions

## Product

This repository contains an offline-first, multi-platform authenticator and
password vault. Each workspace is backed by an independent KDBX 4.1 file and
may use its own master password and sync provider.

The supported client targets are Android, iOS, Linux, macOS, and Windows.
Browser extensions are companion clients and must communicate with the desktop
application through Native Messaging; they must not persist vault keys.

## Repository layout

- `apps/client`: Flutter application shared by mobile and desktop platforms.
- `crates/vault_core`: Rust security core for OTP, vaults, KDBX, and merging.
- `crates/sync_core`: Rust provider-neutral synchronization state machine.
- `crates/native_bridge`: narrow Flutter/Rust FFI boundary.
- `extensions/browser`: browser companion extension when that milestone starts.
- `docs`: threat model, architecture decisions, and compatibility notes.

## Required engineering rules

1. Secrets, passwords, OTP seeds, WebDAV credentials, decrypted KDBX XML, and
   complete private URLs must never be logged, included in errors, fixtures,
   screenshots, analytics, or crash reports.
2. Cryptography, OTP calculation, KDBX parsing/writing, conflict merging, and
   sync transactions belong in Rust. Dart owns presentation and platform
   integration only.
3. Do not expose raw OTP seeds or vault keys through FFI. Prefer opaque session
   handles and purpose-specific commands.
4. Preserve unknown KDBX groups, fields, history items, icons, binaries, and
   metadata during a read-modify-write cycle.
5. Never overwrite a remote vault using last-write-wins. Use conditional writes,
   merge by UUID/history/deletion records, create an encrypted backup, and verify
   the committed remote object.
6. Use safe temporary-file writes followed by atomic replacement for local
   vault changes. Never edit a KDBX file in place.
7. New dependencies that process secrets or encrypted files require a license,
   maintenance, and security review recorded in `docs/decisions`.
8. Keep platform-specific code behind interfaces. Shared behavior must have
   platform-independent tests.

## Quality gates

Before handing off a change, run the relevant subset of:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
flutter analyze apps/client
flutter test apps/client
```

KDBX changes additionally require the round-trip compatibility suite. Sync
changes additionally require concurrent-device, interrupted-write, stale-ETag,
and recovery tests. OTP changes require RFC 4226/6238 vectors.

## Style and change discipline

- Prefer small, explicit domain types over maps and unvalidated strings.
- Keep errors structured and redact their display representations.
- Document security assumptions and failure behavior next to public interfaces.
- Do not weaken locking, clipboard clearing, screenshot protection, backup, or
  verification behavior to make a test pass.
- Do not commit generated build artifacts, local vaults, key files, QR exports,
  signing material, IDE secrets, or diagnostic bundles.
