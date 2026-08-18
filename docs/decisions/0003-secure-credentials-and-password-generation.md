# ADR 0003: system credential storage and local password generation

- Status: accepted
- Dependencies: `flutter_secure_storage` 10.3.x, `bip39` 2.2.x
- Licenses: BSD-3-Clause (`flutter_secure_storage`), CC0-1.0 (`bip39`)

WebDAV passwords are optional per-workspace credentials. They must not be
stored in the JSON workspace registry or KDBX custom fields. The Flutter
platform layer stores them through `flutter_secure_storage`, which delegates to
the platform credential/keychain implementation. Linux packages and builds
therefore require `libsecret`. Registry metadata contains only a boolean that
indicates whether a credential should exist; a missing or invalidated secret
puts synchronization into the `credentials needed` state.

The package is pinned to a maintained 10.3 release line and exposes only the
small read/write/delete surface used by the workspace service. Credentials are
never included in errors, logs, analytics, crash payloads, or debug output.
Removing the “save password” option deletes the corresponding secure-storage
record.

Password and passphrase generation remains in Rust. Random passwords use the
operating-system random source with rejection sampling, mandatory selected
character classes, and a final unbiased shuffle. Passphrases uniformly select
from the fixed 2048-word BIP39 English list supplied by `bip39`; this use does
not derive wallet seeds or keys. Generated values use zeroizing Rust buffers
until deliberately returned for display or entry insertion, and their debug
representations are redacted.

Acceptance requires generator shape and redaction tests, registry migration
tests proving that credentials are absent from JSON, and platform packaging
checks for secure-storage plugins.
