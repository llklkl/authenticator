# ADR 0002: per-workspace AES-GCM quick-unlock envelopes

- Status: accepted for the Android security milestone
- Dependency: `aes-gcm` 0.11.x from RustCrypto
- License: MIT OR Apache-2.0

Each opted-in workspace receives an independent random 256-bit key-encryption
key (KEK). Rust encrypts the KDBX master password with AES-256-GCM and binds the
ciphertext to the application identifier, envelope version, and workspace UUID
as authenticated data. The workspace registry stores only this versioned
envelope. Moving an envelope to another workspace, modifying it, using the wrong
KEK, or presenting an unknown version fails closed with a redacted error.

The opaque UUID-to-KEK keyring crosses Flutter only for the duration of a
platform call and is overwritten on the Dart and Rust sides after use. Android
encrypts it with a non-exportable Android Keystore AES key that requires a fresh
`BIOMETRIC_STRONG` operation. Device credentials are not an allowed fallback.
Biometric-enrollment changes invalidate the Keystore key; the application then
deletes the sealed keyring and all unusable envelopes without touching KDBX
files.

`aes-gcm` is maintained by the RustCrypto organization, has a dual permissive
license compatible with this repository, provides a constant-time software
implementation when the target CPU behaves as documented by the crate, and is
widely used in the Rust cryptography ecosystem. The dependency is pinned in
`Cargo.lock`, covered by Dependabot, and isolated in `vault_core::quick_unlock`.
Updates require the tamper, wrong-workspace, version, truncation, independent-key,
and redacted-debug tests to pass. A future security review may replace the crate
behind this module without changing FFI or registry formats.

Enabling quick unlock on an additional workspace can require two biometric
prompts: one to decrypt the existing keyring and one to encrypt the updated
keyring. Registry metadata is committed only after the new sealed keyring has
been written successfully.
