# 0004: Remote VFS and append-only Tencent COS synchronization

## Status

Accepted.

## Context

The original synchronization provider treated the remote vault as one WebDAV
file and required strong ETag `If-Match` updates. Tencent Cloud COS `PUT Object`
does not provide compare-and-swap replacement by ETag. On buckets without
versioning it provides `x-cos-forbid-overwrite: true`, while object listing is
eventually consistent. Reusing the single-file protocol would therefore permit
last-write-wins data loss.

Tencent does not publish an official Rust COS SDK. Adding platform SDKs in Dart
would also move encrypted-vault transport and sync transactions out of Rust.

## Decision

`sync_core` exposes a remote-only VFS with read, paginated list, create-only
write, and revision-matched write. It deliberately has no unconditional write
or delete operation. WebDAV maps the root VFS object to the existing file URL.

COS uses a content-addressed append-only graph under a user-selected prefix:

- `blobs/<sha256>.kdbx` contains an encrypted KDBX snapshot.
- `commits/<sha256>.json` contains a canonical, versioned manifest with the blob
  hash, encrypted length, and sorted parent commit IDs.

Blob and commit objects are created with overwrite protection and immediately
read back. Missing concurrent commits may delay convergence because COS list is
eventually consistent, but later appear as graph heads and are merged. Existing
objects are never replaced or deleted. COS bucket versioning must be disabled;
the client checks this before every write transaction.

The COS client derives the standard HTTPS regional host from validated bucket
and region values, disables redirects, signs the host and all relevant request
fields, and accepts permanent CAM sub-account credentials only. SecretId and
SecretKey are zeroized in Rust and may be persisted only in OS secure storage.

## Dependency review

- `hmac` and `sha1` implement the COS request-signing algorithm. Both are
  RustCrypto crates already used by the workspace, actively maintained, and
  permissively licensed. SHA-1 is used only where required for request
  authentication, never for vault cryptography or content integrity.
- `md-5` and `base64` produce COS `Content-MD5` transport checks. Encrypted KDBX
  ciphertext is also verified with SHA-256 after upload. These crates never see
  decrypted KDBX data or credentials.
- `quick-xml` parses bounded COS list and versioning responses. Only expected
  fields are retained; provider response bodies are never logged or returned in
  errors. It is actively maintained and MIT licensed.
- `percent-encoding` canonicalizes signed paths and parameters and is already a
  workspace dependency.

## Consequences

COS synchronization needs `GetBucket`, `GetBucketVersioning`, `GetObject`, and
`PutObject` permissions scoped to the configured prefix. It does not need delete
or ACL-management permissions. Remote history grows in v1; garbage collection
requires a separately designed safe protocol and is intentionally deferred.
