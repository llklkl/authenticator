# Synchronization, conflicts, and recovery

Each workspace owns an independent sync-state directory. It contains an
encrypted `base.kdbx`, versioned non-secret `state.json`, rolling redacted
`diagnostics.json`, and encrypted KDBX backups. None of these files contains a
plaintext master password, OTP seed, entry value, URL, or provider credential.

The remote storage layer is a VFS with no unconditional-write operation.
WebDAV keeps the original single-file conditional-write protocol. Tencent Cloud
COS uses immutable blobs and commit manifests under a configured prefix because
COS does not support ETag compare-and-swap replacement.

## Normal transaction

1. Read the local encrypted snapshot and the last verified encrypted baseline.
2. Download the remote object and store an encrypted pre-merge backup.
3. Verify that base, local, and remote use the same root-group UUID.
4. Merge independent fields automatically. Preserve same-field and delete/edit
   conflicts as deterministic conflict records inside the encrypted KDBX.
5. Stop before upload if attachment-bearing replicas diverge.
6. Upload with `If-Match` (or create with `If-None-Match: *`). A stale ETag
   restarts the transaction against the newly observed revision.
7. Download again and verify the committed ETag and ciphertext hash.
8. Back up the current local file, atomically install the verified result, and
   atomically commit it as the next merge baseline.

## Tencent Cloud COS transaction

1. Verify that bucket versioning is disabled and list all commit manifests under
   the workspace prefix, following pagination.
2. Validate the content-addressed commit graph and directly fetch any referenced
   parents missing from the list page.
3. Identify every graph head. Back up and merge each encrypted head against its
   common ancestor with the local baseline.
4. Create and verify `blobs/<sha256>.kdbx`, then create and verify a canonical
   `commits/<sha256>.json` whose parents are the observed frontier.
5. Atomically bind the local encrypted baseline to the verified commit ID.

COS listing is eventually consistent. A concurrent commit omitted from one list
creates a sibling branch rather than being overwritten; a later sync sees both
heads and publishes a merge commit. COS v1 never deletes blobs or commits.

Use a dedicated CAM sub-account and replace the placeholders in this minimal
policy. Keep the `cos:prefix` condition aligned with the configured prefix.

```json
{
  "version": "2.0",
  "statement": [
    {
      "effect": "allow",
      "action": ["name/cos:GetBucketVersioning"],
      "resource": ["qcs::cos:<region>:uid/<appid>:<bucket-appid>/*"]
    },
    {
      "effect": "allow",
      "action": ["name/cos:GetBucket"],
      "resource": ["qcs::cos:<region>:uid/<appid>:<bucket-appid>/*"],
      "condition": {
        "string_like": {"cos:prefix": "<prefix>/*"}
      }
    },
    {
      "effect": "allow",
      "action": ["name/cos:GetObject", "name/cos:PutObject"],
      "resource": ["qcs::cos:<region>:uid/<appid>:<bucket-appid>/<prefix>/*"]
    }
  ]
}
```

Conflict resolution supports a whole-entry default and per-field choices. Secret
values are not previewed in the conflict list. Resolving a conflict mutates the
local KDBX; run sync again to send the resolution to other devices.

## Restore behavior

Restoring validates the backup with the unlocked key and root UUID, backs up the
current local file, installs the selected encrypted snapshot, invalidates the
baseline, and disables automatic sync. The persisted `restore_pending` state
blocks ordinary sync until one explicit choice is made:

- **Safe merge** re-enters the normal merge transaction without a baseline and
  preserves ambiguous edits as conflicts.
- **Replace remote** first backs up the current remote, then conditionally writes
  the restored ciphertext against its observed ETag and verifies the result.

## Manual two-device verification

Use a disposable workspace and either a WebDAV path or a private COS prefix. For
COS, use a bucket with versioning disabled and a CAM sub-account restricted to
the selected prefix:

1. Sync the same initial KDBX on devices A and B.
2. Change username on A and URL on B while both are offline. Reconnect and sync
   both; the final entry must contain both edits and no conflict.
3. Change the same password field differently on A and B. Sync both; the
   conflict center must show one protected-field conflict. Pick each version in
   turn and verify the chosen result reaches the other device.
4. Edit an entry on A and delete it on B. Sync; the edited entry must remain
   available until the user explicitly keeps it or accepts deletion.
5. Add/change an attachment independently on both devices. Sync must stop with
   the attachment-conflict status and the remote object must remain unchanged.
6. Start simultaneous syncs and force one stale ETag. The losing transaction
   must retry and preserve both changes; it must never issue an unconditional
   `PUT`.
7. Restore a local encrypted backup. Confirm auto-sync pauses across restart,
   ordinary sync is rejected, and both explicit recovery choices behave as
   described above.
8. Export diagnostics and inspect the JSON. It must contain only timestamps,
   stages, stable error codes, durations, attempts, and aggregate counts.
9. For COS, hide one newly created commit from a device's list result, create a
   second branch, then make both visible. The next sync must merge both and no
   existing object key may be replaced.

The Rust regression suite covers field merge, conflict preservation and
resolution, delete/edit behavior, workspace mismatch, attachment fail-closed,
stale-ETag retry, remote creation protection, verification, backup rotation,
state persistence, and diagnostics redaction.
