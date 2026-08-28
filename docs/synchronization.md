# Synchronization, conflicts, and recovery

Each workspace owns an independent sync-state directory. It contains an
encrypted `base.kdbx`, versioned non-secret `state.json`, rolling redacted
`diagnostics.json`, and encrypted KDBX backups. None of these files contains a
plaintext master password, OTP seed, entry value, URL, or WebDAV credential.

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

Use a disposable workspace and WebDAV path:

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

The Rust regression suite covers field merge, conflict preservation and
resolution, delete/edit behavior, workspace mismatch, attachment fail-closed,
stale-ETag retry, remote creation protection, verification, backup rotation,
state persistence, and diagnostics redaction.
