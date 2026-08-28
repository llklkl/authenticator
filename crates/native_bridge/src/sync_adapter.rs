use std::fmt;

use sync_core::{MergeOutput, MergeReport, Result, SyncError, VaultMerger};
use vault_core::KdbxEngine;
use zeroize::Zeroizing;

/// Connects the provider-neutral sync state machine to KDBX UUID/history merge.
pub struct KdbxVaultMerger {
    password: Zeroizing<String>,
}

impl KdbxVaultMerger {
    pub fn new(password: String) -> Self {
        Self {
            password: Zeroizing::new(password),
        }
    }
}

impl fmt::Debug for KdbxVaultMerger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KdbxVaultMerger")
            .field("password", &"[REDACTED]")
            .finish()
    }
}

impl VaultMerger for KdbxVaultMerger {
    fn merge(&self, base: Option<&[u8]>, local: &[u8], remote: &[u8]) -> Result<MergeOutput> {
        let output = KdbxEngine
            .three_way_merge_encrypted(base, local, remote, &self.password)
            .map_err(map_vault_merge_error)?;
        Ok(MergeOutput {
            encrypted_bytes: output.encrypted_bytes,
            report: MergeReport {
                auto_merged_objects: output.report.auto_merged_objects,
                created_conflicts: u32::try_from(output.report.created_conflicts.len())
                    .unwrap_or(u32::MAX),
                pending_conflicts: output.report.pending_conflicts,
                baseline_rebuilt: output.report.baseline_rebuilt,
            },
            requires_upload: output.requires_upload,
        })
    }
}

fn map_vault_merge_error(error: vault_core::VaultError) -> SyncError {
    match error {
        vault_core::VaultError::RemoteVaultMismatch => SyncError::RemoteVaultMismatch,
        vault_core::VaultError::AttachmentMergeUnsupported => {
            SyncError::AttachmentConflictUnsupported
        }
        _ => SyncError::Merge,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_database_password() {
        let merger = KdbxVaultMerger::new("private-password".into());
        assert!(!format!("{merger:?}").contains("private-password"));
    }
}
