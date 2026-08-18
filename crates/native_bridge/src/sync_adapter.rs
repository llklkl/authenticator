use std::fmt;

use sync_core::{Result, SyncError, VaultMerger};
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
    fn merge(&self, local: &[u8], remote: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        KdbxEngine
            .merge_encrypted(local, remote, &self.password)
            .map_err(|_| SyncError::Merge)
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
