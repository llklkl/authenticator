use std::{collections::BTreeMap, fmt, path::PathBuf};

use uuid::Uuid;

use crate::{Result, VaultError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorkspaceId(Uuid);

impl WorkspaceId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
    pub fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for WorkspaceId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncProviderKind {
    None,
    WebDav,
    S3,
    LocalDirectory,
}

#[derive(Clone, PartialEq, Eq)]
pub struct WorkspaceMetadata {
    pub id: WorkspaceId,
    pub name: String,
    pub color_argb: u32,
    pub icon: String,
    pub vault_path: PathBuf,
    pub sync_provider: SyncProviderKind,
    pub quick_unlock_enabled: bool,
}

impl WorkspaceMetadata {
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() || self.vault_path.as_os_str().is_empty() {
            return Err(VaultError::InvalidWorkspace);
        }
        Ok(())
    }
}

impl fmt::Debug for WorkspaceMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkspaceMetadata")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("color_argb", &self.color_argb)
            .field("icon", &self.icon)
            .field("vault_path", &"[REDACTED]")
            .field("sync_provider", &self.sync_provider)
            .field("quick_unlock_enabled", &self.quick_unlock_enabled)
            .finish()
    }
}

#[derive(Debug, Default)]
pub struct WorkspaceRegistry {
    workspaces: BTreeMap<WorkspaceId, WorkspaceMetadata>,
}

impl WorkspaceRegistry {
    pub fn add(&mut self, workspace: WorkspaceMetadata) -> Result<()> {
        workspace.validate()?;
        if self.workspaces.contains_key(&workspace.id) {
            return Err(VaultError::DuplicateWorkspace);
        }
        self.workspaces.insert(workspace.id, workspace);
        Ok(())
    }

    pub fn get(&self, id: WorkspaceId) -> Result<&WorkspaceMetadata> {
        self.workspaces
            .get(&id)
            .ok_or(VaultError::WorkspaceNotFound)
    }

    pub fn remove(&mut self, id: WorkspaceId) -> Result<WorkspaceMetadata> {
        self.workspaces
            .remove(&id)
            .ok_or(VaultError::WorkspaceNotFound)
    }

    pub fn list(&self) -> impl Iterator<Item = &WorkspaceMetadata> {
        self.workspaces.values()
    }
    pub fn len(&self) -> usize {
        self.workspaces.len()
    }
    pub fn is_empty(&self) -> bool {
        self.workspaces.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace(id: WorkspaceId) -> WorkspaceMetadata {
        WorkspaceMetadata {
            id,
            name: "Personal".into(),
            color_argb: 0xff_336699,
            icon: "person".into(),
            vault_path: PathBuf::from("personal.kdbx"),
            sync_provider: SyncProviderKind::WebDav,
            quick_unlock_enabled: true,
        }
    }

    #[test]
    fn rejects_duplicate_ids() {
        let id = WorkspaceId::new();
        let mut registry = WorkspaceRegistry::default();
        registry.add(workspace(id)).unwrap();
        assert_eq!(
            registry.add(workspace(id)),
            Err(VaultError::DuplicateWorkspace)
        );
    }

    #[test]
    fn metadata_debug_redacts_local_path() {
        let debug = format!("{:?}", workspace(WorkspaceId::new()));
        assert!(!debug.contains("personal.kdbx"));
    }
}
