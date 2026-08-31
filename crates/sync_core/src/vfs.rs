use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::{Result, SyncError};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VfsPath(String);

impl VfsPath {
    pub fn root() -> Self {
        Self(String::new())
    }

    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty()
            || value.starts_with('/')
            || value.ends_with('/')
            || value.contains('\\')
            || value.contains('?')
            || value.contains('#')
            || value.chars().any(char::is_control)
            || value
                .split('/')
                .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        {
            return Err(SyncError::InvalidConfiguration);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn join(&self, child: &str) -> Result<Self> {
        if self.0.is_empty() {
            Self::new(child)
        } else {
            Self::new(format!("{}/{child}", self.0))
        }
    }
}

impl std::fmt::Debug for VfsPath {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VfsPath([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct VfsRevision {
    token: String,
    pub content_sha256: [u8; 32],
    pub content_length: u64,
}

impl VfsRevision {
    pub fn new(token: String, content_sha256: [u8; 32], content_length: u64) -> Result<Self> {
        if token.trim().is_empty() || token.chars().any(char::is_control) {
            return Err(SyncError::Provider);
        }
        Ok(Self {
            token,
            content_sha256,
            content_length,
        })
    }

    pub fn token(&self) -> &str {
        &self.token
    }
}

impl std::fmt::Debug for VfsRevision {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VfsRevision")
            .field("token", &"[REDACTED]")
            .field("content_sha256", &self.content_sha256)
            .field("content_length", &self.content_length)
            .finish()
    }
}

pub struct VfsObject {
    pub revision: VfsRevision,
    pub bytes: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for VfsObject {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VfsObject")
            .field("revision", &self.revision)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VfsCapabilities {
    pub list: bool,
    pub create_only: bool,
    pub match_revision: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VfsListEntry {
    pub path: VfsPath,
    pub content_length: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct VfsListPage {
    pub entries: Vec<VfsListEntry>,
    pub continuation: Option<String>,
}

impl std::fmt::Debug for VfsListPage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VfsListPage")
            .field("entries", &self.entries)
            .field(
                "continuation",
                &self.continuation.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum WriteCondition<'a> {
    CreateOnly,
    Match(&'a VfsRevision),
}

#[async_trait]
pub trait RemoteVfs: Send + Sync {
    fn capabilities(&self) -> VfsCapabilities;

    async fn read(&self, path: &VfsPath) -> Result<VfsObject>;

    async fn list(&self, prefix: &VfsPath, continuation: Option<&str>) -> Result<VfsListPage>;

    async fn write(
        &self,
        path: &VfsPath,
        bytes: &[u8],
        condition: WriteCondition<'_>,
    ) -> Result<VfsRevision>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_reject_ambiguous_or_private_url_components() {
        for invalid in ["", "/root", "root/", "a//b", "a/../b", "a\\b", "a?token=x"] {
            assert_eq!(VfsPath::new(invalid), Err(SyncError::InvalidConfiguration));
        }
        assert_eq!(
            VfsPath::new("commits/a.json").unwrap().as_str(),
            "commits/a.json"
        );
        assert!(!format!("{:?}", VfsPath::new("private/path").unwrap()).contains("private"));
    }
}
