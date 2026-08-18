use std::fmt;

use uuid::Uuid;
use zeroize::Zeroizing;

use crate::OtpConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Login,
    Otp,
    RecoveryCodes,
    SecureNote,
}

#[derive(Clone, PartialEq, Eq)]
pub struct VaultEntry {
    pub id: Uuid,
    pub kind: EntryKind,
    pub title: String,
    pub username: String,
    password: Zeroizing<String>,
    pub url: String,
    notes: Zeroizing<String>,
    pub tags: Vec<String>,
    pub otp: Option<OtpConfig>,
    pub modified_at_unix_ms: i64,
}

impl VaultEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: EntryKind,
        title: String,
        username: String,
        password: Zeroizing<String>,
        url: String,
        notes: Zeroizing<String>,
        tags: Vec<String>,
        otp: Option<OtpConfig>,
        modified_at_unix_ms: i64,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            kind,
            title,
            username,
            password,
            url,
            notes,
            tags,
            otp,
            modified_at_unix_ms,
        }
    }

    pub fn password(&self) -> &str {
        &self.password
    }
    pub fn notes(&self) -> &str {
        &self.notes
    }

    pub fn summary(&self) -> EntrySummary {
        EntrySummary {
            id: self.id,
            kind: self.kind,
            title: self.title.clone(),
            username: self.username.clone(),
            has_password: !self.password.is_empty(),
            has_otp: self.otp.is_some(),
            tags: self.tags.clone(),
            modified_at_unix_ms: self.modified_at_unix_ms,
        }
    }
}

impl fmt::Debug for VaultEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultEntry")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("title", &self.title)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("url", &self.url)
            .field("notes", &"[REDACTED]")
            .field("tags", &self.tags)
            .field("otp", &self.otp.as_ref().map(|_| "[CONFIGURED]"))
            .field("modified_at_unix_ms", &self.modified_at_unix_ms)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntrySummary {
    pub id: Uuid,
    pub kind: EntryKind,
    pub title: String,
    pub username: String,
    pub has_password: bool,
    pub has_otp: bool,
    pub tags: Vec<String>,
    pub modified_at_unix_ms: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_redacts_sensitive_fields() {
        let entry = VaultEntry::new(
            EntryKind::Login,
            "Example".into(),
            "alice".into(),
            Zeroizing::new("password-value".into()),
            "https://example.com".into(),
            Zeroizing::new("private-note".into()),
            vec![],
            None,
            0,
        );
        let debug = format!("{entry:?}");
        assert!(!debug.contains("password-value"));
        assert!(!debug.contains("private-note"));
    }
}
