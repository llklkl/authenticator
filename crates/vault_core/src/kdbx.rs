use std::{fmt, io::Cursor};

use keepass::{
    Database, DatabaseKey,
    db::{EntryId, fields},
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{OtpConfig, Result, VaultEntry, VaultError};

/// A decrypted database whose internal representation never crosses the FFI boundary.
pub struct KdbxDatabase {
    inner: Database,
}

impl Clone for KdbxDatabase {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

const KIND_FIELD: &str = "Authenticator.EntryKind";
const MODIFIED_AT_FIELD: &str = "Authenticator.ModifiedAtUnixMs";

impl fmt::Debug for KdbxDatabase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KdbxDatabase")
            .field("entry_count", &self.inner.num_entries())
            .field("group_count", &self.inner.num_groups())
            .field("content", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdbxEntryRecord {
    pub id: Uuid,
    pub kind: crate::EntryKind,
    pub title: String,
    pub username: String,
    pub url: String,
    pub has_password: bool,
    pub has_otp: bool,
    pub tags: Vec<String>,
    pub modified_at_unix_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntrySecretField {
    Password,
    Notes,
}

/// KDBX 4.1 adapter. Upstream types are deliberately contained in this module.
#[derive(Debug, Default, Clone, Copy)]
pub struct KdbxEngine;

impl KdbxEngine {
    pub fn create(&self, root_name: &str) -> Result<KdbxDatabase> {
        if root_name.trim().is_empty() {
            return Err(VaultError::InvalidKdbx);
        }
        let mut inner = Database::new();
        inner.root_mut().name = root_name.to_owned();
        Ok(KdbxDatabase { inner })
    }

    pub fn open(&self, encrypted_bytes: &[u8], password: &str) -> Result<KdbxDatabase> {
        let key = DatabaseKey::new().with_password(password);
        let inner = Database::open(&mut Cursor::new(encrypted_bytes), key)
            .map_err(|_| VaultError::KdbxOpen)?;
        Ok(KdbxDatabase { inner })
    }

    pub fn save(&self, database: &KdbxDatabase, password: &str) -> Result<Zeroizing<Vec<u8>>> {
        let mut encrypted_bytes = Vec::new();
        let key = DatabaseKey::new().with_password(password);
        database
            .inner
            .save(&mut encrypted_bytes, key)
            .map_err(|_| VaultError::KdbxSave)?;
        Ok(Zeroizing::new(encrypted_bytes))
    }

    pub fn add_entry(&self, database: &mut KdbxDatabase, entry: &VaultEntry) -> Result<()> {
        let id = EntryId::from_uuid(entry.id);
        let mut root = database.inner.root_mut();
        let mut target = root
            .add_entry_with_id(id)
            .map_err(|_| VaultError::InvalidKdbx)?;
        target.set_unprotected(fields::TITLE, &entry.title);
        target.set_unprotected(fields::USERNAME, &entry.username);
        target.set_protected(fields::PASSWORD, entry.password());
        target.set_unprotected(fields::URL, &entry.url);
        target.set_protected(fields::NOTES, entry.notes());
        target.set_unprotected(KIND_FIELD, kind_name(entry.kind));
        target.set_unprotected(MODIFIED_AT_FIELD, entry.modified_at_unix_ms.to_string());
        target.tags.clone_from(&entry.tags);
        if let Some(otp) = &entry.otp {
            target.set_protected(fields::OTP, otp.protected_uri().as_str());
        }
        Ok(())
    }

    pub fn entries(&self, database: &KdbxDatabase) -> Vec<KdbxEntryRecord> {
        database
            .inner
            .iter_all_entries()
            .map(|entry| KdbxEntryRecord {
                id: entry.id().uuid(),
                kind: read_kind(&entry),
                title: entry.get_title().unwrap_or_default().to_owned(),
                username: entry.get_username().unwrap_or_default().to_owned(),
                url: entry.get_url().unwrap_or_default().to_owned(),
                has_password: entry.get_password().is_some_and(|value| !value.is_empty()),
                has_otp: entry
                    .get_raw_otp_value()
                    .is_some_and(|value| !value.is_empty()),
                tags: entry.tags.clone(),
                modified_at_unix_ms: entry
                    .get(MODIFIED_AT_FIELD)
                    .and_then(|value| value.parse().ok())
                    .unwrap_or_default(),
            })
            .collect()
    }

    pub fn update_entry(&self, database: &mut KdbxDatabase, entry: &VaultEntry) -> Result<()> {
        let mut target = database
            .inner
            .entry_mut(EntryId::from_uuid(entry.id))
            .ok_or(VaultError::EntryNotFound)?;
        let mut tracked = target.track_changes();
        tracked.set_unprotected(fields::TITLE, &entry.title);
        tracked.set_unprotected(fields::USERNAME, &entry.username);
        tracked.set_protected(fields::PASSWORD, entry.password());
        tracked.set_unprotected(fields::URL, &entry.url);
        tracked.set_protected(fields::NOTES, entry.notes());
        tracked.set_unprotected(KIND_FIELD, kind_name(entry.kind));
        tracked.set_unprotected(MODIFIED_AT_FIELD, entry.modified_at_unix_ms.to_string());
        tracked.tags.clone_from(&entry.tags);
        if let Some(otp) = &entry.otp {
            tracked.set_protected(fields::OTP, otp.protected_uri().as_str());
        } else {
            tracked.fields.remove(fields::OTP);
        }
        Ok(())
    }

    pub fn remove_entry(&self, database: &mut KdbxDatabase, id: Uuid) -> Result<()> {
        let mut entry = database
            .inner
            .entry_mut(EntryId::from_uuid(id))
            .ok_or(VaultError::EntryNotFound)?;
        entry.track_changes().remove();
        Ok(())
    }

    pub fn reveal_field(
        &self,
        database: &KdbxDatabase,
        id: Uuid,
        field: EntrySecretField,
    ) -> Result<Zeroizing<String>> {
        let entry = database
            .inner
            .entry(EntryId::from_uuid(id))
            .ok_or(VaultError::EntryNotFound)?;
        let value = match field {
            EntrySecretField::Password => entry.get_password(),
            EntrySecretField::Notes => entry.get(fields::NOTES),
        }
        .ok_or(VaultError::FieldUnavailable)?;
        Ok(Zeroizing::new(value.to_owned()))
    }

    pub fn otp_config(&self, database: &KdbxDatabase, id: Uuid) -> Result<OtpConfig> {
        let entry = database
            .inner
            .entry(EntryId::from_uuid(id))
            .ok_or(VaultError::EntryNotFound)?;
        let uri = entry
            .get_raw_otp_value()
            .ok_or(VaultError::FieldUnavailable)?;
        OtpConfig::from_uri(uri)
    }

    pub fn merge(&self, target: &mut KdbxDatabase, source: &KdbxDatabase) -> Result<()> {
        target
            .inner
            .merge(&source.inner)
            .map_err(|_| VaultError::InvalidKdbx)?;
        Ok(())
    }

    /// Merge two encrypted replicas and re-encrypt the result with the same key.
    pub fn merge_encrypted(
        &self,
        local: &[u8],
        remote: &[u8],
        password: &str,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let mut target = self.open(local, password)?;
        let source = self.open(remote, password)?;
        self.merge(&mut target, &source)?;
        self.save(&target, password)
    }
}

fn kind_name(kind: crate::EntryKind) -> &'static str {
    match kind {
        crate::EntryKind::Login => "login",
        crate::EntryKind::Otp => "otp",
        crate::EntryKind::RecoveryCodes => "recovery_codes",
        crate::EntryKind::SecureNote => "secure_note",
    }
}

fn read_kind(entry: &keepass::db::EntryRef<'_>) -> crate::EntryKind {
    match entry.get(KIND_FIELD) {
        Some("otp") => crate::EntryKind::Otp,
        Some("recovery_codes") => crate::EntryKind::RecoveryCodes,
        Some("secure_note") => crate::EntryKind::SecureNote,
        Some("login") => crate::EntryKind::Login,
        _ if entry.get_raw_otp_value().is_some() && entry.get_password().is_none() => {
            crate::EntryKind::Otp
        }
        _ => crate::EntryKind::Login,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EntryKind, OtpConfig};

    fn sample_entry() -> VaultEntry {
        VaultEntry::new(
            EntryKind::Login,
            "Example".into(),
            "alice@example.com".into(),
            Zeroizing::new("correct horse battery staple".into()),
            "https://example.com".into(),
            Zeroizing::new("private note".into()),
            vec!["personal".into()],
            Some(
                OtpConfig::from_uri(
                    "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example",
                )
                .unwrap(),
            ),
            0,
        )
    }

    #[test]
    fn creates_saves_and_reopens_kdbx4_with_otp() {
        let engine = KdbxEngine;
        let mut database = engine.create("Personal").unwrap();
        let entry = sample_entry();
        engine.add_entry(&mut database, &entry).unwrap();

        let encrypted = engine.save(&database, "test master password").unwrap();
        assert!(encrypted.starts_with(&[0x03, 0xd9, 0xa2, 0x9a]));

        let opened = engine.open(&encrypted, "test master password").unwrap();
        assert_eq!(
            engine.entries(&opened),
            vec![KdbxEntryRecord {
                id: entry.id,
                kind: EntryKind::Login,
                title: "Example".into(),
                username: "alice@example.com".into(),
                url: "https://example.com".into(),
                has_password: true,
                has_otp: true,
                tags: vec!["personal".into()],
                modified_at_unix_ms: 0,
            }]
        );
        assert!(matches!(
            engine.open(&encrypted, "wrong password"),
            Err(VaultError::KdbxOpen)
        ));
    }

    #[test]
    fn preserves_unknown_protected_fields_across_round_trip() {
        let engine = KdbxEngine;
        let mut database = engine.create("Personal").unwrap();
        database
            .inner
            .root_mut()
            .add_entry()
            .set_protected("Authenticator.Unknown", "preserve-me");

        let first = engine.save(&database, "password").unwrap();
        let opened = engine.open(&first, "password").unwrap();
        let second = engine.save(&opened, "password").unwrap();
        let reopened = engine.open(&second, "password").unwrap();
        let entry = reopened.inner.iter_all_entries().next().unwrap();
        assert_eq!(entry.get("Authenticator.Unknown"), Some("preserve-me"));
    }

    #[test]
    fn merges_independently_added_entries_from_encrypted_replicas() {
        let engine = KdbxEngine;
        let base = engine.create("Personal").unwrap();
        let encrypted_base = engine.save(&base, "password").unwrap();
        let mut local = engine.open(&encrypted_base, "password").unwrap();
        let mut remote = engine.open(&encrypted_base, "password").unwrap();

        let local_entry = sample_entry();
        engine.add_entry(&mut local, &local_entry).unwrap();
        let mut remote_entry = sample_entry();
        remote_entry.id = Uuid::new_v4();
        remote_entry.title = "Remote".into();
        engine.add_entry(&mut remote, &remote_entry).unwrap();

        let local_bytes = engine.save(&local, "password").unwrap();
        let remote_bytes = engine.save(&remote, "password").unwrap();
        let merged = engine
            .merge_encrypted(&local_bytes, &remote_bytes, "password")
            .unwrap();
        let reopened = engine.open(&merged, "password").unwrap();
        let records = engine.entries(&reopened);
        assert_eq!(records.len(), 2);
        assert!(records.iter().any(|entry| entry.title == "Example"));
        assert!(records.iter().any(|entry| entry.title == "Remote"));
    }

    #[test]
    fn updates_reveals_and_removes_entries_with_history() {
        let engine = KdbxEngine;
        let mut database = engine.create("Personal").unwrap();
        let mut entry = sample_entry();
        engine.add_entry(&mut database, &entry).unwrap();

        entry.title = "Updated".into();
        entry.modified_at_unix_ms = 42;
        engine.update_entry(&mut database, &entry).unwrap();
        assert_eq!(engine.entries(&database)[0].title, "Updated");
        assert_eq!(engine.entries(&database)[0].modified_at_unix_ms, 42);
        assert_eq!(
            &*engine
                .reveal_field(&database, entry.id, EntrySecretField::Password)
                .unwrap(),
            "correct horse battery staple"
        );
        assert_eq!(
            engine.otp_config(&database, entry.id).unwrap().issuer(),
            "Example"
        );

        engine.remove_entry(&mut database, entry.id).unwrap();
        assert!(engine.entries(&database).is_empty());
        assert!(database.inner.deleted_objects.contains_key(&entry.id));
    }
}
