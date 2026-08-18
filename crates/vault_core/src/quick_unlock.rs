use std::{collections::BTreeMap, fmt};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload, consts::U12},
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{Result, VaultError};

const ENVELOPE_MAGIC: &[u8; 4] = b"AVQE";
const KEYRING_MAGIC: &[u8; 4] = b"AVQK";
const FORMAT_VERSION: u8 = 1;
const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const MAX_KEYRING_ENTRIES: usize = 1_024;
const AAD_PREFIX: &[u8] = b"top.llklkl.authenticatorvault/quick-unlock/v1\0";

pub struct QuickUnlockEnrollment {
    pub envelope: Zeroizing<Vec<u8>>,
    pub updated_keyring: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for QuickUnlockEnrollment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QuickUnlockEnrollment")
            .field("envelope", &"[REDACTED]")
            .field("updated_keyring", &"[REDACTED]")
            .finish()
    }
}

pub fn prepare_quick_unlock(
    master_password: &str,
    workspace_id: Uuid,
    existing_keyring: Option<&[u8]>,
) -> Result<QuickUnlockEnrollment> {
    let mut key = Zeroizing::new([0_u8; KEY_SIZE]);
    getrandom::fill(&mut *key).map_err(|_| VaultError::QuickUnlock)?;
    let envelope = seal_master_password(master_password, workspace_id, &*key)?;
    let mut keyring = match existing_keyring {
        Some(bytes) => decode_keyring(bytes)?,
        None => BTreeMap::new(),
    };
    if keyring.len() >= MAX_KEYRING_ENTRIES && !keyring.contains_key(&workspace_id) {
        return Err(VaultError::QuickUnlock);
    }
    keyring.insert(workspace_id, *key);
    Ok(QuickUnlockEnrollment {
        envelope,
        updated_keyring: Zeroizing::new(encode_keyring(&keyring)?),
    })
}

pub fn remove_quick_unlock(keyring: &[u8], workspace_id: Uuid) -> Result<Zeroizing<Vec<u8>>> {
    let mut entries = decode_keyring(keyring)?;
    entries.remove(&workspace_id);
    Ok(Zeroizing::new(encode_keyring(&entries)?))
}

pub fn quick_unlock_key(keyring: &[u8], workspace_id: Uuid) -> Result<Zeroizing<[u8; 32]>> {
    let entries = decode_keyring(keyring)?;
    entries
        .get(&workspace_id)
        .copied()
        .map(Zeroizing::new)
        .ok_or(VaultError::QuickUnlock)
}

pub fn unseal_quick_unlock(
    envelope: &[u8],
    workspace_id: Uuid,
    key: &[u8],
) -> Result<Zeroizing<String>> {
    if key.len() != KEY_SIZE
        || envelope.len() < ENVELOPE_MAGIC.len() + 1 + NONCE_SIZE + TAG_SIZE
        || envelope.get(..4) != Some(ENVELOPE_MAGIC)
        || envelope.get(4) != Some(&FORMAT_VERSION)
    {
        return Err(VaultError::QuickUnlock);
    }
    let nonce = envelope
        .get(5..5 + NONCE_SIZE)
        .ok_or(VaultError::QuickUnlock)?;
    let ciphertext = envelope
        .get(5 + NONCE_SIZE..)
        .ok_or(VaultError::QuickUnlock)?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| VaultError::QuickUnlock)?;
    let nonce = <&Nonce<U12>>::try_from(nonce).map_err(|_| VaultError::QuickUnlock)?;
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &aad(workspace_id),
            },
        )
        .map_err(|_| VaultError::QuickUnlock)?;
    String::from_utf8(plaintext)
        .map(Zeroizing::new)
        .map_err(|_| VaultError::QuickUnlock)
}

fn seal_master_password(
    master_password: &str,
    workspace_id: Uuid,
    key: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| VaultError::QuickUnlock)?;
    let mut nonce = [0_u8; NONCE_SIZE];
    getrandom::fill(&mut nonce).map_err(|_| VaultError::QuickUnlock)?;
    let nonce_ref =
        <&Nonce<U12>>::try_from(nonce.as_slice()).map_err(|_| VaultError::QuickUnlock)?;
    let ciphertext = cipher
        .encrypt(
            nonce_ref,
            Payload {
                msg: master_password.as_bytes(),
                aad: &aad(workspace_id),
            },
        )
        .map_err(|_| VaultError::QuickUnlock)?;
    let mut envelope = Vec::with_capacity(5 + NONCE_SIZE + ciphertext.len());
    envelope.extend_from_slice(ENVELOPE_MAGIC);
    envelope.push(FORMAT_VERSION);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(Zeroizing::new(envelope))
}

fn aad(workspace_id: Uuid) -> Vec<u8> {
    let mut value = Vec::with_capacity(AAD_PREFIX.len() + 16);
    value.extend_from_slice(AAD_PREFIX);
    value.extend_from_slice(workspace_id.as_bytes());
    value
}

fn encode_keyring(entries: &BTreeMap<Uuid, [u8; KEY_SIZE]>) -> Result<Vec<u8>> {
    let count = u16::try_from(entries.len()).map_err(|_| VaultError::QuickUnlock)?;
    let mut bytes = Vec::with_capacity(7 + entries.len() * (16 + KEY_SIZE));
    bytes.extend_from_slice(KEYRING_MAGIC);
    bytes.push(FORMAT_VERSION);
    bytes.extend_from_slice(&count.to_be_bytes());
    for (workspace_id, key) in entries {
        bytes.extend_from_slice(workspace_id.as_bytes());
        bytes.extend_from_slice(key);
    }
    Ok(bytes)
}

fn decode_keyring(bytes: &[u8]) -> Result<BTreeMap<Uuid, [u8; KEY_SIZE]>> {
    if bytes.len() < 7
        || bytes.get(..4) != Some(KEYRING_MAGIC)
        || bytes.get(4) != Some(&FORMAT_VERSION)
    {
        return Err(VaultError::QuickUnlock);
    }
    let count = usize::from(u16::from_be_bytes([
        *bytes.get(5).ok_or(VaultError::QuickUnlock)?,
        *bytes.get(6).ok_or(VaultError::QuickUnlock)?,
    ]));
    if count > MAX_KEYRING_ENTRIES || bytes.len() != 7 + count * (16 + KEY_SIZE) {
        return Err(VaultError::QuickUnlock);
    }
    let mut entries = BTreeMap::new();
    let mut cursor = 7;
    for _ in 0..count {
        let id_end = cursor + 16;
        let workspace_id =
            Uuid::from_slice(bytes.get(cursor..id_end).ok_or(VaultError::QuickUnlock)?)
                .map_err(|_| VaultError::QuickUnlock)?;
        cursor = id_end;
        let key_end = cursor + KEY_SIZE;
        let mut key = [0_u8; KEY_SIZE];
        key.copy_from_slice(bytes.get(cursor..key_end).ok_or(VaultError::QuickUnlock)?);
        cursor = key_end;
        if entries.insert(workspace_id, key).is_some() {
            return Err(VaultError::QuickUnlock);
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_updates_independent_workspace_keys() {
        let first_id = Uuid::new_v4();
        let second_id = Uuid::new_v4();
        let first = prepare_quick_unlock("first password", first_id, None).unwrap();
        let second =
            prepare_quick_unlock("second password", second_id, Some(&first.updated_keyring))
                .unwrap();

        let first_key = quick_unlock_key(&second.updated_keyring, first_id).unwrap();
        let second_key = quick_unlock_key(&second.updated_keyring, second_id).unwrap();
        assert_ne!(&*first_key, &*second_key);
        assert_eq!(
            &*unseal_quick_unlock(&first.envelope, first_id, &*first_key).unwrap(),
            "first password"
        );
        assert_eq!(
            &*unseal_quick_unlock(&second.envelope, second_id, &*second_key).unwrap(),
            "second password"
        );
    }

    #[test]
    fn rejects_wrong_workspace_key_tampering_and_unknown_version() {
        let id = Uuid::new_v4();
        let other_id = Uuid::new_v4();
        let enrolled = prepare_quick_unlock("password", id, None).unwrap();
        let key = quick_unlock_key(&enrolled.updated_keyring, id).unwrap();
        assert!(unseal_quick_unlock(&enrolled.envelope, other_id, &*key).is_err());

        let mut tampered = enrolled.envelope.to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(unseal_quick_unlock(&tampered, id, &*key).is_err());
        tampered = enrolled.envelope.to_vec();
        tampered[4] = 2;
        assert!(unseal_quick_unlock(&tampered, id, &*key).is_err());
        assert!(unseal_quick_unlock(&enrolled.envelope[..8], id, &*key).is_err());
    }

    #[test]
    fn removes_workspace_and_redacts_debug_output() {
        let id = Uuid::new_v4();
        let enrolled = prepare_quick_unlock("visible marker", id, None).unwrap();
        let empty = remove_quick_unlock(&enrolled.updated_keyring, id).unwrap();
        assert!(quick_unlock_key(&empty, id).is_err());
        let debug = format!("{enrolled:?}");
        assert!(!debug.contains("visible marker"));
        assert!(!debug.contains(&data_encoding::HEXLOWER.encode(&enrolled.envelope)));
    }
}
