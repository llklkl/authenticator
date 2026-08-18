use std::fmt;

use bip39::Language;
use zeroize::Zeroizing;

use crate::{Result, VaultError};

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?";
const AMBIGUOUS: &[u8] = b"Il1O0o|`'\"";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordGeneratorRequest {
    Random {
        length: usize,
        lowercase: bool,
        uppercase: bool,
        digits: bool,
        symbols: bool,
        exclude_ambiguous: bool,
    },
    Passphrase {
        word_count: usize,
        separator: String,
        capitalize: bool,
        include_number: bool,
    },
}

#[derive(Clone, PartialEq, Eq)]
pub struct GeneratedPassword {
    pub value: Zeroizing<String>,
    pub entropy_bits: u32,
}

impl fmt::Debug for GeneratedPassword {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GeneratedPassword")
            .field("value", &"[REDACTED]")
            .field("entropy_bits", &self.entropy_bits)
            .finish()
    }
}

pub fn generate_password(request: &PasswordGeneratorRequest) -> Result<GeneratedPassword> {
    match request {
        PasswordGeneratorRequest::Random {
            length,
            lowercase,
            uppercase,
            digits,
            symbols,
            exclude_ambiguous,
        } => generate_random(
            *length,
            [*lowercase, *uppercase, *digits, *symbols],
            *exclude_ambiguous,
        ),
        PasswordGeneratorRequest::Passphrase {
            word_count,
            separator,
            capitalize,
            include_number,
        } => generate_passphrase(*word_count, separator, *capitalize, *include_number),
    }
}

fn generate_random(
    length: usize,
    enabled: [bool; 4],
    exclude_ambiguous: bool,
) -> Result<GeneratedPassword> {
    if !(12..=128).contains(&length) || !enabled.iter().any(|value| *value) {
        return Err(VaultError::InvalidGeneratorRequest);
    }
    let source_sets = [LOWER, UPPER, DIGITS, SYMBOLS];
    let sets: Vec<Vec<u8>> = source_sets
        .into_iter()
        .zip(enabled)
        .filter(|(_, enabled)| *enabled)
        .map(|(set, _)| {
            set.iter()
                .copied()
                .filter(|value| !exclude_ambiguous || !AMBIGUOUS.contains(value))
                .collect()
        })
        .collect();
    if sets.is_empty() || sets.iter().any(Vec::is_empty) || length < sets.len() {
        return Err(VaultError::InvalidGeneratorRequest);
    }
    let pool: Vec<u8> = sets.iter().flatten().copied().collect();
    let mut output = Vec::with_capacity(length);
    for set in &sets {
        output.push(set[random_index(set.len())?]);
    }
    while output.len() < length {
        output.push(pool[random_index(pool.len())?]);
    }
    for index in (1..output.len()).rev() {
        let swap = random_index(index + 1)?;
        output.swap(index, swap);
    }
    let entropy_bits = ((length as f64) * (pool.len() as f64).log2()).floor() as u32;
    let value = String::from_utf8(output).map_err(|_| VaultError::InvalidGeneratorRequest)?;
    Ok(GeneratedPassword {
        value: Zeroizing::new(value),
        entropy_bits,
    })
}

fn generate_passphrase(
    word_count: usize,
    separator: &str,
    capitalize: bool,
    include_number: bool,
) -> Result<GeneratedPassword> {
    if !(4..=12).contains(&word_count)
        || separator.chars().count() > 3
        || separator.chars().any(char::is_control)
    {
        return Err(VaultError::InvalidGeneratorRequest);
    }
    let words = Language::English.word_list();
    let mut selected = Vec::with_capacity(word_count);
    for _ in 0..word_count {
        let mut word = words[random_index(words.len())?].to_owned();
        if capitalize {
            let first = word.remove(0).to_ascii_uppercase();
            word.insert(0, first);
        }
        selected.push(word);
    }
    let mut value = selected.join(separator);
    if include_number {
        value.push_str(separator);
        value.push(char::from(b'0' + random_index(10)? as u8));
    }
    Ok(GeneratedPassword {
        value: Zeroizing::new(value),
        entropy_bits: word_count as u32 * 11 + u32::from(include_number) * 3,
    })
}

fn random_index(bound: usize) -> Result<usize> {
    let bound = u64::try_from(bound).map_err(|_| VaultError::InvalidGeneratorRequest)?;
    if bound == 0 {
        return Err(VaultError::InvalidGeneratorRequest);
    }
    let zone = u64::MAX - (u64::MAX % bound);
    loop {
        let mut bytes = [0_u8; 8];
        getrandom::fill(&mut bytes).map_err(|_| VaultError::InvalidGeneratorRequest)?;
        let value = u64::from_le_bytes(bytes);
        if value < zone {
            return usize::try_from(value % bound).map_err(|_| VaultError::InvalidGeneratorRequest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_password_obeys_all_selected_classes() {
        let generated = generate_password(&PasswordGeneratorRequest::Random {
            length: 24,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: true,
        })
        .unwrap();
        assert_eq!(generated.value.len(), 24);
        assert!(generated.value.bytes().any(|value| LOWER.contains(&value)));
        assert!(generated.value.bytes().any(|value| UPPER.contains(&value)));
        assert!(generated.value.bytes().any(|value| DIGITS.contains(&value)));
        assert!(
            generated
                .value
                .bytes()
                .any(|value| SYMBOLS.contains(&value))
        );
        assert!(
            !generated
                .value
                .bytes()
                .any(|value| AMBIGUOUS.contains(&value))
        );
        assert!(!format!("{generated:?}").contains(generated.value.as_str()));
    }

    #[test]
    fn passphrase_uses_requested_shape() {
        let generated = generate_password(&PasswordGeneratorRequest::Passphrase {
            word_count: 6,
            separator: "-".into(),
            capitalize: true,
            include_number: true,
        })
        .unwrap();
        assert_eq!(generated.value.split('-').count(), 7);
        assert!(generated.entropy_bits >= 69);
    }

    #[test]
    fn invalid_requests_fail_closed() {
        assert_eq!(
            generate_password(&PasswordGeneratorRequest::Random {
                length: 4,
                lowercase: true,
                uppercase: false,
                digits: false,
                symbols: false,
                exclude_ambiguous: false,
            }),
            Err(VaultError::InvalidGeneratorRequest)
        );
    }
}
