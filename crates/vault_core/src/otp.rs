use std::fmt;

use data_encoding::{BASE32_NOPAD, BASE64, BASE64URL};
use hmac::{Hmac, Mac};
use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use url::Url;
use zeroize::Zeroizing;

use crate::{Result, VaultError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpKind {
    Totp { period: u64 },
    Hotp { counter: u64 },
}

#[derive(Clone, PartialEq, Eq)]
pub struct OtpConfig {
    issuer: String,
    account: String,
    secret: Zeroizing<Vec<u8>>,
    algorithm: OtpAlgorithm,
    digits: u8,
    kind: OtpKind,
}

impl fmt::Debug for OtpConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OtpConfig")
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .field("secret", &"[REDACTED]")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("kind", &self.kind)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpCode {
    pub value: String,
    pub valid_for_seconds: Option<u64>,
    pub period_seconds: Option<u64>,
}

impl OtpConfig {
    pub fn from_uri(value: &str) -> Result<Self> {
        let uri = Url::parse(value).map_err(|_| VaultError::InvalidOtpUri)?;
        if uri.scheme() != "otpauth" {
            return Err(VaultError::InvalidOtpUri);
        }
        let otp_type = uri.host_str().ok_or(VaultError::InvalidOtpUri)?;
        let label = uri.path().strip_prefix('/').unwrap_or(uri.path());
        let label = percent_decode_str(label)
            .decode_utf8()
            .map_err(|_| VaultError::InvalidOtpUri)?;
        if label.trim().is_empty() {
            return Err(VaultError::InvalidOtpUri);
        }

        let mut secret = None;
        let mut issuer = None;
        let mut algorithm = OtpAlgorithm::Sha1;
        let mut digits = 6;
        let mut period = 30;
        let mut counter = None;
        for (key, value) in uri.query_pairs() {
            match key.as_ref() {
                "secret" => secret = Some(decode_secret(&value)?),
                "issuer" => issuer = Some(value.into_owned()),
                "algorithm" => {
                    algorithm = match value.to_ascii_uppercase().as_str() {
                        "SHA1" => OtpAlgorithm::Sha1,
                        "SHA256" => OtpAlgorithm::Sha256,
                        "SHA512" => OtpAlgorithm::Sha512,
                        _ => return Err(VaultError::UnsupportedOtpAlgorithm),
                    };
                }
                "digits" => digits = value.parse().map_err(|_| VaultError::InvalidOtpDigits)?,
                "period" => period = value.parse().map_err(|_| VaultError::InvalidOtpPeriod)?,
                "counter" => {
                    counter = Some(value.parse().map_err(|_| VaultError::InvalidHotpCounter)?)
                }
                _ => {}
            }
        }
        if !matches!(digits, 6 | 8) {
            return Err(VaultError::InvalidOtpDigits);
        }
        if period == 0 {
            return Err(VaultError::InvalidOtpPeriod);
        }

        let (label_issuer, account) = label
            .split_once(':')
            .map_or((None, label.as_ref()), |(left, right)| {
                (Some(left.trim()), right.trim())
            });
        if account.is_empty() {
            return Err(VaultError::InvalidOtpUri);
        }
        let issuer = issuer
            .or_else(|| label_issuer.map(ToOwned::to_owned))
            .unwrap_or_default();
        let kind = match otp_type {
            "totp" => OtpKind::Totp { period },
            "hotp" => OtpKind::Hotp {
                counter: counter.ok_or(VaultError::InvalidHotpCounter)?,
            },
            _ => return Err(VaultError::UnsupportedOtpType),
        };

        Ok(Self {
            issuer,
            account: account.to_owned(),
            secret: Zeroizing::new(secret.ok_or(VaultError::InvalidOtpSecret)?),
            algorithm,
            digits,
            kind,
        })
    }

    /// Parse all OTP records in one Google Authenticator migration QR payload.
    /// The decoded seeds remain inside Rust-owned `OtpConfig` values.
    pub fn from_migration_uri(value: &str) -> Result<Vec<Self>> {
        let uri = Url::parse(value).map_err(|_| VaultError::InvalidOtpUri)?;
        if uri.scheme() != "otpauth-migration" || uri.host_str() != Some("offline") {
            return Err(VaultError::InvalidOtpUri);
        }
        let encoded = uri
            .query()
            .and_then(|query| query.split('&').find_map(|part| part.strip_prefix("data=")))
            .ok_or(VaultError::InvalidOtpUri)?;
        let encoded = percent_decode_str(encoded)
            .decode_utf8()
            .map_err(|_| VaultError::InvalidOtpUri)?;
        let payload = BASE64URL
            .decode(encoded.as_bytes())
            .or_else(|_| BASE64.decode(encoded.as_bytes()))
            .map_err(|_| VaultError::InvalidOtpUri)?;
        parse_migration_payload(&payload)
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn account(&self) -> &str {
        &self.account
    }
    pub fn algorithm(&self) -> OtpAlgorithm {
        self.algorithm
    }
    pub fn digits(&self) -> u8 {
        self.digits
    }
    pub fn kind(&self) -> OtpKind {
        self.kind
    }

    pub fn code_at(&self, unix_seconds: i64) -> Result<OtpCode> {
        let seconds = u64::try_from(unix_seconds).map_err(|_| VaultError::InvalidTimestamp)?;
        let (counter, valid_for_seconds, period_seconds) = match self.kind {
            OtpKind::Totp { period } => (
                seconds / period,
                Some(period - seconds % period),
                Some(period),
            ),
            OtpKind::Hotp { counter } => (counter, None, None),
        };
        Ok(OtpCode {
            value: self.generate(counter)?,
            valid_for_seconds,
            period_seconds,
        })
    }

    pub fn advance_hotp(&mut self) -> Result<()> {
        match &mut self.kind {
            OtpKind::Hotp { counter } => {
                *counter = counter
                    .checked_add(1)
                    .ok_or(VaultError::InvalidHotpCounter)?;
                Ok(())
            }
            OtpKind::Totp { .. } => Err(VaultError::UnsupportedOtpType),
        }
    }

    pub(crate) fn protected_uri(&self) -> Zeroizing<String> {
        let otp_type = if matches!(self.kind, OtpKind::Totp { .. }) {
            "totp"
        } else {
            "hotp"
        };
        let label = if self.issuer.is_empty() {
            self.account.clone()
        } else {
            format!("{}:{}", self.issuer, self.account)
        };
        let mut uri = format!(
            "otpauth://{otp_type}/{}?secret={}",
            utf8_percent_encode(&label, NON_ALPHANUMERIC),
            BASE32_NOPAD.encode(&self.secret)
        );
        if !self.issuer.is_empty() {
            uri.push_str("&issuer=");
            uri.push_str(&utf8_percent_encode(&self.issuer, NON_ALPHANUMERIC).to_string());
        }
        uri.push_str(match self.algorithm {
            OtpAlgorithm::Sha1 => "&algorithm=SHA1",
            OtpAlgorithm::Sha256 => "&algorithm=SHA256",
            OtpAlgorithm::Sha512 => "&algorithm=SHA512",
        });
        uri.push_str(&format!("&digits={}", self.digits));
        match self.kind {
            OtpKind::Totp { period } => uri.push_str(&format!("&period={period}")),
            OtpKind::Hotp { counter } => uri.push_str(&format!("&counter={counter}")),
        }
        Zeroizing::new(uri)
    }

    fn generate(&self, counter: u64) -> Result<String> {
        let counter = counter.to_be_bytes();
        let digest = match self.algorithm {
            OtpAlgorithm::Sha1 => hmac_digest::<Hmac<Sha1>>(&self.secret, &counter)?,
            OtpAlgorithm::Sha256 => hmac_digest::<Hmac<Sha256>>(&self.secret, &counter)?,
            OtpAlgorithm::Sha512 => hmac_digest::<Hmac<Sha512>>(&self.secret, &counter)?,
        };
        let offset = usize::from(digest[digest.len() - 1] & 0x0f);
        let binary = (u32::from(digest[offset] & 0x7f) << 24)
            | (u32::from(digest[offset + 1]) << 16)
            | (u32::from(digest[offset + 2]) << 8)
            | u32::from(digest[offset + 3]);
        let modulus = 10_u32.pow(u32::from(self.digits));
        Ok(format!(
            "{:0width$}",
            binary % modulus,
            width = usize::from(self.digits)
        ))
    }
}

fn parse_migration_payload(payload: &[u8]) -> Result<Vec<OtpConfig>> {
    let mut cursor = 0;
    let mut configs = Vec::new();
    while cursor < payload.len() {
        let key = read_varint(payload, &mut cursor)?;
        let field = key >> 3;
        let wire = key & 7;
        if field == 1 && wire == 2 {
            let bytes = read_length_delimited(payload, &mut cursor)?;
            configs.push(parse_migration_parameter(bytes)?);
        } else {
            skip_protobuf_value(payload, &mut cursor, wire)?;
        }
    }
    if configs.is_empty() {
        return Err(VaultError::InvalidOtpUri);
    }
    Ok(configs)
}

fn parse_migration_parameter(bytes: &[u8]) -> Result<OtpConfig> {
    let mut cursor = 0;
    let mut secret = None;
    let mut name = None;
    let mut issuer = None;
    let mut algorithm = OtpAlgorithm::Sha1;
    let mut digits = 6;
    let mut otp_type = None;
    let mut counter = 0;
    while cursor < bytes.len() {
        let key = read_varint(bytes, &mut cursor)?;
        let field = key >> 3;
        let wire = key & 7;
        match (field, wire) {
            (1, 2) => secret = Some(read_length_delimited(bytes, &mut cursor)?.to_vec()),
            (2, 2) => name = Some(read_utf8(bytes, &mut cursor)?),
            (3, 2) => issuer = Some(read_utf8(bytes, &mut cursor)?),
            (4, 0) => {
                algorithm = match read_varint(bytes, &mut cursor)? {
                    0 | 1 => OtpAlgorithm::Sha1,
                    2 => OtpAlgorithm::Sha256,
                    3 => OtpAlgorithm::Sha512,
                    _ => return Err(VaultError::UnsupportedOtpAlgorithm),
                }
            }
            (5, 0) => {
                digits = match read_varint(bytes, &mut cursor)? {
                    0 | 1 => 6,
                    2 => 8,
                    _ => return Err(VaultError::InvalidOtpDigits),
                }
            }
            (6, 0) => otp_type = Some(read_varint(bytes, &mut cursor)?),
            (7, 0) => counter = read_varint(bytes, &mut cursor)?,
            (_, wire) => skip_protobuf_value(bytes, &mut cursor, wire)?,
        }
    }
    let secret = secret
        .filter(|value| !value.is_empty())
        .ok_or(VaultError::InvalidOtpSecret)?;
    let issuer = issuer.unwrap_or_default();
    let mut account = name.ok_or(VaultError::InvalidOtpUri)?;
    if account.trim().is_empty() {
        return Err(VaultError::InvalidOtpUri);
    }
    if !issuer.is_empty() {
        if let Some(stripped) = account
            .strip_prefix(&issuer)
            .and_then(|rest| rest.strip_prefix(':'))
        {
            account = stripped.trim().to_owned();
        }
    }
    let kind = match otp_type {
        Some(1) => OtpKind::Hotp { counter },
        Some(2) => OtpKind::Totp { period: 30 },
        _ => return Err(VaultError::UnsupportedOtpType),
    };
    Ok(OtpConfig {
        issuer,
        account,
        secret: Zeroizing::new(secret),
        algorithm,
        digits,
        kind,
    })
}

fn read_utf8(bytes: &[u8], cursor: &mut usize) -> Result<String> {
    String::from_utf8(read_length_delimited(bytes, cursor)?.to_vec())
        .map_err(|_| VaultError::InvalidOtpUri)
}

fn read_length_delimited<'a>(bytes: &'a [u8], cursor: &mut usize) -> Result<&'a [u8]> {
    let length =
        usize::try_from(read_varint(bytes, cursor)?).map_err(|_| VaultError::InvalidOtpUri)?;
    let end = cursor
        .checked_add(length)
        .ok_or(VaultError::InvalidOtpUri)?;
    let value = bytes.get(*cursor..end).ok_or(VaultError::InvalidOtpUri)?;
    *cursor = end;
    Ok(value)
}

fn read_varint(bytes: &[u8], cursor: &mut usize) -> Result<u64> {
    let mut value = 0_u64;
    for shift in (0..=63).step_by(7) {
        let byte = *bytes.get(*cursor).ok_or(VaultError::InvalidOtpUri)?;
        *cursor += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(VaultError::InvalidOtpUri)
}

fn skip_protobuf_value(bytes: &[u8], cursor: &mut usize, wire: u64) -> Result<()> {
    match wire {
        0 => {
            read_varint(bytes, cursor)?;
        }
        1 => *cursor = cursor.checked_add(8).ok_or(VaultError::InvalidOtpUri)?,
        2 => {
            read_length_delimited(bytes, cursor)?;
        }
        5 => *cursor = cursor.checked_add(4).ok_or(VaultError::InvalidOtpUri)?,
        _ => return Err(VaultError::InvalidOtpUri),
    }
    if *cursor > bytes.len() {
        return Err(VaultError::InvalidOtpUri);
    }
    Ok(())
}

fn decode_secret(value: &str) -> Result<Vec<u8>> {
    let normalized = value
        .chars()
        .filter(|character| !character.is_ascii_whitespace() && *character != '-')
        .take_while(|character| *character != '=')
        .collect::<String>()
        .to_ascii_uppercase();
    if normalized.is_empty() {
        return Err(VaultError::InvalidOtpSecret);
    }
    BASE32_NOPAD
        .decode(normalized.as_bytes())
        .map_err(|_| VaultError::InvalidOtpSecret)
}

fn hmac_digest<M>(secret: &[u8], counter: &[u8]) -> Result<Vec<u8>>
where
    M: Mac + hmac::digest::KeyInit,
{
    let mut mac =
        <M as hmac::KeyInit>::new_from_slice(secret).map_err(|_| VaultError::InvalidOtpSecret)?;
    mac.update(counter);
    Ok(mac.finalize().into_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_6238_sha1_vectors() {
        let config = OtpConfig::from_uri("otpauth://totp/RFC:test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA1&digits=8&period=30").unwrap();
        let vectors = [
            (59, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ];
        for (timestamp, expected) in vectors {
            assert_eq!(config.code_at(timestamp).unwrap().value, expected);
        }
    }

    #[test]
    fn rfc_4226_vectors() {
        let mut config = OtpConfig::from_uri(
            "otpauth://hotp/RFC:test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0",
        )
        .unwrap();
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for value in expected {
            assert_eq!(config.code_at(0).unwrap().value, value);
            config.advance_hotp().unwrap();
        }
    }

    #[test]
    fn parser_and_protected_uri_round_trip() {
        let original = OtpConfig::from_uri("otpauth://totp/Example%20Co:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example%20Co&algorithm=SHA256&digits=8&period=45").unwrap();
        assert_eq!(original.account(), "alice@example.com");
        let encoded = original.protected_uri();
        assert_eq!(OtpConfig::from_uri(&encoded).unwrap(), original);
    }

    #[test]
    fn debug_redacts_secret() {
        let config = OtpConfig::from_uri("otpauth://totp/test?secret=JBSWY3DPEHPK3PXP").unwrap();
        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn parses_google_authenticator_migration_payload() {
        fn varint(mut value: u64) -> Vec<u8> {
            let mut output = Vec::new();
            loop {
                let mut byte = (value & 0x7f) as u8;
                value >>= 7;
                if value != 0 {
                    byte |= 0x80;
                }
                output.push(byte);
                if value == 0 {
                    return output;
                }
            }
        }
        fn field(number: u8, value: &[u8]) -> Vec<u8> {
            let mut output = vec![(number << 3) | 2];
            output.extend(varint(value.len() as u64));
            output.extend(value);
            output
        }

        let mut parameter = field(1, b"Hello!\xde\xad\xbe\xef");
        parameter.extend(field(2, b"Example:alice@example.com"));
        parameter.extend(field(3, b"Example"));
        parameter.extend([0x20, 0x01, 0x28, 0x01, 0x30, 0x02]);
        let payload = field(1, &parameter);
        let encoded = BASE64URL.encode(&payload);
        let configs =
            OtpConfig::from_migration_uri(&format!("otpauth-migration://offline?data={encoded}"))
                .unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].issuer(), "Example");
        assert_eq!(configs[0].account(), "alice@example.com");
        assert_eq!(configs[0].digits(), 6);
        assert_eq!(configs[0].kind(), OtpKind::Totp { period: 30 });
    }
}
