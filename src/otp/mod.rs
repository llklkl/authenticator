use crate::encoding::{base32, urlencoded};
use std::fmt;

mod timestamp;

pub mod totp;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretAlgorithm {
    HmacSha1,
    HmacSha256,
    HmacSha512,
}

#[derive(Debug, PartialEq, Eq)]
pub enum OtpType {
    TOTP,
}

#[derive(Debug)]
pub enum OtpauthParseError {
    InvalidUri,
    InvalidLabel,
    InvalidOtpType(String),
    InvalidSecretFormat,
    UnsupportedAlgorithm(String),
}

impl fmt::Display for OtpauthParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OtpauthParseError::InvalidUri => write!(f, "Invalid otpauth uri"),
            OtpauthParseError::InvalidLabel => write!(f, "Invalid label"),
            OtpauthParseError::UnsupportedAlgorithm(algo) => {
                write!(f, "Invalid algorithm {}", algo)
            }
            OtpauthParseError::InvalidSecretFormat => write!(f, "Invalid secret format"),
            OtpauthParseError::InvalidOtpType(ot) => write!(f, "Invalid otp type {}", ot),
        }
    }
}

pub struct KeyFormat {
    opt_type: OtpType,
    secret: Vec<u8>,
    label: String,
    issuer: String,
    algorithm: SecretAlgorithm,
    digits: usize,
    counter: u64,
    period: i32, // in seconds
}

fn get_secret_key(secret: &Vec<u8>) -> Vec<u8> {
    secret.clone()
}

pub fn from(key: &KeyFormat) -> Box<dyn OtpGenerator> {
    match key.opt_type {
        OtpType::TOTP => Box::new(totp::Totp::new(
            key.secret.clone(),
            key.algorithm.clone(),
            key.digits,
            key.counter,
            key.period,
        )),
    }
}

/// 解析 otpauth key uri 结构
pub fn parse_otpauth_uri(key_uri: &str) -> Result<KeyFormat, OtpauthParseError> {
    // otpauth://TYPE/LABEL?PARAMETERS
    const SCHEMA: &str = "otpauth://";

    let uri = key_uri.trim();
    if !uri.starts_with(SCHEMA) {
        return Err(OtpauthParseError::InvalidUri);
    }

    let mut key = KeyFormat {
        opt_type: OtpType::TOTP,
        secret: vec![],
        label: "".to_string(),
        issuer: "".to_string(),
        algorithm: SecretAlgorithm::HmacSha1,
        digits: 6,
        counter: 0,
        period: 30,
    };

    let uri = &uri[SCHEMA.len()..];
    let idx = uri.find('/').ok_or(OtpauthParseError::InvalidUri)?;
    let opt_type = uri[..idx].to_lowercase();
    match opt_type.as_ref() {
        "totp" => key.opt_type = OtpType::TOTP,
        _ => {
            return Err(OtpauthParseError::InvalidOtpType(opt_type));
        }
    }

    let uri = &uri[idx + 1..];
    let idx = uri.find('?').ok_or(OtpauthParseError::InvalidUri)?;

    key.label = parse_label(&uri[..idx]);

    let uri = &uri[idx + 1..];
    for param in uri.split('&') {
        let vals: Vec<_> = param.splitn(2, '=').collect();
        if vals.len() != 2 {
            continue;
        }

        match vals[0].to_lowercase().as_ref() {
            "secret" => key.secret = parse_secret(vals[1].as_bytes())?,
            "digits" => {
                if !vals[1].is_empty() {
                    key.digits = vals[1].parse().map_err(|_| OtpauthParseError::InvalidUri)?;
                }
            }
            "counter" => {
                if !vals[1].is_empty() {
                    key.counter = vals[1].parse().map_err(|_| OtpauthParseError::InvalidUri)?;
                }
            }
            "algorithm" => match vals[1].to_uppercase().as_ref() {
                "SHA1" => key.algorithm = SecretAlgorithm::HmacSha1,
                "SHA256" => key.algorithm = SecretAlgorithm::HmacSha256,
                "SHA512" => key.algorithm = SecretAlgorithm::HmacSha1,
                _ => {
                    return Err(OtpauthParseError::UnsupportedAlgorithm(vals[1].to_string()));
                }
            },
            "period" => {
                if !vals[1].is_empty() {
                    key.period = vals[1].parse().map_err(|_| OtpauthParseError::InvalidUri)?;
                }
            }
            "issuer" => key.issuer = parse_label(vals[1]),
            _ => (),
        }
    }

    Ok(key)
}

fn parse_secret(secret: &[u8]) -> Result<Vec<u8>, OtpauthParseError> {
    base32::RFC4648_RAW.decode(secret).or(base32::RFC4648
        .decode(secret)
        .map_err(|_| OtpauthParseError::InvalidSecretFormat))
}

fn parse_label(val: &str) -> String {
    String::from_utf8(urlencoded::decode(val).unwrap_or(val.as_bytes().to_vec()))
        .unwrap_or(val.to_string())
}

pub trait OtpGenerator {
    fn current_otp(&self) -> String;
}

#[cfg(test)]
mod tests {
    use crate::otp::{parse_otpauth_uri, OtpType, SecretAlgorithm};

    #[test]
    fn test_parse_optauth() {
        let k = parse_otpauth_uri("otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30&counter=10");
        assert!(k.is_ok(), "parse err {}", k.err().unwrap());
        let k = k.unwrap();
        assert_eq!(k.opt_type, OtpType::TOTP);
        assert_eq!(
            k.secret,
            vec![
                61, 198, 202, 164, 130, 74, 109, 40, 135, 103, 178, 51, 30, 32, 180, 49, 102, 203,
                133, 217
            ]
        );
        assert_eq!(k.issuer, "ACME Co");
        assert_eq!(k.label, "ACME Co:john.doe@email.com");
        assert_eq!(k.counter, 10);
        assert_eq!(k.digits, 6);
        assert_eq!(k.period, 30);
        assert_eq!(k.algorithm, SecretAlgorithm::HmacSha1);
    }
}
