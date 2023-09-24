use super::SecretAlgorithm;
use crate::tools::otp::{get_secret_key, OtpGenerator, timestamp};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

pub struct Totp {
    secret: Vec<u8>,
    algorithm: SecretAlgorithm,
    digits: usize,
    t0: u64,
    period: i32,
}

impl Totp {
    pub fn new(
        secret: Vec<u8>,
        algo: SecretAlgorithm,
        digits: usize,
        t0: u64,
        period: i32,
    ) -> Self {
        Totp {
            secret,
            algorithm: algo,
            digits,
            t0,
            period,
        }
    }

    fn otp_at(&self, t: u64) -> String {
        let step = (t - self.t0) / (self.period as u64);
        let step_bytes = step.to_be_bytes();
        let mut key = get_secret_key(&self.secret);

        let result = match self.algorithm {
            SecretAlgorithm::HmacSha1 => {
                let mut hasher = HmacSha1::new_from_slice(key.as_slice()).unwrap();
                hasher.update(&step_bytes);
                hasher.finalize().into_bytes().to_vec()
            }
            SecretAlgorithm::HmacSha256 => {
                let mut hasher = HmacSha256::new_from_slice(key.as_slice()).unwrap();
                hasher.update(&step_bytes);
                hasher.finalize().into_bytes().to_vec()
            }
            SecretAlgorithm::HmacSha512 => {
                let mut hasher = HmacSha512::new_from_slice(key.as_slice()).unwrap();
                hasher.update(&step_bytes);
                hasher.finalize().into_bytes().to_vec()
            }
        };

        key.fill(0);

        self.generate_otp(result.as_slice())
    }

    fn generate_otp(&self, hash: &[u8]) -> String {
        let offset = hash[hash.len() - 1] as usize & 0xf;
        let code = ((hash[offset] & 0x7f) as u32) << 24
            | (hash[offset + 1] as u32) << 16
            | (hash[offset + 2] as u32) << 8
            | (hash[offset + 3] as u32);
        let otp_code = code % DIGIT10_POW[self.digits];
        let mut otp = otp_code.to_string();
        while otp.len() < self.digits {
            otp.insert(0, '0');
        }

        otp
    }
}

impl OtpGenerator for Totp {
    fn current_otp(&self) -> String {
        self.otp_at(timestamp::now())
    }
}

const DIGIT10_POW: [u32; 10] = [
    1,
    10,
    100,
    1000,
    1_0000,
    10_0000,
    100_0000,
    1000_0000,
    1_0000_0000,
    10_0000_0000,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp() {
        let secret = b"12345678901234567890".to_vec();
        let totp = Totp::new(
            secret,
            SecretAlgorithm::HmacSha1,
            6,
            0,
            30,
        );

        assert_eq!(totp.otp_at(0), "755224");
        assert_eq!(totp.otp_at(30*1), "287082");
        assert_eq!(totp.otp_at(30*2), "359152");
        assert_eq!(totp.otp_at(30*3), "969429");
        assert_eq!(totp.otp_at(30*4), "338314");
        assert_eq!(totp.otp_at(30*5), "254676");
        assert_eq!(totp.otp_at(30*6), "287922");
        assert_eq!(totp.otp_at(30*7), "162583");
        assert_eq!(totp.otp_at(30*8), "399871");
        assert_eq!(totp.otp_at(30*9), "520489");
    }

    #[test]
    fn test_generate_otp() {
        let secret = b"12345678901234567890".to_vec();
        let totp = Totp::new(
            secret,
            SecretAlgorithm::HmacSha1,
            6,
            0,
            30,
        );

        let hash = [0;20];
        assert_eq!(totp.generate_otp(&hash), "000000");
    }

    #[test]
    fn test_current_otp() {
        let secret = b"12345678901234567890".to_vec();
        let totp = Totp::new(
            secret,
            SecretAlgorithm::HmacSha1,
            8,
            0,
            30,
        );
        println!("{}", totp.current_otp())
    }
}
