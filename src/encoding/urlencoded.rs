use crate::encoding::DecodeError;

const HEX_TBL: &[u8] = b"0123456789ABCDEF";

pub fn encode<T: AsRef<[u8]>>(src: T) -> Vec<u8> {
    let src_data = src.as_ref();
    let mut dst: Vec<u8> = Vec::with_capacity(src_data.len());
    for ch in src_data {
        if *ch == b'-' || *ch == b'_' || *ch == b'~' || *ch == b'.' || ch.is_ascii_alphanumeric() {
            dst.push(*ch);
            continue;
        }

        dst.push(b'%');
        dst.push(HEX_TBL[(ch >> 4 & 0xf) as usize]);
        dst.push(HEX_TBL[(ch & 0xf) as usize]);
    }

    dst
}

pub fn decode<T: AsRef<[u8]>>(src: T) -> Result<Vec<u8>, DecodeError> {
    let src_data = src.as_ref();
    let mut dst: Vec<u8> = Vec::with_capacity(src_data.len());

    let mut i = 0_usize;
    while i < src_data.len() {
        if src_data[i] == b'%' {
            if i + 2 >= src_data.len() {
                return Err(DecodeError::InvalidByte(i, src_data[i]));
            }
            if !src_data[i + 1].is_ascii_hexdigit() {
                return Err(DecodeError::InvalidByte(i + 1, src_data[i + 1]));
            }
            if !src_data[i + 2].is_ascii_hexdigit() {
                return Err(DecodeError::InvalidByte(i + 2, src_data[i + 2]));
            }
            i += 3;
        } else {
            i += 1;
        }
    }

    i = 0;
    while i < src_data.len() {
        if src_data[i] == b'%' {
            dst.push(unhex(src_data[i + 1]) << 4 | unhex(src_data[i + 2]));
            i += 3;
        } else {
            dst.push(src_data[i]);
            i += 1;
        }
    }

    Ok(dst)
}

fn unhex(ch: u8) -> u8 {
    if ch.is_ascii_digit() {
        ch - b'0'
    } else if ch.is_ascii_lowercase() {
        ch - b'a' + 10
    } else {
        ch - b'A' + 10
    }
}

#[cfg(test)]
mod tests {
    use crate::encoding::urlencoded::{decode, encode};

    #[test]
    fn test_encode() {
        assert_eq!(
            encode("1ab%?.=+中文"),
            b"1ab%25%3F.%3D%2B%E4%B8%AD%E6%96%87"
        );
    }

    #[test]
    fn test_decode() {
        assert_eq!(
            decode("1ab%25%3F.%3D%2B%E4%B8%AD%E6%96%87").unwrap(),
            "1ab%?.=+中文".as_bytes()
        );
        assert!(decode("%%").is_err(), "原串无法解析");
    }
}
