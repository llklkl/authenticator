// use crate::{
//     encoding::alphabet,
// };

use super::alphabet;
use crate::encoding::DecodeError;

pub struct Encoding {
    encode_tbl: [u8; 32],
    decode_tbl: [u8; 256],
    pad_char: u8,
    padding: bool,
}

impl Encoding {
    pub const fn new(alphabet: &[u8; 32], pad_char: u8, padding: bool) -> Self {
        Self {
            encode_tbl: encode_table(alphabet),
            decode_tbl: decode_table(alphabet),
            pad_char,
            padding,
        }
    }

    pub fn encode_len(&self, length: usize) -> usize {
        if self.padding {
            (length + 4) / 5 * 8
        } else {
            (length * 8 + 4) / 5
        }
    }

    pub fn decode_len(&self, length: usize) -> usize {
        if self.padding {
            length / 8 * 5
        } else {
            length * 5 / 8
        }
    }

    fn encode_inplace(&self, dst: &mut [u8], src: &[u8]) {
        let mut srci = 0_usize;
        let mut dsti = 0_usize;
        let loop_size = src.len() / 5;
        for _ in 0..loop_size {
            let src_chunk = &src[srci..];
            let dst_chunk = &mut dst[dsti..];
            let mut x = 0_u64;
            for v in &src_chunk[..5] {
                x = (x << 8) | (*v as u64);
            }
            dst_chunk[0] = self.encode_tbl[(x >> 35 & 31) as usize];
            dst_chunk[1] = self.encode_tbl[(x >> 30 & 31) as usize];
            dst_chunk[2] = self.encode_tbl[(x >> 25 & 31) as usize];
            dst_chunk[3] = self.encode_tbl[(x >> 20 & 31) as usize];
            dst_chunk[4] = self.encode_tbl[(x >> 15 & 31) as usize];
            dst_chunk[5] = self.encode_tbl[(x >> 10 & 31) as usize];
            dst_chunk[6] = self.encode_tbl[(x >> 5 & 31) as usize];
            dst_chunk[7] = self.encode_tbl[(x & 31) as usize];

            srci += 5;
            dsti += 8;
        }
        if srci == src.len() {
            return;
        }

        // rest
        let src_chunk = &src[srci..];
        let dst_chunk = &mut dst[dsti..];
        let b = &mut [0_u8; 8];
        if src_chunk.len() >= 4 {
            b[6] = src_chunk[3] << 3 & 31; // h2
            b[5] = src_chunk[3] >> 2 & 31; //
            b[4] = src_chunk[3] >> 7 & 31; // l1
        }
        if src_chunk.len() >= 3 {
            b[4] |= src_chunk[2] << 1 & 31; // h4
            b[3] = src_chunk[2] >> 4 & 31; // l4
        }
        if src_chunk.len() >= 2 {
            b[3] |= src_chunk[1] << 4 & 31; // h1
            b[2] = src_chunk[1] >> 1 & 31; //
            b[1] |= src_chunk[1] >> 6 & 31; // l2
        }
        if src_chunk.len() >= 1 {
            b[1] |= src_chunk[0] << 2 & 31; // h3
            b[0] = src_chunk[0] >> 3 & 31;
        }

        for i in 0..dst_chunk.len() {
            dst_chunk[i] = self.encode_tbl[b[i] as usize];
        }

        if self.padding {
            match src_chunk.len() {
                4 => dst_chunk[7..].fill(self.pad_char),
                3 => dst_chunk[5..].fill(self.pad_char),
                2 => dst_chunk[4..].fill(self.pad_char),
                1 => dst_chunk[2..].fill(self.pad_char),
                _ => (),
            }
        }
    }

    pub fn encode<T: AsRef<[u8]>>(&self, src: T) -> Vec<u8> {
        let input = src.as_ref();
        let length = self.encode_len(input.len());
        let mut dst = vec![0_u8; length];

        self.encode_inplace(dst.as_mut_slice(), input);

        dst
    }

    fn decode_inplace(&self, dst: &mut [u8], src: &[u8]) -> Result<usize, DecodeError> {
        let mut srci = 0_usize;
        let mut dsti = 0_usize;
        let mut loop_size = src.len() / 8;
        if self.padding && loop_size > 0 {
            loop_size -= 1;
        }
        for _ in 0..loop_size {
            let src_chunk = &src[srci..];
            let dst_chunk = &mut dst[dsti..];
            let mut x = 0_u64;
            for i in 0..8 {
                let d = self.decode_tbl[src_chunk[i] as usize];
                if d == INVALID_VALUE {
                    return Err(DecodeError::InvalidByte(srci + i, src_chunk[i]));
                }
                x = x << 5 | (d as u64);
            }

            dst_chunk[0] = (x >> 32 & 0xff) as u8;
            dst_chunk[1] = (x >> 24 & 0xff) as u8;
            dst_chunk[2] = (x >> 16 & 0xff) as u8;
            dst_chunk[3] = (x >> 8 & 0xff) as u8;
            dst_chunk[4] = (x & 0xff) as u8;

            srci += 8;
            dsti += 5;
        }

        while srci < src.len() {
            let src_chunk = &src[srci..];
            let dst_chunk = &mut dst[dsti..];

            let mut i = 0_usize;
            let mut x = 0_u64;
            let mut xlen = 0;
            while i < src_chunk.len() && i < 8 {
                if src_chunk[i] == self.pad_char {
                    if !self.padding {
                        return Err(DecodeError::InvalidByte(srci + i, src_chunk[i]));
                    } else {
                        if src_chunk.len() != 8 {
                            return Err(DecodeError::InvalidPadding);
                        }
                        while i < 8 {
                            if src_chunk[i] != self.pad_char {
                                return Err(DecodeError::InvalidPadding);
                            }
                            i += 1;
                        }
                        break;
                    }
                }
                let d = self.decode_tbl[src_chunk[i] as usize];
                if d != INVALID_VALUE {
                    xlen += 1;
                    x |= (d as u64) << (40 - xlen * 5);
                } else {
                    return Err(DecodeError::InvalidByte(srci + i, src_chunk[i]));
                }
                i += 1;
            }

            let mut dl = 0_usize;
            if xlen >= 2 {
                dst_chunk[0] = (x >> 32 & 0xff) as u8;
                dl = 1;
            }
            if xlen >= 4 {
                dst_chunk[1] = (x >> 24 & 0xff) as u8;
                dl = 2;
            }
            if xlen >= 5 {
                dst_chunk[2] = (x >> 16 & 0xff) as u8;
                dl = 3;
            }
            if xlen >= 7 {
                dst_chunk[3] = (x >> 8 & 0xff) as u8;
                dl = 4;
            }
            if xlen >= 8 {
                dst_chunk[4] = (x & 0xff) as u8;
                dl = 5;
            }

            if xlen == 1 || xlen == 3 || x == 6 {
                return Err(DecodeError::InvalidLength(src.len()));
            }

            srci += i;
            dsti += dl;
        }

        Ok(dsti)
    }

    pub fn decode<T: AsRef<[u8]>>(&self, src: T) -> Result<Vec<u8>, DecodeError> {
        let input = src.as_ref();
        let length = self.decode_len(input.len());
        let mut dst = vec![0_u8; length];

        match self.decode_inplace(dst.as_mut_slice(), input) {
            Ok(size) => {
                dst.truncate(size);
                Ok(dst)
            }
            Err(e) => Err(e),
        }
    }
}

const fn encode_table(alphabet: &[u8; ALPHABET_LENGTH]) -> [u8; 32] {
    let mut tbl: [u8; 32] = [INVALID_VALUE; 32];
    let mut idx = 0;
    while idx < alphabet.len() {
        tbl[idx] = alphabet[idx];
        idx += 1;
    }

    tbl
}

const fn decode_table(alphabet: &[u8; ALPHABET_LENGTH]) -> [u8; 256] {
    let mut tbl: [u8; 256] = [INVALID_VALUE; 256];
    let mut idx = 0;
    while idx < alphabet.len() {
        tbl[alphabet[idx] as usize] = idx as u8;
        idx += 1;
    }

    tbl
}

const PAD_CHAR: u8 = b'=';
const INVALID_VALUE: u8 = 0xff;
const ALPHABET_LENGTH: usize = 32;

pub const RFC4648: Encoding = Encoding::new(alphabet::RFC4648_BASE32_ALPHABET, PAD_CHAR, true);
pub const RFC4648_RAW: Encoding = Encoding::new(alphabet::RFC4648_BASE32_ALPHABET, PAD_CHAR, false);
pub const EXTENDED_HEX: Encoding = Encoding::new(alphabet::EXTENDED_HEX_ALPHABET, PAD_CHAR, true);
pub const EXTENDED_HEX_RAW: Encoding =
    Encoding::new(alphabet::EXTENDED_HEX_ALPHABET, PAD_CHAR, false);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_rfc4648_with_padding() {
        assert_eq!(RFC4648.encode(b""), b"");
        assert_eq!(RFC4648.decode(b"").unwrap(), b"");
        assert_eq!(RFC4648.encode(b"1"), b"GE======");
        assert_eq!(RFC4648.decode(b"GE======").unwrap(), b"1");
        assert_eq!(RFC4648.encode(b"8f"), b"HBTA====");
        assert_eq!(RFC4648.decode(b"HBTA====").unwrap(), b"8f");
        assert_eq!(RFC4648.encode(b"062"), b"GA3DE===");
        assert_eq!(RFC4648.decode(b"GA3DE===").unwrap(), b"062");
        assert_eq!(RFC4648.encode(b"bd4f"), b"MJSDIZQ=");
        assert_eq!(RFC4648.decode(b"MJSDIZQ=").unwrap(), b"bd4f");
        assert_eq!(RFC4648.encode(b"7120f"), b"G4YTEMDG");
        assert_eq!(RFC4648.decode(b"G4YTEMDG").unwrap(), b"7120f");
        assert_eq!(RFC4648.encode(b"d3fb4d"), b"MQZWMYRUMQ======");
        assert_eq!(RFC4648.decode(b"MQZWMYRUMQ======").unwrap(), b"d3fb4d");
        assert_eq!(RFC4648.encode(b"af4d379"), b"MFTDIZBTG44Q====");
        assert_eq!(RFC4648.decode(b"MFTDIZBTG44Q====").unwrap(), b"af4d379");
        assert_eq!(RFC4648.encode(b"41299817"), b"GQYTEOJZHAYTO===");
        assert_eq!(RFC4648.decode(b"GQYTEOJZHAYTO===").unwrap(), b"41299817");
        assert_eq!(RFC4648.encode(b"69a667353"), b"GY4WCNRWG4ZTKMY=");
        assert_eq!(RFC4648.decode(b"GY4WCNRWG4ZTKMY=").unwrap(), b"69a667353");
        assert_eq!(RFC4648.encode(b"8c4124fea5"), b"HBRTIMJSGRTGKYJV");
        assert_eq!(RFC4648.decode(b"HBRTIMJSGRTGKYJV").unwrap(), b"8c4124fea5");
        assert_eq!(RFC4648.encode(b"a711aeaded2"), b"ME3TCMLBMVQWIZLEGI======");
        assert_eq!(
            RFC4648.decode(b"ME3TCMLBMVQWIZLEGI======").unwrap(),
            b"a711aeaded2"
        );
        assert_eq!(RFC4648.encode(b"1aa415f464b4"), b"GFQWCNBRGVTDINRUMI2A====");
        assert_eq!(
            RFC4648.decode(b"GFQWCNBRGVTDINRUMI2A====").unwrap(),
            b"1aa415f464b4"
        );
        assert_eq!(
            RFC4648.encode(b"9f4e097e5e693"),
            b"HFTDIZJQHE3WKNLFGY4TG==="
        );
        assert_eq!(
            RFC4648.decode(b"HFTDIZJQHE3WKNLFGY4TG===").unwrap(),
            b"9f4e097e5e693"
        );
        assert_eq!(
            RFC4648.encode(b"1459df79d0ee19"),
            b"GE2DKOLEMY3TSZBQMVSTCOI="
        );
        assert_eq!(
            RFC4648.decode(b"GE2DKOLEMY3TSZBQMVSTCOI=").unwrap(),
            b"1459df79d0ee19"
        );
        assert_eq!(
            RFC4648.encode(b"178f4dec766682d"),
            b"GE3TQZRUMRSWGNZWGY3DQMTE"
        );
        assert_eq!(
            RFC4648.decode(b"GE3TQZRUMRSWGNZWGY3DQMTE").unwrap(),
            b"178f4dec766682d"
        );
        assert_eq!(
            RFC4648.encode(b"491bb6d1e7bba963"),
            b"GQ4TCYTCGZSDCZJXMJRGCOJWGM======"
        );
        assert_eq!(
            RFC4648.decode(b"GQ4TCYTCGZSDCZJXMJRGCOJWGM======").unwrap(),
            b"491bb6d1e7bba963"
        );
        assert_eq!(
            RFC4648.encode(b"6ef3d890b53c6bb2a"),
            b"GZSWMM3EHA4TAYRVGNRTMYTCGJQQ===="
        );
        assert_eq!(
            RFC4648.decode(b"GZSWMM3EHA4TAYRVGNRTMYTCGJQQ====").unwrap(),
            b"6ef3d890b53c6bb2a"
        );
        assert_eq!(
            RFC4648.encode(b"2f71e8d047b39b824a"),
            b"GJTDOMLFHBSDANBXMIZTSYRYGI2GC==="
        );
        assert_eq!(
            RFC4648.decode(b"GJTDOMLFHBSDANBXMIZTSYRYGI2GC===").unwrap(),
            b"2f71e8d047b39b824a"
        );
        assert_eq!(
            RFC4648.encode(b"1d2f60c19c4fed4aa95"),
            b"GFSDEZRWGBRTCOLDGRTGKZBUMFQTSNI="
        );
        assert_eq!(
            RFC4648.decode(b"GFSDEZRWGBRTCOLDGRTGKZBUMFQTSNI=").unwrap(),
            b"1d2f60c19c4fed4aa95"
        );
        assert_eq!(
            RFC4648.encode(b"d68ef0e9e8a90dce83a5"),
            b"MQ3DQZLGGBSTSZJYME4TAZDDMU4DGYJV"
        );
        assert_eq!(
            RFC4648.decode(b"MQ3DQZLGGBSTSZJYME4TAZDDMU4DGYJV").unwrap(),
            b"d68ef0e9e8a90dce83a5"
        );
        assert_eq!(
            RFC4648.encode(b"d1492b3d57bf42b01fe04"),
            b"MQYTIOJSMIZWINJXMJTDIMTCGAYWMZJQGQ======"
        );
        assert_eq!(
            RFC4648
                .decode(b"MQYTIOJSMIZWINJXMJTDIMTCGAYWMZJQGQ======")
                .unwrap(),
            b"d1492b3d57bf42b01fe04"
        );
        assert_eq!(
            RFC4648.encode(b"539bf6d2be3e164a30f8dd"),
            b"GUZTSYTGGZSDEYTFGNSTCNRUMEZTAZRYMRSA===="
        );
        assert_eq!(
            RFC4648
                .decode(b"GUZTSYTGGZSDEYTFGNSTCNRUMEZTAZRYMRSA====")
                .unwrap(),
            b"539bf6d2be3e164a30f8dd"
        );
        assert_eq!(
            RFC4648.encode(b"ce71727be163d904106d5d6"),
            b"MNSTOMJXGI3WEZJRGYZWIOJQGQYTANTEGVSDM==="
        );
        assert_eq!(
            RFC4648
                .decode(b"MNSTOMJXGI3WEZJRGYZWIOJQGQYTANTEGVSDM===")
                .unwrap(),
            b"ce71727be163d904106d5d6"
        );
        assert_eq!(
            RFC4648.encode(b"9033a5a9b5de045df5191596"),
            b"HEYDGM3BGVQTSYRVMRSTANBVMRTDKMJZGE2TSNQ="
        );
        assert_eq!(
            RFC4648
                .decode(b"HEYDGM3BGVQTSYRVMRSTANBVMRTDKMJZGE2TSNQ=")
                .unwrap(),
            b"9033a5a9b5de045df5191596"
        );
    }

    #[test]
    fn test_encode_rfc4648_no_padding() {
        assert_eq!(RFC4648_RAW.encode(b""), b"");
        assert_eq!(RFC4648_RAW.decode(b"").unwrap(), b"");
        assert_eq!(RFC4648_RAW.encode(b"4"), b"GQ");
        assert_eq!(RFC4648_RAW.decode(b"GQ").unwrap(), b"4");
        assert_eq!(RFC4648_RAW.encode(b"9c"), b"HFRQ");
        assert_eq!(RFC4648_RAW.decode(b"HFRQ").unwrap(), b"9c");
        assert_eq!(RFC4648_RAW.encode(b"c96"), b"MM4TM");
        assert_eq!(RFC4648_RAW.decode(b"MM4TM").unwrap(), b"c96");
        assert_eq!(RFC4648_RAW.encode(b"a7ee"), b"ME3WKZI");
        assert_eq!(RFC4648_RAW.decode(b"ME3WKZI").unwrap(), b"a7ee");
        assert_eq!(RFC4648_RAW.encode(b"3e450"), b"GNSTINJQ");
        assert_eq!(RFC4648_RAW.decode(b"GNSTINJQ").unwrap(), b"3e450");
        assert_eq!(RFC4648_RAW.encode(b"9d47e7"), b"HFSDIN3FG4");
        assert_eq!(RFC4648_RAW.decode(b"HFSDIN3FG4").unwrap(), b"9d47e7");
        assert_eq!(RFC4648_RAW.encode(b"3b0a408"), b"GNRDAYJUGA4A");
        assert_eq!(RFC4648_RAW.decode(b"GNRDAYJUGA4A").unwrap(), b"3b0a408");
        assert_eq!(RFC4648_RAW.encode(b"5422f470"), b"GU2DEMTGGQ3TA");
        assert_eq!(RFC4648_RAW.decode(b"GU2DEMTGGQ3TA").unwrap(), b"5422f470");
        assert_eq!(RFC4648_RAW.encode(b"af9dbb9e0"), b"MFTDSZDCMI4WKMA");
        assert_eq!(
            RFC4648_RAW.decode(b"MFTDSZDCMI4WKMA").unwrap(),
            b"af9dbb9e0"
        );
        assert_eq!(RFC4648_RAW.encode(b"b71c38c6a3"), b"MI3TCYZTHBRTMYJT");
        assert_eq!(
            RFC4648_RAW.decode(b"MI3TCYZTHBRTMYJT").unwrap(),
            b"b71c38c6a3"
        );
        assert_eq!(RFC4648_RAW.encode(b"da5a82a5e89"), b"MRQTKYJYGJQTKZJYHE");
        assert_eq!(
            RFC4648_RAW.decode(b"MRQTKYJYGJQTKZJYHE").unwrap(),
            b"da5a82a5e89"
        );
        assert_eq!(RFC4648_RAW.encode(b"8d39950d92d2"), b"HBSDGOJZGUYGIOJSMQZA");
        assert_eq!(
            RFC4648_RAW.decode(b"HBSDGOJZGUYGIOJSMQZA").unwrap(),
            b"8d39950d92d2"
        );
        assert_eq!(
            RFC4648_RAW.encode(b"b2c5eab238095"),
            b"MIZGGNLFMFRDEMZYGA4TK"
        );
        assert_eq!(
            RFC4648_RAW.decode(b"MIZGGNLFMFRDEMZYGA4TK").unwrap(),
            b"b2c5eab238095"
        );
        assert_eq!(
            RFC4648_RAW.encode(b"ae6d84cc8ada39"),
            b"MFSTMZBYGRRWGODBMRQTGOI"
        );
        assert_eq!(
            RFC4648_RAW.decode(b"MFSTMZBYGRRWGODBMRQTGOI").unwrap(),
            b"ae6d84cc8ada39"
        );
        assert_eq!(
            RFC4648_RAW.encode(b"9c5105ac1f79ff9"),
            b"HFRTKMJQGVQWGMLGG44WMZRZ"
        );
        assert_eq!(
            RFC4648_RAW.decode(b"HFRTKMJQGVQWGMLGG44WMZRZ").unwrap(),
            b"9c5105ac1f79ff9"
        );
        assert_eq!(
            RFC4648_RAW.encode(b"4db9ee4fa83f6758"),
            b"GRSGEOLFMU2GMYJYGNTDMNZVHA"
        );
        assert_eq!(
            RFC4648_RAW.decode(b"GRSGEOLFMU2GMYJYGNTDMNZVHA").unwrap(),
            b"4db9ee4fa83f6758"
        );
        assert_eq!(
            RFC4648_RAW.encode(b"9029e194eadda28c8"),
            b"HEYDEOLFGE4TIZLBMRSGCMRYMM4A"
        );
        assert_eq!(
            RFC4648_RAW.decode(b"HEYDEOLFGE4TIZLBMRSGCMRYMM4A").unwrap(),
            b"9029e194eadda28c8"
        );
        assert_eq!(
            RFC4648_RAW.encode(b"30cdb935991507aa0a"),
            b"GMYGGZDCHEZTKOJZGE2TAN3BMEYGC"
        );
        assert_eq!(
            RFC4648_RAW
                .decode(b"GMYGGZDCHEZTKOJZGE2TAN3BMEYGC")
                .unwrap(),
            b"30cdb935991507aa0a"
        );
        assert_eq!(
            RFC4648_RAW.encode(b"360149ee9d7649d2de1"),
            b"GM3DAMJUHFSWKOLEG43DIOLEGJSGKMI"
        );
        assert_eq!(
            RFC4648_RAW
                .decode(b"GM3DAMJUHFSWKOLEG43DIOLEGJSGKMI")
                .unwrap(),
            b"360149ee9d7649d2de1"
        );
        assert_eq!(
            RFC4648_RAW.encode(b"5c2b9066f4ec032968e0"),
            b"GVRTEYRZGA3DMZRUMVRTAMZSHE3DQZJQ"
        );
        assert_eq!(
            RFC4648_RAW
                .decode(b"GVRTEYRZGA3DMZRUMVRTAMZSHE3DQZJQ")
                .unwrap(),
            b"5c2b9066f4ec032968e0"
        );
        assert_eq!(
            RFC4648_RAW.encode(b"12ae600ae7616bf38830f"),
            b"GEZGCZJWGAYGCZJXGYYTMYTGGM4DQMZQMY"
        );
        assert_eq!(
            RFC4648_RAW
                .decode(b"GEZGCZJWGAYGCZJXGYYTMYTGGM4DQMZQMY")
                .unwrap(),
            b"12ae600ae7616bf38830f"
        );
        assert_eq!(
            RFC4648_RAW.encode(b"2f23026e3f93b1a1c640a6"),
            b"GJTDEMZQGI3GKM3GHEZWEMLBGFRTMNBQME3A"
        );
        assert_eq!(
            RFC4648_RAW
                .decode(b"GJTDEMZQGI3GKM3GHEZWEMLBGFRTMNBQME3A")
                .unwrap(),
            b"2f23026e3f93b1a1c640a6"
        );
        assert_eq!(
            RFC4648_RAW.encode(b"2ecaad5c66419eedeecb28e"),
            b"GJSWGYLBMQ2WGNRWGQYTSZLFMRSWKY3CGI4GK"
        );
        assert_eq!(
            RFC4648_RAW
                .decode(b"GJSWGYLBMQ2WGNRWGQYTSZLFMRSWKY3CGI4GK")
                .unwrap(),
            b"2ecaad5c66419eedeecb28e"
        );
        assert_eq!(
            RFC4648_RAW.encode(b"4b56768c0b9344eedee9fb2a"),
            b"GRRDKNRXGY4GGMDCHEZTINDFMVSGKZJZMZRDEYI"
        );
        assert_eq!(
            RFC4648_RAW
                .decode(b"GRRDKNRXGY4GGMDCHEZTINDFMVSGKZJZMZRDEYI")
                .unwrap(),
            b"4b56768c0b9344eedee9fb2a"
        );
    }

    #[test]
    fn test_extended_hex_with_padding() {
        assert_eq!(EXTENDED_HEX.encode(b""), b"");
        assert_eq!(EXTENDED_HEX.encode(b"f"), b"CO======");
        assert_eq!(EXTENDED_HEX.encode(b"fo"), b"CPNG====");
        assert_eq!(EXTENDED_HEX.encode(b"foo"), b"CPNMU===");
        assert_eq!(EXTENDED_HEX.encode(b"foob"), b"CPNMUOG=");
        assert_eq!(EXTENDED_HEX.encode(b"fooba"), b"CPNMUOJ1");
        assert_eq!(EXTENDED_HEX.encode(b"foobar"), b"CPNMUOJ1E8======");
        assert_eq!(EXTENDED_HEX.encode(b"foobar"), b"CPNMUOJ1E8======");

        assert_eq!(EXTENDED_HEX.decode(b"").unwrap(), b"");
        assert_eq!(EXTENDED_HEX.decode(b"CO======").unwrap(), b"f");
        assert_eq!(EXTENDED_HEX.decode(b"CPNG====").unwrap(), b"fo");
        assert_eq!(EXTENDED_HEX.decode(b"CPNMU===").unwrap(), b"foo");
        assert_eq!(EXTENDED_HEX.decode(b"CPNMUOG=").unwrap(), b"foob");
        assert_eq!(EXTENDED_HEX.decode(b"CPNMUOJ1").unwrap(), b"fooba");
        assert_eq!(EXTENDED_HEX.decode(b"CPNMUOJ1E8======").unwrap(), b"foobar");
        assert_eq!(EXTENDED_HEX.decode(b"CPNMUOJ1E8======").unwrap(), b"foobar");
    }

    #[test]
    fn test_extended_hex_no_padding() {
        assert_eq!(EXTENDED_HEX_RAW.encode(b""), b"");
        assert_eq!(EXTENDED_HEX_RAW.encode(b"f"), b"CO");
        assert_eq!(EXTENDED_HEX_RAW.encode(b"fo"), b"CPNG");
        assert_eq!(EXTENDED_HEX_RAW.encode(b"foo"), b"CPNMU");
        assert_eq!(EXTENDED_HEX_RAW.encode(b"foob"), b"CPNMUOG");
        assert_eq!(EXTENDED_HEX_RAW.encode(b"fooba"), b"CPNMUOJ1");
        assert_eq!(EXTENDED_HEX_RAW.encode(b"foobar"), b"CPNMUOJ1E8");

        assert_eq!(EXTENDED_HEX_RAW.decode(b"").unwrap(), b"");
        assert_eq!(EXTENDED_HEX_RAW.decode(b"CO").unwrap(), b"f");
        assert_eq!(EXTENDED_HEX_RAW.decode(b"CPNG").unwrap(), b"fo");
        assert_eq!(EXTENDED_HEX_RAW.decode(b"CPNMU").unwrap(), b"foo");
        assert_eq!(EXTENDED_HEX_RAW.decode(b"CPNMUOG").unwrap(), b"foob");
        assert_eq!(EXTENDED_HEX_RAW.decode(b"CPNMUOJ1").unwrap(), b"fooba");
        assert_eq!(EXTENDED_HEX_RAW.decode(b"CPNMUOJ1E8").unwrap(), b"foobar");
    }


    #[test]
    fn test_extended_hex_decode_error() {
        assert_eq!(EXTENDED_HEX.decode(b"CO===").unwrap_err(), DecodeError::InvalidPadding);
        assert_eq!(EXTENDED_HEX.decode(b"CPNG=1==").unwrap_err(), DecodeError::InvalidPadding);
        assert_eq!(EXTENDED_HEX.decode(b"CPNMU===").unwrap(), b"foo");
        assert_eq!(EXTENDED_HEX.decode(b"CPNMUOG=").unwrap(), b"foob");
        assert_eq!(EXTENDED_HEX.decode(b"CPNMUOJ1").unwrap(), b"fooba");
        assert_eq!(EXTENDED_HEX.decode(b"CPNMUOJ1E8======").unwrap(), b"foobar");
        assert_eq!(EXTENDED_HEX.decode(b"CPNMUOJ1E8======").unwrap(), b"foobar");

        assert_eq!(EXTENDED_HEX_RAW.decode(b"=").unwrap_err(), DecodeError::InvalidByte(0, b'='));
        assert_eq!(EXTENDED_HEX_RAW.decode(b"CZ").unwrap_err(), DecodeError::InvalidByte(1, b'Z'));
        assert_eq!(EXTENDED_HEX_RAW.decode(b"CPN").unwrap_err(), DecodeError::InvalidLength(3));
        assert_eq!(EXTENDED_HEX_RAW.decode(b"CPNG====").unwrap_err(), DecodeError::InvalidByte(4, b'='));
    }
}
