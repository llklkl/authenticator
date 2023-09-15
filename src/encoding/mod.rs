use std::fmt;

mod alphabet;

pub mod base32;
pub mod urlencoded;

#[derive(Debug,Eq,PartialEq)]
pub enum DecodeError {
    InvalidByte(usize, u8),
    InvalidPadding,
    InvalidLength(usize),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::InvalidByte(position, ch) => {
                write!(f, "Invalid character {} at position {}", ch, position)
            }
            Self::InvalidLength(length) => {
                write!(f, "Invalid length {}", length)
            }
            Self::InvalidPadding => {
                write!(f, "Invalid padding character")
            }
        }
    }
}