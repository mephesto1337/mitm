use std::fmt;
use std::io;

#[derive(Debug, Eq, PartialEq)]
pub enum ArpEntryParseError {
    Ip(std::net::AddrParseError),
    MacByte(std::num::ParseIntError),
    MacTooLong { extra_bytes: usize },
    MacTooShort { missing_bytes: usize },
    InvalidFormat(String),
}

impl std::convert::From<std::num::ParseIntError> for ArpEntryParseError {
    fn from(e: std::num::ParseIntError) -> Self {
        Self::MacByte(e)
    }
}

impl std::convert::From<std::net::AddrParseError> for ArpEntryParseError {
    fn from(e: std::net::AddrParseError) -> Self {
        Self::Ip(e)
    }
}

impl std::convert::From<String> for ArpEntryParseError {
    fn from(s: String) -> Self {
        Self::InvalidFormat(s)
    }
}

impl fmt::Display for ArpEntryParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Ip(addr_parse_error) => fmt::Display::fmt(&addr_parse_error, f),
            Self::MacByte(parse_int_error) => fmt::Display::fmt(parse_int_error, f),
            Self::MacTooLong { extra_bytes } => write!(f, "Got {extra_bytes} extra bytes"),
            Self::MacTooShort { missing_bytes } => write!(f, "{missing_bytes} are missing"),
            Self::InvalidFormat(ref s) => write!(f, "Invalid /proc/net/arp entry {s:?}"),
        }
    }
}

impl std::error::Error for ArpEntryParseError {}

impl std::convert::From<ArpEntryParseError> for io::Error {
    fn from(e: ArpEntryParseError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, e)
    }
}
