use std::fmt;
use std::io;

#[derive(Debug, Eq, PartialEq)]
pub enum ArpEntryParseError {
    Ip(std::net::AddrParseError),
    MacByte(std::num::ParseIntError),
    MacTooLong { extra_bytes: usize },
    MacTooShort { missing_bytes: usize },
    Incomplete,
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

impl fmt::Display for ArpEntryParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for ArpEntryParseError {}

impl std::convert::From<ArpEntryParseError> for io::Error {
    fn from(e: ArpEntryParseError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, e)
    }
}
