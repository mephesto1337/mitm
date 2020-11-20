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
