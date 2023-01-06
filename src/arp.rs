use crate::error::ArpEntryParseError;
use std::{fmt, net::Ipv4Addr};

pub const MAC_ADDRESS_SIZE: usize = 6usize;

#[derive(PartialEq, Eq, Hash, Clone, Default)]
pub struct MacAddress {
    bytes: [u8; MAC_ADDRESS_SIZE],
}

impl From<[u8; MAC_ADDRESS_SIZE]> for MacAddress {
    fn from(bytes: [u8; MAC_ADDRESS_SIZE]) -> Self {
        Self { bytes }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ArpEntry {
    pub mac: MacAddress,
    pub ip: Ipv4Addr,
    pub device: String,
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.bytes[0],
            self.bytes[1],
            self.bytes[2],
            self.bytes[3],
            self.bytes[4],
            self.bytes[5]
        )
    }
}
impl fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("MacAddress")
            .field("bytes", &format!("{:02x?}", self.bytes))
            .finish()
    }
}
impl fmt::Debug for ArpEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ArpEntry")
            .field("mac", &self.mac)
            .field("ip", &self.ip)
            .field("device", &self.device)
            .finish()
    }
}

impl MacAddress {
    pub const fn zeroed() -> Self {
        Self {
            bytes: [0u8; MAC_ADDRESS_SIZE],
        }
    }
}

impl std::str::FromStr for ArpEntry {
    type Err = ArpEntryParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        //  IP address       HW type     Flags       HW address            Mask     Device
        //  192.168.1.1      0x1         0x2         44:ce:7d:60:66:98     *        wlan0

        let mut ae = Self {
            ip: Ipv4Addr::new(0, 0, 0, 0),
            mac: MacAddress::default(),
            device: "".into(),
        };
        let mut seen_all = false;
        for (i, field) in s.split_ascii_whitespace().enumerate() {
            match i {
                0 => ae.ip = field.parse()?,
                3 => {
                    let mut mac_iter = field.split(':');
                    for i in 0..MAC_ADDRESS_SIZE {
                        ae.mac.bytes[i] = u8::from_str_radix(
                            mac_iter.next().ok_or(ArpEntryParseError::MacTooShort {
                                missing_bytes: (MAC_ADDRESS_SIZE - i),
                            })?,
                            16,
                        )?;
                    }
                    let extra_bytes = mac_iter.count();
                    if extra_bytes > 0 {
                        return Err(ArpEntryParseError::MacTooLong { extra_bytes });
                    }
                }
                5 => {
                    ae.device = field.into();
                    seen_all = true;
                }
                _ => {}
            }
        }

        if seen_all {
            Ok(ae)
        } else {
            Err(ArpEntryParseError::Incomplete)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_arpentry_ok() {
        let s = "192.168.1.1      0x1         0x2         44:ce:7d:60:66:98     *        wlan0";
        let ae = ArpEntry {
            ip: Ipv4Addr::new(192, 168, 1, 1),
            mac: [0x44, 0xce, 0x7d, 0x60, 0x66, 0x98].into(),
            device: "wlan0".into(),
        };
        assert_eq!(s.parse::<ArpEntry>(), Ok(ae));
    }

    #[test]
    fn parse_arpentry_err_ip() {
        let s = "192.168.11      0x1         0x2         44:ce:7d:60:66:98     *        wlan0";
        assert_eq!(
            s.parse::<ArpEntry>()
                .map_err(|e| if let ArpEntryParseError::Ip(_) = e {
                    true
                } else {
                    false
                }),
            Err(true)
        );
    }

    #[test]
    fn parse_arpentry_err_mac_byte() {
        let s = "192.168.1.1      0x1         0x2         44:cg:7d:60:66:98     *        wlan0";
        assert_eq!(
            s.parse::<ArpEntry>()
                .map_err(|e| if let ArpEntryParseError::MacByte(_) = e {
                    true
                } else {
                    false
                }),
            Err(true)
        );
    }

    #[test]
    fn parse_arpentry_err_mac_long() {
        let s = "192.168.1.1      0x1         0x2         44:ce:7d:60:66:98:00     *        wlan0";
        assert_eq!(
            s.parse::<ArpEntry>().map_err(|e| {
                println!("[parse_arpentry_err_mac_long] e = {:?}", e);
                if let ArpEntryParseError::MacTooLong { extra_bytes } = e {
                    extra_bytes == 1
                } else {
                    false
                }
            }),
            Err(true)
        );
    }

    #[test]
    fn parse_arpentry_err_mac_short() {
        let s = "192.168.1.1      0x1         0x2         44:ce:7d:60     *        wlan0";
        assert_eq!(
            s.parse::<ArpEntry>().map_err(|e| {
                if let ArpEntryParseError::MacTooShort { missing_bytes } = e {
                    eprintln!("missing_bytes = {:?}", missing_bytes);
                    missing_bytes == 2
                } else {
                    false
                }
            }),
            Err(true)
        );
    }
}
