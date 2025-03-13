use std::collections::{hash_map::Entry, HashMap};
use std::fs;
use std::io::{self, BufRead, BufReader};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

mod arp;
mod error;

/// Lifetime of an ARP entry. It means that if host changes after that amount of time it will *not*
/// be considered as a MITM attack attempt.
pub const ARP_ENTRY_LIFETIME: Duration = Duration::from_secs(300);

use arp::ArpEntry;
pub use arp::MacAddress;

/// Struct that show changes in ARP table
#[derive(Debug, Clone)]
pub struct ArpChange {
    /// Host that has changed @MAC
    pub host: Ipv4Addr,

    /// Previsous seen @MAC
    pub old_mac: MacAddress,

    /// Previsous seen @MAC and last time seen
    pub old_mac_last_seen: Instant,

    /// New @MAC (seen just now)
    pub new_mac: MacAddress,
}

#[derive(Debug)]
pub struct ArpTable {
    entries: HashMap<Ipv4Addr, Vec<(MacAddress, Instant)>>,
    mac_lifetime: Duration,
}

impl ArpTable {
    pub fn new(mac_lifetime: Option<Duration>) -> io::Result<Self> {
        let now = Instant::now();
        let arp_file = BufReader::new(fs::File::open("/proc/net/arp")?);

        let mut lines = arp_file.lines();
        let _header = lines.next();
        let mut entries = HashMap::new();

        for ae in Self::read_os_entries()?.drain(..) {
            match entries.entry(ae.ip) {
                Entry::Vacant(v) => {
                    v.insert(vec![(ae.mac, now)]);
                }
                Entry::Occupied(o) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("Host {} has several entries in /proc/net/arp?!", o.key()),
                    ));
                }
            }
        }

        Ok(Self {
            entries,
            mac_lifetime: mac_lifetime.unwrap_or(ARP_ENTRY_LIFETIME),
        })
    }

    fn read_os_entries() -> io::Result<Vec<ArpEntry>> {
        let arp_file = BufReader::new(fs::File::open("/proc/net/arp")?);

        let mut lines = arp_file.lines();
        let _header = lines.next();
        let mut entries = Vec::new();

        for line in lines {
            let ae = line?.parse::<ArpEntry>()?;
            entries.push(ae);
        }

        Ok(entries)
    }

    pub fn update(&mut self) -> io::Result<Vec<ArpChange>> {
        let now = Instant::now();
        let mut changes = Vec::new();
        let mac_lifetime = &self.mac_lifetime;
        const NULL_MAC_ADDR: MacAddress = MacAddress::zeroed();

        for ae in Self::read_os_entries()?.drain(..) {
            match self.entries.entry(ae.ip) {
                Entry::Vacant(v) => {
                    v.insert(vec![(ae.mac, now)]);
                }
                Entry::Occupied(mut o) => {
                    let ip = *o.key();
                    let all_macs = o.get_mut();

                    // Evict old entries
                    let mut updated_all_macs: Vec<_> = all_macs
                        .drain(..)
                        .filter(|&(_, when)| &(now - when) < mac_lifetime)
                        .collect();

                    let mut found = false;
                    for (mac, when) in updated_all_macs.iter_mut() {
                        if mac == &NULL_MAC_ADDR {
                            continue;
                        }
                        if mac == &ae.mac {
                            // Mac has not changed or it was "00:00:00:00:00:00"
                            found = true;
                            *when = now;
                        } else {
                            changes.push(ArpChange {
                                host: ip,
                                old_mac: *mac,
                                old_mac_last_seen: *when,
                                new_mac: ae.mac,
                            });
                        }
                    }

                    if !found {
                        updated_all_macs.push((ae.mac, now));
                    }

                    let _ = std::mem::replace(all_macs, updated_all_macs);
                }
            }
        }

        Ok(changes)
    }
}
