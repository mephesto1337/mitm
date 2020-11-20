use std::collections::{hash_map::Entry, HashMap};
use std::io;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

mod arp;
mod error;

const ARP_ENTRY_LIFETIME: Duration = Duration::from_secs(30);

use arp::{ArpEntry, MacAddress};

struct WaybarMessage {
    text: String,
    class: String,
    alt: String,
}
fn updates_arp(
    entries: &mut HashMap<Ipv4Addr, Vec<(MacAddress, Instant)>>,
) -> io::Result<Vec<String>> {
    let now = Instant::now();
    let mut changes = Vec::new();

    for ae in ArpEntry::from_os()?.drain(..) {
        match entries.entry(ae.ip) {
            Entry::Vacant(v) => {
                v.insert(vec![(ae.mac, now.clone())]);
            }
            Entry::Occupied(mut o) => {
                let key = o.key().clone();
                let all_macs = o.get_mut();

                // Evict old entries
                let mut updated_all_macs: Vec<_> = all_macs
                    .drain(..)
                    .filter(|&(_, when)| now - when < ARP_ENTRY_LIFETIME)
                    .collect();

                let mut found = false;
                for (mac, when) in updated_all_macs.iter_mut() {
                    if mac != &ae.mac {
                        changes.push(format!(
                            "Host {} has changed from {} to {} in {}s.",
                            key,
                            mac,
                            ae.mac,
                            (now - *when).as_secs()
                        ));
                    } else {
                        found = true;
                        *when = now;
                    }
                }

                if !found {
                    updated_all_macs.push((ae.mac, now));
                }

                let _ = std::mem::replace(all_macs, updated_all_macs);
            }
        }
    }

    #[cfg(debug_assertions)]
    eprintln!("entries = {:#?}", entries);

    Ok(changes)
}

fn jsonify_status(res: io::Result<Vec<String>>) {
    let (msg, class, alt): (String, String, String) = match res {
        Ok(msgs) => {
            if msgs.is_empty() {
                ("OK".into(), "".into(), "".into())
            } else {
                let mut alt =
                    String::with_capacity(msgs.iter().map(|m| m.len()).sum::<usize>() + msgs.len());
                for (i, msg) in msgs.iter().enumerate() {
                    if i > 0 {
                        alt.push('\n');
                    }
                    alt.push_str(msg);
                }
                ("MITM on going".into(), "warning".into(), alt)
            }
        }
        Err(e) => (format!("{}", e), "error".into(), "".into()),
    };
    serde_json::to_string(
    println!(
        "{{\"text\":{:?},\"class\":{:?},\"alt\":{:?}}}",
        msg, class, alt
    );
}

fn main() -> io::Result<()> {
    let mut current_entries: HashMap<Ipv4Addr, Vec<(MacAddress, Instant)>> = HashMap::new();
    let mut failed_updates = 0usize;
    updates_arp(&mut current_entries)?;

    loop {
        std::thread::sleep(Duration::from_secs(1));
        let ret = updates_arp(&mut current_entries);
        if ret.is_err() {
            failed_updates += 1;
        }

        jsonify_status(ret);

        if failed_updates > 5 {
            let e = format!("Got {} failed updates in a row, exitting", failed_updates);
            return Err(io::Error::new(io::ErrorKind::Other, e));
        }
    }
}
