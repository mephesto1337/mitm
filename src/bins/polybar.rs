use std::{
    fs,
    io::{self, Write},
    thread::sleep,
    time::{Duration, Instant},
};

use mitm::ArpTable;

const COLOR_ORANGE: &'static str = "%{F#ff9d00}";
const COLOR_RED: &'static str = "%{F#ff0000}";
const COLOR_RESET: &'static str = "%{F-}";
const LOG_FILE: &'static str = "/home/thomas/tmp/arp.log";

fn to_format(text: String, color: String, tooltip: Option<String>) {
    fn write_tooltip(tooltip: String) -> io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .append(true)
            .create(true)
            .open(LOG_FILE)?;
        file.write_all(&b"\n"[..])?;
        file.write_all(tooltip.as_bytes())?;

        Ok(())
    }

    let mut tooltip_err = None;

    if let Some(tooltip) = tooltip {
        if let Err(e) = write_tooltip(tooltip) {
            tooltip_err = Some(format!("{}", e));
        }
    }

    if let Some(e) = tooltip_err {
        println!(
            "{color}ARP: {text}{color_end}",
            color = COLOR_RED,
            text = e,
            color_end = COLOR_RESET
        );
    } else {
        println!(
            "{color}ARP: {text}{color_end}",
            color = color,
            text = text,
            color_end = COLOR_RESET
        );
    }
}

fn main() -> io::Result<()> {
    let mut entries = ArpTable::new(None)?;

    loop {
        sleep(Duration::from_secs(1));

        let (text, color, tooltip): (Option<String>, Option<String>, Option<String>) =
            match entries.update() {
                Ok(mut changes) => {
                    if changes.is_empty() {
                        (Some("OK".into()), None, None)
                    } else {
                        let mut tooltip = String::with_capacity(changes.len() * 83);
                        let text = "⚠ MITM attack".into();
                        let now = Instant::now();
                        for change in changes.drain(..) {
                            tooltip.push_str(&format!(
                                "Host {} has changed from {} to {} in {}s\n",
                                change.host,
                                change.old_mac.0,
                                change.new_mac,
                                (now - change.old_mac.1).as_secs()
                            ));
                        }

                        (Some(text), Some(COLOR_ORANGE.into()), Some(tooltip))
                    }
                }
                Err(e) => {
                    let text = format!("{}", e);
                    (Some(text), Some(COLOR_RED.into()), None)
                }
            };

        let text = text.unwrap_or_else(String::new);
        let color = color.unwrap_or_else(String::new);
        to_format(text, color, tooltip);
    }
}
