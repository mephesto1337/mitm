use std::{
    borrow::Cow,
    fmt::Write as FmtWrite,
    fs,
    io::{self, Write},
    thread::sleep,
    time::{Duration, Instant},
};

use mitm::ArpTable;

const COLOR_NONE: &str = "";
const COLOR_ORANGE: &str = "%{F#ff9d00}";
const COLOR_RED: &str = "%{F#ff0000}";
const COLOR_RESET: &str = "%{F-}";
const LOG_FILE: &str = "/home/thomas/tmp/arp.log";

fn to_format(text: Cow<'_, str>, color: &str, tooltip: Option<String>) {
    fn write_tooltip(tooltip: &str) -> io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(LOG_FILE)?;
        file.write_all(&b"\n"[..])?;
        file.write_all(tooltip.as_bytes())?;

        Ok(())
    }

    let mut tooltip_err = None;

    if let Some(tooltip) = tooltip {
        if let Err(e) = write_tooltip(&tooltip) {
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

        let (text, color, tooltip): (Cow<'static, str>, &'static str, Option<String>) =
            match entries.update() {
                Ok(mut changes) => {
                    if changes.is_empty() {
                        ("OK".into(), COLOR_NONE, None)
                    } else {
                        let mut tooltip = String::with_capacity(changes.len() * 83);
                        let text = "⚠ MITM attack".into();
                        let now = Instant::now();
                        for change in changes.drain(..) {
                            writeln!(
                                &mut tooltip,
                                "Host {} has changed from {} to {} in {}s",
                                change.host,
                                change.old_mac,
                                change.new_mac,
                                (now - change.old_mac_last_seen).as_secs()
                            )
                            .expect("Write to string cannot fail");
                        }

                        (text, COLOR_ORANGE, Some(tooltip))
                    }
                }
                Err(e) => {
                    let text = format!("{}", e).into();
                    (text, COLOR_RED, None)
                }
            };

        to_format(text, color, tooltip);
    }
}
