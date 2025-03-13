use std::{
    borrow::Cow,
    fmt::Write,
    io,
    thread::sleep,
    time::{Duration, Instant},
};

use mitm::ArpTable;

fn to_json(text: &str, class: &str, tooltip: &str) {
    println!(
        "{{\"text\":\"{}\",\"class\":\"{}\",\"tooltip\":\"{}\",\"alt\":\"{}\"}}",
        text,
        class,
        tooltip.replace('\n', "\\n"),
        tooltip.split('\n').next().expect("At least one part")
    );
}

fn main() -> io::Result<()> {
    let mut entries = ArpTable::new(None)?;

    loop {
        sleep(Duration::from_secs(1));

        let (text, class, tooltip): (Cow<'static, str>, &'static str, Option<String>) =
            match entries.update() {
                Ok(mut changes) => {
                    if changes.is_empty() {
                        ("OK".into(), "", None)
                    } else {
                        let mut tooltip = String::with_capacity(changes.len() * 83);
                        let text = "\\u26A0\\uFE0F MITM attack".into();
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

                        (text, "warning", Some(tooltip))
                    }
                }
                Err(e) => {
                    let text = format!("{}", e).into();
                    (text, "error", None)
                }
            };

        let tooltip = tooltip.unwrap_or_else(String::new);
        to_json(text.as_ref(), class, tooltip.as_str());
    }
}
