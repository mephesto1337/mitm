use std::{
    io,
    thread::sleep,
    time::{Duration, Instant},
};

use mitm::ArpTable;

fn to_json(text: String, class: String, tooltip: String) {
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

        let (text, class, tooltip): (Option<String>, Option<String>, Option<String>) =
            match entries.update() {
                Ok(mut changes) => {
                    if changes.is_empty() {
                        (Some("OK".into()), None, None)
                    } else {
                        let mut tooltip = String::with_capacity(changes.len() * 83);
                        let text = "\\u26A0\\uFE0F MITM attack".into();
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

                        (Some(text), Some("warning".into()), Some(tooltip))
                    }
                }
                Err(e) => {
                    let text = format!("{}", e);
                    (Some(text), Some("error".into()), None)
                }
            };

        let text = text.unwrap_or_else(String::new);
        let class = class.unwrap_or_else(String::new);
        let tooltip = tooltip.unwrap_or_else(String::new);
        to_json(text, class, tooltip);
    }
}
