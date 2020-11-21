# A small tool to detect MITM attacks by watching `/proc/net/arp`.

# Lib
If an @IP changes of @MAC (and the previous MAC was seen less than 5 minutes
ago), then it is interpreted as a MITM attack. `ArpTable::update` will returns
all changes.
By default, a lifetime is valid for 300 seconds.

To see an example, check out [waybar-mitm](./src/bins/waybar.rs)

# Bins
## waybar-mitm
A binary to integrate with waybar as in:
```json
"custom/mitm": {
  "format": "ARP: {} ",
  "return-type": "json",
  "exec": "$HOME/local/bin/waybar-mitm"
},
```
