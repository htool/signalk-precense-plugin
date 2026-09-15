# signalk-precense-plugin

Signal K plugin: LAN device presence (ping + ARP/neigh).

Paths: `sensors.presence.<name>` (boolean, only on change), `.lastSeen` (every ping interval), `.ip` (only when the address changes).

Tip: fixed DHCP; Private Wi-Fi Address off on boat SSID.
