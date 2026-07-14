# Bardcastle Firewall - Architecture

## Network Diagram

```
                                    +--------------------------+
                                    |       INTERNET           |
                                    +-----------+--------------+
                                                |
                                    +-----------+--------------+
                                    |   Comcast Cable Gateway   |
                                    |   (bridge / passthrough)  |
                                    +-----------+--------------+
                                                |
                                                | WAN (DHCP from ISP)
                                                |
                              +-----------------+------------------+
                              |          bardcastle-fw             |
                              |     Celeron J1900  /  2 GB RAM     |
                              |     Ubuntu Server 24.04 LTS        |
                              |                                    |
                              |  enp1s0 (WAN) ---- enp2s0 (LAN)   |
                              |       |                  |         |
                              |   nftables NAT      10.0.1.1/24   |
                              |   WireGuard wg0                    |
                              |   10.10.10.1/24                    |
                              +-----------------+------------------+
                                                |
                                                | LAN (10.0.1.0/24)
                                                |
                                    +-----------+--------------+
                                    |     Ethernet Switch       |
                                    +-+-------+-------+--------+
                                      |       |       |
                                      |       |       |
                                   +--+--+ +--+--+ +--+--+
                                   | PC  | | NAS | | AP  |
                                   +-----+ +-----+ +-----+
                                                      |
                                                    Wi-Fi
                                                      |
                                                  +---+---+
                                                  | Phone |
                                                  +-------+

          Remote VPN Clients
          (WireGuard 10.10.10.0/24)
                |
                +--- phone  (10.10.10.2)
                +--- laptop (10.10.10.3)
                |
                +---> WAN:51820/UDP ---> bardcastle-fw ---> LAN / Internet
```

## Design Decisions

### Why Ubuntu Server Over pfSense / OPNsense / IPFire

The original plan was to run pfSense (or OPNsense) on this box. That hit a wall because of a well-known FreeBSD kernel bug affecting Intel Bay Trail (Celeron J1900) network controllers. The `igb` driver on FreeBSD triggers intermittent TX queue stalls under moderate load, causing packet loss and eventually a hung interface that requires a reboot. The bug has been open for years with no reliable fix upstream.

IPFire (Linux-based) was evaluated but its web UI and update model add unnecessary complexity for a single-site firewall that can be managed entirely from the command line.

Ubuntu Server 24.04 LTS was chosen because:

- The `igb` / `e1000e` drivers on the Linux kernel are mature and stable on Bay Trail hardware
- 5 years of LTS security support with `unattended-upgrades` for hands-off patching
- Full access to the standard Linux networking stack (systemd-networkd, nftables, WireGuard kernel module)
- Scriptable and reproducible -- the entire configuration is driven by a Python CLI tool with Jinja2 templates
- Low memory footprint -- base system uses roughly 200 MB of RAM, leaving headroom on a 2 GB box

### Why Each Component

| Component | Role | Why This Over Alternatives |
|---|---|---|
| **systemd-networkd** | Interface config, DHCP client on WAN | Already part of systemd; no extra packages. Replaces netplan/NetworkManager which are unnecessary on a headless router. |
| **nftables** | Stateful firewall, NAT, blocklist sets | Successor to iptables, ships with Ubuntu. Named sets make blocklist integration clean. |
| **dnsmasq** | DNS forwarder + DHCP server | Single lightweight binary handles both DNS and DHCP. Tiny memory footprint compared to running BIND + ISC DHCP separately. |
| **WireGuard** | VPN | Kernel-native on Linux 5.6+, minimal config, excellent performance, low overhead. |
| **CrowdSec** | Community threat intelligence | Crowdsourced IP reputation database with native nftables bouncer. Free tier is sufficient. Optional install. |
| **FireHOL level1** | IP blocklist | Curated aggregation of high-confidence abuse/malware IP lists. Loaded directly into nftables sets. |
| **Suricata** | Network IDS/IPS | Open-source with ET Open rules. Optional due to RAM usage (200-400 MB on a 2 GB system). |
| **fail2ban** | SSH brute-force protection | Watches auth logs and dynamically bans IPs. Lightweight and well-proven. |
| **unattended-upgrades** | Automatic security patches | Security-only updates applied automatically. No manual intervention needed. |
| **vnstat** | Bandwidth monitoring | Lightweight daemon that tracks interface traffic over time. Negligible resource usage. |

## Software Stack

```
+------------------------------------------------------+
|                    bardcastle-fw CLI                  |
|               (Click + Jinja2 + PyYAML)              |
+------+--------+--------+-------+--------+-----------+
       |        |        |       |        |
  +----+---+ +--+---+ +-+----+ ++------+ +---+-------+
  |systemd | |nfta- | |dns-  | |Wire-  | |CrowdSec / |
  |networkd| |bles  | |masq  | |Guard  | |FireHOL    |
  +--------+ +------+ +------+ +-------+ +-----------+
       |        |        |       |        |
  +----+--------+--------+-------+--------+-----------+
  |              Linux Kernel (6.8 HWE)                |
  |        igb/e1000e drivers  |  nf_tables  |  wireguard  |
  +------------------------------------------------------+
  |          Celeron J1900  /  2 GB RAM  /  Dual NIC      |
  +------------------------------------------------------+
```

## Traffic Flow

### LAN to Internet

1. LAN client sends packet to its default gateway (`10.0.1.1`)
2. Packet arrives on `enp2s0` (LAN interface)
3. nftables forward chain: matched by `LAN to WAN` rule, accepted
4. nftables postrouting NAT: source address rewritten to WAN IP (masquerade)
5. Packet exits via `enp1s0` (WAN interface) toward the ISP gateway
6. Return traffic: matched by `ct state established,related`, forwarded back to LAN client

### VPN Client to LAN

1. WireGuard UDP packet arrives on `enp1s0` port 51820
2. nftables input chain: matched by WireGuard rule, accepted
3. WireGuard kernel module decapsulates the packet onto `wg0`
4. Decapsulated packet is forwarded from `wg0` to `enp2s0`
5. nftables forward chain: matched by `WG to LAN` rule, accepted
6. Packet delivered to the LAN destination

### Inbound from Internet (blocked)

1. Packet arrives on `enp1s0`
2. nftables input chain: source checked against `blocklist_v4` -- if matched, dropped immediately
3. If not blocklisted: no matching allow rule (only WireGuard UDP is allowed inbound on WAN)
4. Default policy: drop. Logged at rate-limited 5/minute with prefix `nft-input-drop:`

### DNS Resolution (LAN client)

1. LAN client sends DNS query to `10.0.1.1:53`
2. dnsmasq receives the query on `enp2s0`
3. If cached: responds immediately
4. If not cached: forwards to upstream resolvers (`1.1.1.1`, `9.9.9.9`) and caches the result

## Event System and Future Notification Architecture

All significant events are written as structured JSON to `/var/log/bardcastle/events.jsonl`:

```json
{"timestamp": "2025-03-14T12:00:00+00:00", "type": "dhcp_lease", "data": {"action": "add", "mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.1.101", "hostname": "laptop"}}
{"timestamp": "2025-03-14T12:05:00+00:00", "type": "blocklist_update", "data": {"source": "firehol_level1", "count": 14823}}
{"timestamp": "2025-03-14T13:00:00+00:00", "type": "vpn_connect", "data": {"client_name": "phone", "client_ip": "10.10.10.2"}}
```

Supported event types:

- `new_device` -- unknown MAC address seen on LAN
- `blocked_ip` -- traffic dropped by blocklist
- `vpn_connect` / `vpn_disconnect` -- WireGuard peer activity
- `ids_alert` -- Suricata IDS alert
- `dhcp_lease` -- DHCP lease add/remove/renew
- `service_restart` -- systemd unit restarted
- `config_change` -- configuration modified by bardcastle-fw
- `blocklist_update` -- blocklist refresh completed
- `login_attempt` -- SSH login attempt

### Planned: Notification Dispatch

The future notification pipeline will read from `events.jsonl` and dispatch alerts:

```
events.jsonl --> bardcastle-notify (daemon/cron)
                      |
                      +---> AWS SNS topic --> email / SMS
                      +---> Webhook (Discord, Slack, ntfy.sh)
                      +---> Local log aggregation
```

The log is rotated automatically when it exceeds 50 MB. A single rotated copy is kept at `events.jsonl.1`.

## Configuration Storage

All persistent configuration is stored in `/etc/bardcastle/config.yaml` (mode `0600`). This YAML file tracks:

- Which modules have been configured (bootstrap, network, firewall, dns_dhcp, vpn, hardening, monitoring)
- Network interface assignments and LAN addressing
- VPN server keys, port, and client list
- DNS upstream server choices
- Optional service flags (CrowdSec, Suricata)

Config templates live in the repository under `templates/` and are rendered by Jinja2 at setup time. Original system config files are backed up to the `backups/` directory before being overwritten.
