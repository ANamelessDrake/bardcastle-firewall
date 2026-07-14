# bardcastle-firewall

A Python CLI (`bardcastle-fw`) that turns a low-power x86 mini-PC into a full
router/firewall running Ubuntu Server 24.04 LTS. It provisions and manages
nftables, systemd-networkd, dnsmasq (DNS + DHCP), a WireGuard VPN, CrowdSec
IDS with FireHOL blocklists, SSH/system hardening, and a hardened local web
dashboard, all from templated config with backups and structured event logging.

It ships with an autoinstall ISO builder so a bare appliance can be brought up
unattended: boot from USB, walk away, and reboot into a ready-to-configure box.

## Contents

- [Why this exists](#why-this-exists)
- [Features](#features)
- [Network architecture](#network-architecture)
- [Requirements](#requirements)
- [Installation](#installation)
  - [Option A: automated ISO install](#option-a-automated-iso-install-recommended)
  - [Option B: manual install](#option-b-manual-install)
- [First-time setup](#first-time-setup)
- [Configuration](#configuration)
- [The web dashboard](#the-web-dashboard)
- [Managing the VPN](#managing-the-vpn)
- [Day-to-day operations](#day-to-day-operations)
- [Verification](#verification)
- [Project structure](#project-structure)
- [Documentation](#documentation)
- [License](#license)

## Why this exists

The project began as a replacement for pfSense/OPNsense on a Celeron J1900
appliance whose Intel NICs hit a FreeBSD `igb` driver bug (intermittent Tx
queue hangs). Both pfSense and OPNsense are FreeBSD-based, so neither fixes it.
Rather than replace the hardware, this replaces the OS: Ubuntu Server 24.04 LTS
drives the same NICs cleanly with the kernel params `pcie_aspm=off
intel_idle.max_cstate=1`, and the whole firewall/router config is driven by one
Python CLI. It runs equally well on newer low-power boxes (for example N100
mini-PCs with Intel i226-V 2.5GbE NICs).

## Features

- **Stateful firewall** (nftables): default-drop policy, NAT masquerade, and
  IP blocklist sets matched on the WAN only.
- **Interface management** (systemd-networkd): WAN via DHCP, static LAN, IP
  forwarding.
- **DNS and DHCP** (dnsmasq): forwarding resolver, DHCP for the LAN, optional
  per-query logging, and name resolution for VPN clients.
- **WireGuard VPN**: server plus full client lifecycle (add, show/QR, re-key,
  revoke), per-client DNS names, dynamic DNS endpoint, and a dashboard-access
  allowlist so only your own devices can reach the web UI over the tunnel.
- **Intrusion detection** (CrowdSec + nftables bouncer) with FireHOL threat
  blocklists; optional Suricata IDS.
- **System hardening**: key-only SSH for a single user, fail2ban, unattended
  security upgrades, and locked-down file permissions.
- **Local web dashboard**: read-only FastAPI + React SPA served over HTTPS on
  the LAN (and, optionally, to specific VPN clients). Shows interfaces,
  bandwidth, DHCP leases, DNS activity, VPN client liveness, CrowdSec bans and
  alerts, and a live event feed. Runs as an unprivileged user with a narrow
  sudoers allowlist. Never exposed to the WAN.
- **Structured events**: every config change and notable network event is
  appended as JSON to an event log and surfaced live in the dashboard.
- **Reproducible deploys**: an autoinstall ISO builder and an idempotent
  first-boot script make a full reinstall hands-off.

## Network architecture

```
   Internet
      |
 [ WAN NIC ]  DHCP from upstream modem/router
      |
 +--------------------------------------------------+
 |  bardcastle-firewall (Ubuntu Server 24.04 LTS)   |
 |                                                  |
 |  nftables (default-drop, NAT, blocklists)        |
 |  systemd-networkd     dnsmasq (DNS+DHCP)         |
 |  WireGuard (wg0)      CrowdSec + FireHOL         |
 |  web dashboard (HTTPS, LAN/VPN only)             |
 +--------------------------------------------------+
      |                                   |
 [ LAN NIC ] 10.0.1.1/24            [ wg0 ] 10.10.10.1/24
      |                                   |
   LAN switch / AP                   VPN clients
   10.0.1.100-200 (DHCP)             10.10.10.0/24
```

See [docs/architecture.md](docs/architecture.md) for the full diagram, traffic
flows, and design rationale (including the 2 GB RAM footprint budget that
drives component choices such as dnsmasq over BIND).

## Requirements

- A low-power x86-64 mini-PC with at least two Ethernet NICs (one WAN, one
  LAN). 2 GB RAM minimum; Suricata wants more.
- Ubuntu Server 24.04 LTS.
- A build machine with `xorriso` if you use the ISO installer (any Linux
  distro works; the ISO builder is distro-agnostic).

## Installation

### Option A: automated ISO install (recommended)

Builds a custom Ubuntu installer that sets everything up unattended.

```bash
git clone https://github.com/YOUR-USERNAME/bardcastle-firewall.git
cd bardcastle-firewall

# Download the Ubuntu Server 24.04 LTS ISO into the repo root.
curl -LO https://releases.ubuntu.com/24.04/ubuntu-24.04.4-live-server-amd64.iso

# Build the custom autoinstall ISO (needs xorriso).
sudo ./autoinstall/build-iso.sh

# Flash to USB (find the device with lsblk; replace /dev/sdX).
sudo dd if=bardcastle-fw-autoinstall.iso of=/dev/sdX bs=4M conv=fsync status=progress
```

Before building, edit `autoinstall/user-data` and replace the placeholder
`password:` hash with your own:

```bash
openssl passwd -6      # paste the output into the password: field
```

Boot the appliance from USB. The installer will:

1. Install Ubuntu Server 24.04 LTS (minimal, no snaps).
2. Apply the GRUB kernel params that fix the Intel NIC Tx hangs.
3. Create the admin account and enable SSH.
4. Copy the repo to `/opt/bardcastle-firewall`, install the CLI, and install
   the web dashboard.
5. Reboot into a ready system.

A first-boot service finishes network and package setup idempotently (guarded
by marker files under `/etc/bardcastle/`), so it is safe across reboots.

### Option B: manual install

1. Install Ubuntu Server 24.04 LTS (minimal, no snaps).
2. Fix the Intel NIC hangs by adding to `/etc/default/grub`:
   ```
   GRUB_CMDLINE_LINUX_DEFAULT="pcie_aspm=off intel_idle.max_cstate=1"
   ```
   then `sudo update-grub && sudo reboot`.
3. Install the CLI:
   ```bash
   sudo apt install -y git python3-pip
   git clone https://github.com/YOUR-USERNAME/bardcastle-firewall.git
   cd bardcastle-firewall
   sudo pip install -e .
   ```
4. Run setup from a **local console** (not SSH: the network phase briefly drops
   connectivity):
   ```bash
   sudo bardcastle-fw setup
   ```

## First-time setup

`sudo bardcastle-fw setup` runs eight phases in order. Each is idempotent and,
on re-run, prompts **[R]econfigure / [S]kip**.

| Phase | What it does |
|---|---|
| **Bootstrap** | Removes bloat (snapd, cloud-init), installs packages, optionally installs CrowdSec/Suricata. |
| **Network** | Configures systemd-networkd for WAN (DHCP) and static LAN, enables IP forwarding. |
| **Firewall** | Generates and applies the nftables ruleset (validated with `nft -c` before apply). |
| **DNS/DHCP** | Configures dnsmasq for DNS forwarding and LAN DHCP. |
| **VPN** | Sets up the WireGuard server and prepares client management. |
| **Blocklists** | Loads FireHOL blocklists and wires up CrowdSec. |
| **Hardening** | Key-only SSH, fail2ban, unattended security upgrades, permissions. |
| **Monitoring** | Enables vnstat bandwidth tracking and caps journald size. |

You can also run any phase on its own, for example `sudo bardcastle-fw network
setup` or `sudo bardcastle-fw firewall apply`.

## Configuration

The runtime configuration lives at **`/etc/bardcastle/config.yaml`** (mode
0600, root only). The repo-root `config.yaml` is a commented reference template
only; the tool reads and writes the copy under `/etc/bardcastle/`. Each module
stores its settings under its own key, and `configured:` tracks which phases
have run.

Key sections:

```yaml
network:
  wan_interface: enp2s0      # WAN NIC (DHCP from upstream)
  lan_interface: enp3s0      # LAN NIC (static)
  lan_ip: 10.0.1.1
  lan_subnet: 24
  dhcp_start: 10.0.1.100
  dhcp_end: 10.0.1.200
  domain: example.com        # local domain
  upstream_dns: [1.1.1.1, 9.9.9.9]

vpn:
  server_ip: 10.10.10.1
  port: 51820
  hostname: vpn.example.com  # DDNS endpoint clients dial
  clients: []                # managed by the vpn subcommands

configured: {}               # per-module state, set by the tool
```

Reconfigure interactively per subsystem rather than editing by hand where
possible:

```bash
sudo bardcastle-fw network setup     # interfaces, LAN IP, DHCP range, domain
sudo bardcastle-fw dns setup         # upstream resolvers, query logging
sudo bardcastle-fw firewall apply    # re-render and apply nftables
sudo bardcastle-fw vpn setup         # WireGuard server, endpoint
```

Every module backs up the previous file to `backups/` before writing, and
validates before applying where possible (for example `nft -c -f` before
`nft -f`).

### Dynamic DNS

If your WAN IP is dynamic, the DDNS module keeps a Route 53 record pointed at
the current WAN IP so VPN clients can always reach the endpoint. A systemd
timer refreshes it; configure the hostname during `vpn setup` (default
`vpn.example.com`).

## The web dashboard

A read-only management dashboard, served over HTTPS from the firewall itself.
It is installed automatically by the ISO/first-boot flow, or by hand:

```bash
sudo bash /opt/bardcastle-firewall/webui/install.sh
sudo bardcastle-fw webui set-password
```

Then browse to `https://<lan-ip>/` (for example `https://10.0.1.1/`) and accept
the self-signed certificate warning once. Check service status with
`bardcastle-fw webui status`.

What it shows: interfaces and system resources, daily WAN bandwidth, DHCP
leases, DNS activity (top domains and clients, with a per-host drill-down),
WireGuard client liveness, CrowdSec active bans and recent alerts (with source
country), and a live event feed. Click a host anywhere to see its DNS activity.

Security model:

- Served on ports 80/443 on the LAN, and over the VPN only to clients you
  explicitly allow (see below). **Never** exposed on the WAN (enforced in the
  nftables rules).
- Runs as an unprivileged `bardcastle-web` user; privileged reads go through a
  narrow sudoers allowlist. There is no mutating endpoint.
- Session login on every data endpoint; HTTP redirects to HTTPS.

To allow a specific VPN client to reach the dashboard over the tunnel:

```bash
sudo bardcastle-fw vpn admin <client-name>            # grant
sudo bardcastle-fw vpn admin <client-name> --revoke   # remove
```

By default no VPN client can reach the dashboard; only granted clients are
allowed, and all other VPN users are denied by the default-drop policy.

## Managing the VPN

```bash
sudo bardcastle-fw vpn add-client <name>       # add a client, print config + QR
sudo bardcastle-fw vpn show-client <name>      # reprint a stored client config/QR
sudo bardcastle-fw vpn clients                 # list clients: online, last seen, admin
sudo bardcastle-fw vpn peers                   # raw WireGuard peer/handshake view
sudo bardcastle-fw vpn admin <name>            # allow this client to reach the dashboard
sudo bardcastle-fw vpn rotate-client <name>    # re-key one client
sudo bardcastle-fw vpn rotate-all              # re-key all stored clients (compromise drill)
sudo bardcastle-fw vpn remove-client <name>    # revoke a client immediately
```

By default the server generates a client keypair, prints a complete config plus
a scannable QR code, and stores only the public key. Use `--pubkey` for a
device-generated key (the private key never touches the server), or
`--server-key` to also store the key so it can be reprinted later. VPN clients
have no SSH access; only the admin account holds an SSH key. See
[docs/vpn-client-setup.md](docs/vpn-client-setup.md) for the per-OS client
walkthrough.

## Day-to-day operations

```bash
sudo bardcastle-fw status              # overall dashboard (interfaces, leases, peers, counters)

# DNS / DHCP
bardcastle-fw dns leases               # active DHCP leases
bardcastle-fw dns queries              # recent DNS queries (needs query logging on)

# Firewall
bardcastle-fw firewall rules           # human-readable rule table
sudo bardcastle-fw firewall show       # full nftables ruleset

# Threat intel / IDS
sudo bardcastle-fw blocklist update    # refresh FireHOL + CrowdSec blocklists
bardcastle-fw blocklist stats          # blocklist set sizes and drop counters
bardcastle-fw ids decisions            # CrowdSec active bans
bardcastle-fw ids alerts               # CrowdSec alerts (scenarios, source IPs)
bardcastle-fw ids scenarios            # installed detection scenarios
sudo bardcastle-fw ids enable          # enable optional Suricata IDS
```

Every subsystem also has a `status` subcommand (for example `bardcastle-fw vpn
status`). Structured events are written to `/var/log/bardcastle/events.jsonl`
and streamed live in the dashboard.

## Verification

```bash
sudo bardcastle-fw status              # everything at a glance
sudo nft list ruleset                  # firewall loaded
resolvectl query example.com           # DNS resolving on the router
sudo wg show                           # WireGuard up
sysctl net.ipv4.ip_forward             # forwarding enabled (should be 1)
```

From a LAN client, confirm it gets a `10.0.1.x` address via DHCP and can browse.
Then add your first VPN client with `sudo bardcastle-fw vpn add-client phone`
and scan the QR code.

**Setup fails at the network phase:** run it from a local console, not SSH; the
network restart drops SSH. Reconnect and re-run `sudo bardcastle-fw network
setup`.

**dnsmasq will not start:** systemd-resolved may still hold port 53. Run
`sudo systemctl disable --now systemd-resolved` and retry.

## Project structure

```
bardcastle-firewall/
├── bardcastle/            # Python package: one module per subsystem
│   ├── cli.py             # Click CLI: lazy-imports each subsystem
│   ├── bootstrap.py       # system prep
│   ├── network.py         # systemd-networkd
│   ├── firewall.py        # nftables
│   ├── dns_dhcp.py        # dnsmasq DNS + DHCP
│   ├── vpn.py             # WireGuard server + client lifecycle
│   ├── ddns.py            # Route 53 dynamic DNS
│   ├── blocklists.py      # CrowdSec, FireHOL, Suricata
│   ├── hardening.py       # SSH, fail2ban, upgrades
│   ├── monitoring.py      # vnstat, journald, status dashboard
│   ├── events.py          # structured JSON event log
│   └── utils.py           # config, template render, file writes with backup
├── templates/             # Jinja2 templates for every generated config
├── autoinstall/           # unattended ISO builder + first-boot setup
├── webui/                 # local dashboard
│   ├── backend/           # FastAPI read-only API
│   ├── frontend/          # React (Vite) SPA
│   ├── systemd/           # service units
│   ├── sudoers/           # narrow privileged-read allowlist
│   └── install.sh         # idempotent installer
├── docs/                  # install, architecture, VPN, maintenance guides
├── config.yaml            # commented reference template (runtime lives in /etc)
└── setup.py               # pip install -e .
```

Each subsystem module exposes `func(config: dict) -> dict` that renders a
template, backs up and writes the target file, validates and applies it, then
records state and emits an event.

## Documentation

- [Installation guide](docs/install-guide.md): bare metal to working router.
- [Architecture](docs/architecture.md): network diagram, design decisions,
  traffic flows.
- [VPN client setup](docs/vpn-client-setup.md): per-OS client setup and admin
  provisioning.
- [Web UI design](docs/web-ui-design.md): dashboard design and a proposal for an
  optional cloud-hosted variant.
- [Maintenance](docs/maintenance.md): updates, backups, troubleshooting.

## License

MIT
