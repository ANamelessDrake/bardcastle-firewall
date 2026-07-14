# Bardcastle Firewall - Installation Guide

Step-by-step guide from bare metal to a working Ubuntu LTS router/firewall.

---

## Phase 1: Ubuntu Server Installation

### Create Bootable USB

Download [Ubuntu Server 24.04 LTS](https://ubuntu.com/download/server) and write it to a USB drive:

```bash
# From a Linux workstation (replace /dev/sdX with your USB device)
sudo dd if=ubuntu-24.04-live-server-amd64.iso of=/dev/sdX bs=4M status=progress
sync
```

### Install Ubuntu Server

Boot the Celeron J1900 box from the USB drive and walk through the installer:

1. **Language**: English
2. **Keyboard**: US (or your layout)
3. **Installation type**: Ubuntu Server (minimized) -- select the minimal install
4. **Network**: Leave defaults for now (DHCP on whatever port is connected); networking will be reconfigured by `bardcastle-fw`
5. **Proxy**: Leave blank unless required
6. **Mirror**: Default archive mirror
7. **Storage**: Use entire disk, defaults are fine for a dedicated firewall box
8. **Profile**:
   - Your name: `admin`
   - Server name: `bardcastle-fw`
   - Username: `admin`
   - Password: choose a strong password
9. **SSH**: Enable OpenSSH server, optionally import SSH keys from GitHub
10. **Snaps**: Skip all snap selections -- do not install any snaps
11. **Reboot** when prompted and remove the USB drive

### Post-Install Baseline

After first boot, log in at the console (or via SSH if the box has a DHCP address) and confirm the system is up to date:

```bash
sudo apt update && sudo apt upgrade -y
sudo reboot
```

---

## Phase 2: Install bardcastle-firewall

### Clone the Repository

```bash
sudo apt install -y git python3-pip python3-venv
cd ~
git clone https://github.com/YOUR-USERNAME/bardcastle-firewall.git
cd bardcastle-firewall
```

### Install the CLI Tool

```bash
pip install -e .
```

This installs the `bardcastle-fw` command globally via the `console_scripts` entry point. Dependencies installed: Click (CLI framework), Jinja2 (config templating), PyYAML (config persistence).

### Run Full Setup

> **Important**: Run the setup command from a **local console** (keyboard + monitor or IPMI/serial), **not** over SSH. The network phase restarts systemd-networkd and will briefly drop connectivity, which will kill an SSH session.

```bash
sudo bardcastle-fw setup
```

---

## Phase 3: What the Setup Command Does

The `setup` command runs eight phases in sequence. Each phase can be skipped or re-run individually. Configuration state is saved to `/etc/bardcastle/config.yaml` after each phase.

### 1. Bootstrap

- Removes bloat packages: `snapd`, `cloud-init`, `netplan.io`, `network-manager`
- Installs required packages: `nftables`, `dnsmasq`, `wireguard-tools`, `vnstat`, `fail2ban`, `htop`, `tmux`, `curl`, and Python dependencies
- Disables `systemd-resolved` (frees port 53 for dnsmasq)
- Enables `systemd-networkd`
- Optionally installs **CrowdSec** (community threat intelligence with nftables bouncer)
- Optionally installs **Suricata IDS** (network intrusion detection -- uses 200-400 MB RAM, significant on a 2 GB system)

### 2. Network

- Detects physical network interfaces and displays them (name, MAC, state, speed, driver)
- Prompts you to assign **WAN** and **LAN** roles to interfaces (typically `enp1s0` for WAN, `enp2s0` for LAN)
- Prompts for LAN IP address (default: `10.0.1.1`), subnet prefix (default: `/24`), and DHCP range (default: `10.0.1.100` - `10.0.1.200`)
- Prompts for domain name (default: `example.com`)
- Writes systemd-networkd unit files to `/etc/systemd/network/`
- Writes IP forwarding sysctl config to `/etc/sysctl.d/99-router.conf`
- Restarts systemd-networkd (this is where connectivity blips if you are on SSH)

### 3. Firewall

- Renders the nftables ruleset from the `nftables.conf.j2` template using your WAN/LAN interface names and VPN port
- Validates the ruleset with `nft -c -f` (dry run) before applying
- Applies the ruleset and enables the `nftables` systemd service
- Default policy: drop all input and forward traffic, then explicitly allow required services (SSH from LAN, DNS/DHCP from LAN, WireGuard from WAN, established/related connections)
- Sets up NAT masquerade for LAN and VPN traffic leaving via WAN
- Creates empty `blocklist_v4` and `blocklist_v6` nftables sets for CrowdSec/FireHOL population

### 4. DNS/DHCP

- Configures dnsmasq as both DNS forwarder and DHCP server on the LAN interface
- Prompts for upstream DNS servers (default: `1.1.1.1`, `9.9.9.9`)
- Installs a DHCP event hook script that logs lease events to `/var/log/bardcastle/events.jsonl`
- Enables and starts dnsmasq, then runs a DNS resolution test

### 5. VPN

- Generates a WireGuard server keypair
- Prompts for VPN server IP (default: `10.10.10.1`) and listen port (default: `51820`)
- Writes the server config to `/etc/wireguard/wg0.conf` (mode `0600`)
- Enables and starts `wg-quick@wg0`

### 6. Blocklists

- If CrowdSec is installed, updates the hub and installs the `crowdsecurity/linux` collection
- Downloads the FireHOL level-1 blocklist and loads all IPs/CIDRs into the nftables `blocklist_v4` set
- Sets up a daily cron job at `/etc/cron.d/bardcastle-blocklists` (runs at 04:00)

### 7. Hardening

- Writes an SSH hardening drop-in config to `/etc/ssh/sshd_config.d/99-bardcastle.conf`:
  - Disables root login and password auth
  - Enables public key auth only
  - Restricts access to the configured SSH user
  - Limits auth attempts to 3
  - Disables X11/TCP/agent forwarding
- Validates the sshd config with `sshd -t` before restarting
- Configures fail2ban for SSH (5 retries, 1-hour ban, 10-minute window)
- Installs and configures `unattended-upgrades` for security-only automatic updates
- Sets restrictive file permissions on `/etc/wireguard` (700), `/etc/nftables.conf` (600), `/etc/bardcastle` (700)

### 8. Monitoring

- Enables vnstat bandwidth monitoring on both WAN and LAN interfaces
- Configures journald log retention to 100 MB maximum
- Restarts systemd-journald

---

## Phase 4: Verification

After setup completes, verify everything is working:

```bash
# Overall status dashboard
sudo bardcastle-fw status

# Check each service individually
systemctl status systemd-networkd
systemctl status nftables
systemctl status dnsmasq
systemctl status wg-quick@wg0
systemctl status fail2ban
systemctl status vnstat

# Verify firewall rules are loaded
sudo nft list ruleset

# Verify DNS resolution from the router
dig @127.0.0.1 google.com

# Verify WireGuard interface is up
sudo wg show

# Check IP forwarding is enabled
sysctl net.ipv4.ip_forward

# From a LAN client, verify DHCP and DNS
# (connect a device to the LAN switch -- it should get a 10.0.1.x address)
```

### Add Your First VPN Client

```bash
sudo bardcastle-fw vpn add-client phone
```

This generates a client config and optionally displays a QR code (if `qrencode` is installed) for scanning with the WireGuard mobile app.

---

## Troubleshooting the Install

**Setup fails at the network phase**: Make sure you are running from a local console. If run over SSH, the network restart will kill your session. Reconnect and run `sudo bardcastle-fw network setup` to retry.

**dnsmasq fails to start**: systemd-resolved may still be holding port 53. Verify it is stopped: `systemctl status systemd-resolved`. If still active, run `sudo systemctl disable --now systemd-resolved` and retry.

**SSH locked out after hardening**: The hardening phase disables password auth. Make sure your SSH public key is in `~admin/.ssh/authorized_keys` before running the hardening phase. If locked out, access via local console and edit `/etc/ssh/sshd_config.d/99-bardcastle.conf`.
