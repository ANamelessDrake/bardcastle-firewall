# Bardcastle Firewall - Maintenance Guide

## System Updates

### Manual Updates

```bash
sudo apt update && sudo apt upgrade -y
```

Reboot if a kernel update was installed:

```bash
sudo reboot
```

### Automatic Security Updates

The hardening phase configures `unattended-upgrades` to automatically install security patches from the `${distro_codename}-security` pocket. Automatic reboots are disabled -- kernel updates require a manual reboot.

Check the unattended-upgrades log:

```bash
cat /var/log/unattended-upgrades/unattended-upgrades.log
```

Verify the configuration:

```bash
cat /etc/apt/apt.conf.d/50bardcastle
```

---

## Backing Up Configuration

The following files contain all state needed to restore the firewall:

| File / Directory | Contents |
|---|---|
| `/etc/bardcastle/config.yaml` | Master config (interfaces, VPN keys, client list, module state) |
| `/etc/wireguard/` | WireGuard server and client configs (includes private keys) |
| `/etc/nftables.conf` | Active firewall ruleset |
| `/etc/dnsmasq.conf` | DNS/DHCP configuration |
| `/etc/ssh/sshd_config.d/99-bardcastle.conf` | SSH hardening drop-in |
| `/etc/fail2ban/jail.d/bardcastle.conf` | fail2ban jail config |

### Quick Backup Script

```bash
#!/bin/bash
BACKUP_DIR="/root/bardcastle-backup-$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

cp /etc/bardcastle/config.yaml "$BACKUP_DIR/"
cp -r /etc/wireguard/ "$BACKUP_DIR/wireguard/"
cp /etc/nftables.conf "$BACKUP_DIR/"
cp /etc/dnsmasq.conf "$BACKUP_DIR/"
cp /etc/ssh/sshd_config.d/99-bardcastle.conf "$BACKUP_DIR/"
cp /etc/fail2ban/jail.d/bardcastle.conf "$BACKUP_DIR/"

tar czf "$BACKUP_DIR.tar.gz" "$BACKUP_DIR"
rm -rf "$BACKUP_DIR"

echo "Backup saved to $BACKUP_DIR.tar.gz"
```

> **Security note**: The backup contains WireGuard private keys and other secrets. Store it in a secure location and restrict permissions (`chmod 600`).

The `bardcastle-fw` tool also keeps timestamped backups of config files it overwrites in the `backups/` directory within the project repository.

---

## Managing VPN Clients

### Add a New Client

```bash
sudo bardcastle-fw vpn add-client <name>
```

This generates a client keypair, assigns the next available IP in `10.10.10.0/24` plus the matching IPv6 address from the tunnel's ULA prefix (the IPv4 host octet is reused, so `10.10.10.5` becomes `<prefix>::5`), updates the server config, restarts WireGuard, and prints the client configuration. If `qrencode` is installed, a scannable QR code is also displayed for mobile devices.

Clients created before the tunnel became dual stack keep working over IPv4 and gain IPv6 by adding their IPv6 address to the `Address` line, with no re-keying. See "Enabling IPv6 on a client created before the tunnel was dual stack" in [vpn-client-setup.md](vpn-client-setup.md), and note that NetworkManager-managed Linux clients need an `nmcli` change as well, because editing the config file alone has no effect there.

Example:

```bash
sudo bardcastle-fw vpn add-client laptop
# Outputs client config to paste into WireGuard app
# and optionally a QR code
```

### View Connected Peers

```bash
sudo bardcastle-fw vpn peers
# or directly:
sudo wg show
```

### Remove a Client

Currently, client removal is manual:

1. Edit `/etc/bardcastle/config.yaml` and remove the client entry from the `vpn.clients` list
2. Regenerate the server config and restart WireGuard:

```bash
sudo bardcastle-fw vpn setup
# When prompted, choose to reconfigure
```

Alternatively, edit `/etc/wireguard/wg0.conf` directly to remove the `[Peer]` block, then:

```bash
sudo systemctl restart wg-quick@wg0
```

---

## Updating Blocklists

### Automatic Updates

A cron job at `/etc/cron.d/bardcastle-blocklists` runs daily at 04:00:

```
0 4 * * * root bardcastle-fw blocklist update > /dev/null 2>&1
```

This downloads the FireHOL level-1 netset and reloads the nftables `blocklist_v4` set. If CrowdSec is installed, it also updates the CrowdSec hub and collections.

### Manual Update

```bash
sudo bardcastle-fw blocklist update
```

### View Blocklist Statistics

```bash
bardcastle-fw blocklist stats
```

This shows the number of IPs in the nftables blocklist set and, if CrowdSec is installed, the number of active CrowdSec decisions (blocked IPs).

---

## Monitoring

### Status Dashboard

```bash
sudo bardcastle-fw status
```

Displays a comprehensive overview:

- Network interfaces (IPs, link state)
- Active DHCP leases
- WireGuard peer status
- Firewall rule hit counters
- CrowdSec blocked IP count
- System resources (RAM usage, CPU load averages)
- WAN bandwidth statistics (today and month, via vnstat)

### Bandwidth Monitoring

```bash
# Summary for all interfaces
vnstat

# Detailed daily stats for WAN
vnstat -i enp1s0 -d

# Live traffic rate
vnstat -i enp1s0 -l
```

### DHCP Leases

```bash
bardcastle-fw dns leases
```

### Firewall Rules and Counters

```bash
sudo bardcastle-fw firewall show
```

### Service Logs

```bash
# Firewall drops (nftables logs)
journalctl -k | grep "nft-"

# dnsmasq (DNS/DHCP)
journalctl -u dnsmasq -f

# WireGuard
journalctl -u wg-quick@wg0

# fail2ban
journalctl -u fail2ban -f
sudo fail2ban-client status sshd

# CrowdSec (if installed)
journalctl -u crowdsec -f
sudo cscli decisions list

# Suricata (if installed)
journalctl -u suricata -f
tail -f /var/log/suricata/fast.log

# Unattended upgrades
cat /var/log/unattended-upgrades/unattended-upgrades.log
```

### Event Log

All bardcastle events are recorded in structured JSON:

```bash
tail -f /var/log/bardcastle/events.jsonl
```

---

## Troubleshooting

### DNS Not Working for LAN Clients

**Symptom**: LAN clients get an IP via DHCP but cannot resolve domain names.

1. Check if dnsmasq is running:
   ```bash
   systemctl status dnsmasq
   ```

2. Check if port 53 is in use by something else:
   ```bash
   sudo ss -tulnp | grep :53
   ```
   If `systemd-resolved` is listening, disable it:
   ```bash
   sudo systemctl disable --now systemd-resolved
   ```

3. Test DNS from the router itself:
   ```bash
   dig @127.0.0.1 google.com
   ```

4. Check dnsmasq logs:
   ```bash
   journalctl -u dnsmasq --no-pager -n 50
   ```

### No Internet Access from LAN

**Symptom**: LAN clients have a `10.0.1.x` IP and can ping the router (`10.0.1.1`) but cannot reach the internet.

1. Verify IP forwarding is enabled:
   ```bash
   sysctl net.ipv4.ip_forward
   # Should return: net.ipv4.ip_forward = 1
   ```

2. Verify the WAN interface has an IP:
   ```bash
   ip addr show enp1s0
   ```

3. Verify NAT masquerade is active:
   ```bash
   sudo nft list table ip nat
   ```
   Look for the `masquerade` rule in the postrouting chain.

4. Verify the router can reach the internet:
   ```bash
   ping -c 3 1.1.1.1
   ```

5. Check nftables forward chain is allowing LAN-to-WAN:
   ```bash
   sudo nft list chain inet filter forward
   ```

### WireGuard Not Connecting

**Symptom**: VPN client shows "handshake did not complete" or cannot reach LAN resources.

1. Check the WireGuard interface is up:
   ```bash
   sudo wg show
   ```

2. Verify the firewall allows UDP on the VPN port (default 51820) on the WAN interface:
   ```bash
   sudo nft list chain inet filter input | grep -i wireguard
   ```

3. Verify port forwarding on the Comcast gateway (if not in bridge mode): UDP port 51820 must be forwarded to the WAN IP of `bardcastle-fw`.

4. Check that the client config has the correct server public key and endpoint:
   ```bash
   sudo cat /etc/bardcastle/config.yaml | grep server_public_key
   ```

5. Restart the WireGuard interface:
   ```bash
   sudo systemctl restart wg-quick@wg0
   ```

### Locked Out of SSH

**Symptom**: Cannot SSH into the router after the hardening phase.

The hardening config disables password authentication and restricts access to a single user. If locked out:

1. **Access via local console** (keyboard + monitor connected to the box)

2. Temporarily restore password auth:
   ```bash
   sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' \
       /etc/ssh/sshd_config.d/99-bardcastle.conf
   sudo systemctl restart sshd
   ```

3. Copy your SSH public key:
   ```bash
   ssh-copy-id admin@10.0.1.1
   ```

4. Re-disable password auth:
   ```bash
   sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' \
       /etc/ssh/sshd_config.d/99-bardcastle.conf
   sudo systemctl restart sshd
   ```

### fail2ban Banned Your IP

```bash
# Check if your IP is banned
sudo fail2ban-client status sshd

# Unban a specific IP
sudo fail2ban-client set sshd unbanip <your-ip>
```

### High Memory Usage

On a 2 GB system, memory can be tight if Suricata is enabled. Check what is using RAM:

```bash
sudo bardcastle-fw status   # Shows RAM usage in the dashboard
free -h
ps aux --sort=-%mem | head -10
```

If Suricata is consuming too much memory, disable it:

```bash
sudo bardcastle-fw ids disable
```
