#!/usr/bin/env bash
# Auto-detect physical NICs and configure WAN/LAN networking.
# First NIC (by PCI bus order) = WAN (DHCP), second = LAN (static 10.0.1.1/24).
# Called during autoinstall late-commands inside the target chroot.

set -euo pipefail

# Find physical interfaces sorted by name (PCI bus order)
IFACES=()
for iface in /sys/class/net/*/device; do
    name="$(basename "$(dirname "$iface")")"
    [[ "$name" != "lo" ]] && IFACES+=("$name")
done
IFS=$'\n' IFACES=($(sort <<<"${IFACES[*]}")); unset IFS

if [[ ${#IFACES[@]} -lt 2 ]]; then
    echo "ERROR: Need at least 2 physical NICs, found ${#IFACES[@]}" >&2
    exit 1
fi

WAN="${IFACES[0]}"
LAN="${IFACES[1]}"

echo "Auto-detected interfaces: WAN=$WAN  LAN=$LAN"

# Remove any netplan configs left by the installer
rm -f /etc/netplan/*.yaml

# Enable systemd-networkd
systemctl enable systemd-networkd

# WAN: DHCP client, ignore ISP DNS
mkdir -p /etc/systemd/network
cat > /etc/systemd/network/10-wan.network <<EOF
[Match]
Name=$WAN

[Network]
DHCP=yes

[DHCP]
UseDNS=no
UseNTP=yes
ClientIdentifier=mac
EOF

# LAN: static 10.0.1.1/24
# ConfigureWithoutCarrier so the LAN IP (and dnsmasq, which binds to it)
# survives the switch being off or unplugged.
cat > /etc/systemd/network/20-lan.network <<EOF
[Match]
Name=$LAN

[Link]
RequiredForOnline=no

[Network]
Address=10.0.1.1/24
ConfigureWithoutCarrier=yes
EOF

# IP forwarding and router hardening
cat > /etc/sysctl.d/99-router.conf <<EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.${WAN}.accept_ra = 2
net.ipv6.conf.${WAN}.autoconf = 0
EOF

# Firewall: basic NAT + default-drop + blocklist sets
cat > /etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    set blocklist_v4 {
        type ipv4_addr
        flags interval
    }
    set blocklist_v6 {
        type ipv6_addr
        flags interval
    }

    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        iif lo accept
        iif ${WAN} ip saddr @blocklist_v4 drop
        iif ${WAN} ip6 saddr @blocklist_v6 drop
        icmp type echo-request accept
        icmpv6 type { echo-request, nd-neighbor-solicit, nd-router-advert, nd-neighbor-advert } accept
        iif ${LAN} tcp dport 22 accept
        iif ${LAN} udp dport 53 accept
        iif ${LAN} tcp dport 53 accept
        iif ${LAN} udp dport 67 accept
        iif ${WAN} udp dport 51820 accept
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
        ct state established,related accept
        iif ${LAN} oif ${WAN} accept
        iif wg0 oif ${LAN} accept
        iif wg0 oif ${WAN} accept
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}

table ip nat {
    chain postrouting {
        type nat hook postrouting priority 100;
        oif ${WAN} masquerade
    }

    chain prerouting {
        type nat hook prerouting priority -100;
    }
}
EOF

systemctl enable nftables

# Write bardcastle config so the CLI tool knows what's already configured
mkdir -p /etc/bardcastle
# bootstrap stays false: first-boot only installs a minimal package set;
# the full bootstrap phase (dnsmasq, fail2ban, wireguard-tools, vnstat,
# bloat removal) must still run via 'bardcastle-fw setup'.
cat > /etc/bardcastle/config.yaml <<EOF
configured:
  bootstrap: false
  network: true
  firewall: true
  dns: false
  vpn: false
  hardening: false
  monitoring: false
  blocklists: false
network:
  wan_interface: ${WAN}
  lan_interface: ${LAN}
  lan_ip: 10.0.1.1
  lan_subnet: 24
  dhcp_start: 10.0.1.100
  dhcp_end: 10.0.1.200
  domain: example.com
EOF
chmod 600 /etc/bardcastle/config.yaml

echo "Done: WAN=${WAN} (DHCP)  LAN=${LAN} (10.0.1.1/24)  Firewall=enabled"
