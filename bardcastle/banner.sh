#!/usr/bin/env bash
# Bardcastle Firewall - Pre-login status banner
# Runs at boot via systemd to generate /etc/issue with live system info.
# Displayed on the console BEFORE the login prompt.

set -euo pipefail

ISSUE_FILE="/etc/issue"

# Detect interfaces: physical NICs sorted by name (PCI bus order)
get_iface_ip() {
    local iface="$1"
    ip -4 addr show "$iface" 2>/dev/null | grep -oP 'inet \K[0-9./]+' | head -1
}

get_iface_state() {
    local iface="$1"
    cat "/sys/class/net/$iface/operstate" 2>/dev/null || echo "unknown"
}

get_iface_mac() {
    local iface="$1"
    cat "/sys/class/net/$iface/address" 2>/dev/null || echo "unknown"
}

# Count DHCP leases
lease_count() {
    if [[ -f /var/lib/misc/dnsmasq.leases ]]; then
        grep -c . /var/lib/misc/dnsmasq.leases 2>/dev/null || echo "0"
    else
        echo "-"
    fi
}

# WireGuard peer count
wg_peers() {
    if command -v wg &>/dev/null; then
        wg show all peers 2>/dev/null | wc -l || echo "0"
    else
        echo "-"
    fi
}

# CrowdSec blocked count
cs_blocked() {
    if command -v cscli &>/dev/null; then
        cscli decisions list -o raw 2>/dev/null | tail -n +2 | wc -l || echo "0"
    else
        echo "-"
    fi
}

# Memory
mem_info() {
    local total avail used pct
    total=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
    avail=$(awk '/MemAvailable/ {print $2}' /proc/meminfo)
    used=$(( total - avail ))
    pct=$(( used * 100 / total ))
    echo "$(( used / 1024 ))M / $(( total / 1024 ))M (${pct}%)"
}

# Load
load_info() {
    awk '{print $1, $2, $3}' /proc/loadavg
}

# Read config to find WAN/LAN interface names
WAN_IFACE=""
LAN_IFACE=""
if [[ -f /etc/bardcastle/config.yaml ]]; then
    WAN_IFACE=$(grep 'wan_interface:' /etc/bardcastle/config.yaml 2>/dev/null | awk '{print $2}' || true)
    LAN_IFACE=$(grep 'lan_interface:' /etc/bardcastle/config.yaml 2>/dev/null | awk '{print $2}' || true)
fi

# Fallback: auto-detect from systemd-networkd configs
if [[ -z "$WAN_IFACE" ]]; then
    WAN_IFACE=$(grep -l 'DHCP=yes' /etc/systemd/network/*.network 2>/dev/null \
        | xargs -r grep -oP 'Name=\K.*' | head -1 || true)
fi
if [[ -z "$LAN_IFACE" ]]; then
    LAN_IFACE=$(grep -l 'Address=' /etc/systemd/network/*.network 2>/dev/null \
        | xargs -r grep -oP 'Name=\K.*' | head -1 || true)
fi

# Fallback: first two physical interfaces
if [[ -z "$WAN_IFACE" || -z "$LAN_IFACE" ]]; then
    PHYS_IFACES=()
    for iface in /sys/class/net/*/device; do
        name="$(basename "$(dirname "$iface")")"
        [[ "$name" != "lo" ]] && PHYS_IFACES+=("$name")
    done
    IFS=$'\n' PHYS_IFACES=($(sort <<<"${PHYS_IFACES[*]}")); unset IFS
    [[ -z "$WAN_IFACE" && ${#PHYS_IFACES[@]} -ge 1 ]] && WAN_IFACE="${PHYS_IFACES[0]}"
    [[ -z "$LAN_IFACE" && ${#PHYS_IFACES[@]} -ge 2 ]] && LAN_IFACE="${PHYS_IFACES[1]}"
fi

WAN_IP=$(get_iface_ip "$WAN_IFACE" 2>/dev/null || echo "no address")
WAN_STATE=$(get_iface_state "$WAN_IFACE" 2>/dev/null || echo "unknown")
WAN_MAC=$(get_iface_mac "$WAN_IFACE" 2>/dev/null || echo "unknown")

LAN_IP=$(get_iface_ip "$LAN_IFACE" 2>/dev/null || echo "no address")
LAN_STATE=$(get_iface_state "$LAN_IFACE" 2>/dev/null || echo "unknown")
LAN_MAC=$(get_iface_mac "$LAN_IFACE" 2>/dev/null || echo "unknown")

WG_IP=$(get_iface_ip "wg0" 2>/dev/null || echo "not configured")

UPTIME=$(uptime -p 2>/dev/null || echo "unknown")

# Check if first-boot setup is still incomplete
SETUP_MSG=""
if [[ ! -f /etc/bardcastle/.first-boot-done ]]; then
    if [[ ! -f /etc/bardcastle/.packages-done ]]; then
        SETUP_MSG=" │  !! Setup incomplete. After login run:                   │
 │  !!   sudo bardcastle-first-login                        │
 │                                                          │"
    fi
fi

HOSTNAME_STR=$(hostname 2>/dev/null || echo "bardcastle-fw")

BANNER=$(cat <<EOF

 ┌──────────────────────────────────────────────────────────┐
 │            BARDCASTLE FIREWALL  ·  ${HOSTNAME_STR}
 ├──────────────────────────────────────────────────────────┤
 │
 │  WAN  (${WAN_IFACE})
 │    IP     : ${WAN_IP}
 │    MAC    : ${WAN_MAC}
 │    State  : ${WAN_STATE}
 │
 │  LAN  (${LAN_IFACE})
 │    IP     : ${LAN_IP}
 │    MAC    : ${LAN_MAC}
 │    State  : ${LAN_STATE}
 │
 │  VPN  (wg0)
 │    IP     : ${WG_IP}
 │    Peers  : $(wg_peers)
 │
 │  DHCP Leases : $(lease_count)
 │  Blocked IPs : $(cs_blocked)
 │  Memory      : $(mem_info)
 │  Load        : $(load_info)
 │  Uptime      : ${UPTIME}
 │
${SETUP_MSG} └──────────────────────────────────────────────────────────┘

EOF
)

# Write to /etc/issue for pre-login display
echo "$BANNER" > "$ISSUE_FILE"

# If called from MOTD (stdout is a terminal or pipe), also print it
if [[ "${1:-}" == "--motd" ]]; then
    echo "$BANNER"
fi
