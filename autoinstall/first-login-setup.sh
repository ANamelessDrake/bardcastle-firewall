#!/usr/bin/env bash
# Bardcastle Firewall - First boot setup
# Runs on each boot via systemd until all steps complete successfully.
# Configures WAN/LAN interfaces, firewall, installs remaining packages,
# and generates the status banner.

set -uo pipefail

MARKER="/etc/bardcastle/.first-boot-done"
NET_MARKER="/etc/bardcastle/.network-done"
PKG_MARKER="/etc/bardcastle/.packages-done"
WEBUI_MARKER="/etc/bardcastle/.webui-done"

mkdir -p /etc/bardcastle

# If everything is done, nothing to do
if [[ -f "$MARKER" ]]; then
    exit 0
fi

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║     BARDCASTLE FIREWALL - Boot Configuration            ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# --- Phase 1: Network (runs once, idempotent) ---
if [[ ! -f "$NET_MARKER" ]]; then
    echo "--- Phase 1: Detecting interfaces and configuring networking ---"
    if /usr/local/bin/bardcastle-net-setup; then
        echo "[OK] Network and firewall configured."
        touch "$NET_MARKER"
    else
        echo "[WARN] Network setup failed. Will retry on next boot."
        echo "  To run manually: sudo bardcastle-net-setup"
    fi

    sysctl --system > /dev/null 2>&1 || true
    systemctl restart systemd-networkd || true
    nft -f /etc/nftables.conf 2>/dev/null || true
    systemctl enable nftables 2>/dev/null || true
else
    echo "[OK] Network already configured."
fi

# --- Phase 2: Install packages (needs network, retries until success) ---
if [[ ! -f "$PKG_MARKER" ]]; then
    echo ""
    echo "--- Phase 2: Installing packages ---"

    # Wait for WAN to get a DHCP lease (up to 30 seconds)
    echo "Waiting for WAN DHCP lease..."
    GOT_IP=false
    for i in $(seq 1 30); do
        if ip -4 addr show | grep -q "dynamic"; then
            echo "[OK] WAN has an IP address."
            GOT_IP=true
            break
        fi
        sleep 1
    done

    if [[ "$GOT_IP" == "false" ]]; then
        echo "[WARN] No DHCP lease. Package install will retry on next boot."
        echo "  Connect WAN cable and reboot, or run manually:"
        echo "  sudo apt update && sudo apt install python3-pip python3-venv nftables net-tools curl dnsutils ethtool traceroute"
    else
        if apt-get update -qq && apt-get install -y -qq \
            python3 \
            python3-pip \
            python3-venv \
            nftables \
            net-tools \
            curl \
            iputils-ping \
            dnsutils \
            traceroute \
            ethtool; then
            echo "[OK] All packages installed."
            touch "$PKG_MARKER"

            # Install bardcastle-fw CLI
            if [[ -d /opt/bardcastle-firewall ]]; then
                pip3 install --break-system-packages -e /opt/bardcastle-firewall && \
                    echo "[OK] bardcastle-fw CLI installed." || \
                    echo "[WARN] bardcastle-fw CLI install failed."
            fi
        else
            echo "[WARN] Package install failed. Will retry on next boot."
        fi
    fi
else
    echo "[OK] Packages already installed."
fi

# --- Phase 3: Web dashboard (needs packages; idempotent, retries) ---
if [[ -f "$PKG_MARKER" && ! -f "$WEBUI_MARKER" ]]; then
    echo ""
    echo "--- Phase 3: Installing web dashboard ---"
    if [[ -f /opt/bardcastle-firewall/webui/install.sh ]]; then
        if bash /opt/bardcastle-firewall/webui/install.sh; then
            echo "[OK] Web dashboard installed (set a password with"
            echo "     'sudo bardcastle-fw webui set-password')."
            touch "$WEBUI_MARKER"
        else
            echo "[WARN] Web dashboard install failed. Will retry on next boot."
        fi
    fi
fi

# Generate the status banner
/usr/local/bin/bardcastle-banner 2>/dev/null || true

# If all phases are done, mark fully complete and disable service
if [[ -f "$NET_MARKER" && -f "$PKG_MARKER" && -f "$WEBUI_MARKER" ]]; then
    touch "$MARKER"
    systemctl disable bardcastle-first-login.service 2>/dev/null || true

    echo ""
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║  Setup complete. Run:                                   ║"
    echo "║                                                         ║"
    echo "║    sudo bardcastle-fw setup                             ║"
    echo "║                                                         ║"
    echo "║  This will configure DNS/DHCP, VPN, blocklists,        ║"
    echo "║  hardening, and monitoring.                             ║"
    echo "╚══════════════════════════════════════════════════════════╝"
else
    echo ""
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║  Some steps incomplete. Will retry on next boot.        ║"
    echo "║  Or run manually: sudo bardcastle-first-login           ║"
    echo "╚══════════════════════════════════════════════════════════╝"
fi
echo ""
