#!/usr/bin/env bash
# Install and enable the bardcastle web dashboard as a hardened service.
#
# Idempotent and safe to re-run. Called at first boot and runnable by hand.
# Sets up a dedicated unprivileged service user, a Python venv, a self-signed
# TLS cert, a session secret, a narrow sudoers allowlist, and the systemd
# units. After this, set a login password with:
#   sudo bardcastle-fw webui set-password

set -euo pipefail

REPO=/opt/bardcastle-firewall
VENV=/opt/bardcastle-webui/venv
WEBDIR=/etc/bardcastle-web
SVCUSER=bardcastle-web

if [[ $EUID -ne 0 ]]; then
    echo "Error: run as root (sudo)." >&2
    exit 1
fi

echo "[1/7] Service user..."
id "$SVCUSER" &>/dev/null || useradd --system --no-create-home \
    --shell /usr/sbin/nologin "$SVCUSER"
# Read the system journal (for the DNS-query panel in a later phase).
getent group systemd-journal >/dev/null 2>&1 && usermod -aG systemd-journal "$SVCUSER" || true

echo "[2/7] Secrets directory..."
install -d -o "$SVCUSER" -g "$SVCUSER" -m 700 "$WEBDIR"

echo "[3/7] Python venv + dependencies..."
[ -d "$VENV" ] || python3 -m venv "$VENV"
"$VENV/bin/pip" install -q --upgrade pip >/dev/null 2>&1 || true
"$VENV/bin/pip" install -q -r "$REPO/webui/backend/requirements.txt"

echo "[4/7] TLS certificate..."
if [ ! -f "$WEBDIR/tls-cert.pem" ]; then
    lan_ip=$(grep -oP '^\s*lan_ip:\s*\K[0-9.]+' /etc/bardcastle/config.yaml 2>/dev/null || echo 10.0.1.1)
    hn=$(hostname)
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout "$WEBDIR/tls-key.pem" -out "$WEBDIR/tls-cert.pem" \
        -subj "/CN=${hn}" \
        -addext "subjectAltName=IP:${lan_ip},IP:10.10.10.1,DNS:${hn},DNS:${hn}.example.com" \
        >/dev/null 2>&1
    chown "$SVCUSER":"$SVCUSER" "$WEBDIR/tls-key.pem" "$WEBDIR/tls-cert.pem"
    chmod 600 "$WEBDIR/tls-key.pem"
    chmod 644 "$WEBDIR/tls-cert.pem"
fi

echo "[5/7] Session secret..."
if [ ! -f "$WEBDIR/secret.key" ]; then
    openssl rand -hex 32 > "$WEBDIR/secret.key"
    chown "$SVCUSER":"$SVCUSER" "$WEBDIR/secret.key"
    chmod 600 "$WEBDIR/secret.key"
fi

echo "[6/7] Sudoers allowlist..."
install -m 440 -o root -g root "$REPO/webui/sudoers/bardcastle-web" \
    /etc/sudoers.d/bardcastle-web
visudo -c -f /etc/sudoers.d/bardcastle-web >/dev/null

echo "[7/7] systemd units..."
install -m 644 "$REPO/webui/systemd/bardcastle-webui.service" /etc/systemd/system/
install -m 644 "$REPO/webui/systemd/bardcastle-webui-redirect.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now bardcastle-webui.service bardcastle-webui-redirect.service

echo ""
echo "Dashboard installed and running."
if [ ! -f "$WEBDIR/auth.json" ]; then
    echo "No login password is set yet. Set one with:"
    echo "  sudo bardcastle-fw webui set-password"
fi
