"""DNS and DHCP module using dnsmasq for bardcastle-firewall."""

import re
import sys
from pathlib import Path

from bardcastle.events import emit_event
from bardcastle.utils import (
    enable_and_start,
    mark_configured,
    render_template,
    require_root,
    run_cmd,
    save_config,
    write_config_file,
)

DNSMASQ_CONF = "/etc/dnsmasq.conf"
DHCP_HOOK_PATH = "/usr/local/bin/bardcastle-dhcp-hook"
LEASES_FILE = "/var/lib/misc/dnsmasq.leases"

DHCP_HOOK_SCRIPT = """\
#!/usr/bin/env bash
# bardcastle DHCP event hook for dnsmasq
# Called by dnsmasq with: <action> <mac> <ip> <hostname> [<client-id>]

ACTION="$1"
MAC="$2"
IP="$3"
HOSTNAME="$4"

LOG_DIR="/var/log/bardcastle"
LOG_FILE="${LOG_DIR}/events.jsonl"

mkdir -p "$LOG_DIR"

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S+00:00")

printf '{"timestamp":"%s","type":"dhcp_lease","data":{"action":"%s","mac":"%s","ip":"%s","hostname":"%s"}}\\n' \\
    "$TIMESTAMP" "$ACTION" "$MAC" "$IP" "$HOSTNAME" >> "$LOG_FILE"
"""


def setup(config: dict) -> dict:
    """Set up dnsmasq for DNS and DHCP from config.

    Reads LAN settings from config, prompts for upstream DNS servers,
    renders the dnsmasq.conf.j2 template, installs a DHCP event hook,
    and enables the service.
    """
    require_root()

    network = config["network"]
    lan_interface = network["lan_interface"]
    lan_ip = network["lan_ip"]
    dhcp_start = network["dhcp_start"]
    dhcp_end = network["dhcp_end"]
    domain = network.get("domain", "bardcastle.lan")
    # Name the router answers to on the LAN, so you can reach it by name
    # (dashboard, SSH) instead of by IP. Resolves to the LAN IP via dnsmasq.
    router_name = network.get("router_name", "bardcastle-gates")

    print(f"LAN interface : {lan_interface}")
    print(f"LAN IP        : {lan_ip}")
    print(f"DHCP range    : {dhcp_start} - {dhcp_end}")
    print(f"Domain        : {domain}")
    print(f"Router name   : {router_name}")

    # Prompt for upstream DNS servers
    import click
    upstream_dns = click.prompt(
        "Upstream DNS servers (comma-separated)",
        default="1.1.1.1,9.9.9.9",
    )
    dns_servers = [s.strip() for s in upstream_dns.split(",") if s.strip()]

    # Render dnsmasq configuration from template
    content = render_template("dnsmasq.conf.j2", {
        "lan_interface": lan_interface,
        "lan_ip": lan_ip,
        "dhcp_start": dhcp_start,
        "dhcp_end": dhcp_end,
        "domain": domain,
        "router_name": router_name,
        "dns_servers": dns_servers,
        "dhcp_hook_path": DHCP_HOOK_PATH,
    })

    # Write dnsmasq config with backup
    write_config_file(DNSMASQ_CONF, content, mode=0o644, backup=True)
    print(f"Wrote {DNSMASQ_CONF}")

    # Install the DHCP event hook script
    write_config_file(DHCP_HOOK_PATH, DHCP_HOOK_SCRIPT, mode=0o755, backup=False)
    print(f"Installed DHCP hook at {DHCP_HOOK_PATH}")

    # Ensure the log directory exists
    Path("/var/log/bardcastle").mkdir(parents=True, exist_ok=True)

    # Enable and start dnsmasq
    print("Enabling dnsmasq service...")
    enable_and_start("dnsmasq")

    # Test DNS resolution (non-fatal)
    print("Testing DNS resolution...")
    try:
        result = run_cmd(
            ["dig", "@127.0.0.1", "google.com", "+short"],
            check=True, capture=True,
        )
        if result.stdout.strip():
            print(f"DNS test OK: google.com -> {result.stdout.strip().splitlines()[0]}")
        else:
            print("DNS test returned no results (service may still be starting).")
    except Exception:
        print(
            "WARNING: DNS test failed. dnsmasq may still be starting.",
            file=sys.stderr,
        )

    # Save DNS settings into config
    config.setdefault("dns", {})
    config["dns"]["upstream_servers"] = dns_servers
    config["dns"]["domain"] = domain

    # Mark as configured and save
    mark_configured(config, "dns")
    save_config(config)

    emit_event("config_change", {
        "module": "dns_dhcp",
        "action": "setup",
        "lan_interface": lan_interface,
        "domain": domain,
        "upstream_dns": dns_servers,
    })

    print("DNS and DHCP configured successfully.")
    return config


VPN_HOSTS_FILE = "/var/lib/bardcastle/vpn-hosts"


def _lease_hostmap() -> dict:
    """Map IP -> friendly name for query output.

    Combines DHCP leases (LAN devices) with the VPN client mapping, so both
    LAN devices and VPN users show by name in the query log.
    """
    hostmap = {}
    path = Path(LEASES_FILE)
    if path.exists():
        for line in path.read_text().splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[3] != "*":
                hostmap[parts[2]] = parts[3]

    # VPN clients: "<ip> <name>.vpn.<domain>"; show "<name>.vpn" so VPN users
    # are visually distinct from LAN devices.
    vpn_path = Path(VPN_HOSTS_FILE)
    if vpn_path.exists():
        for line in vpn_path.read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                hostmap[parts[0]] = ".".join(parts[1].split(".")[:2])
    return hostmap


# Matches: "query[A] www.example.com from 10.0.1.129"
_QUERY_RE = re.compile(r"query\[(\w+)\]\s+(\S+)\s+from\s+(\S+)")


def show_queries(client=None, domain=None, limit=50,
                 follow=False, top=False) -> None:
    """Browse dnsmasq's DNS query log from the journal.

    Requires DNS query logging (log-queries) to be enabled.
    """
    import subprocess

    hostmap = _lease_hostmap()
    # Allow --client to be given as a name as well as an IP. Resolve
    # deterministically: an exact name wins, then the bare label (so
    # "-c emccabe.vpn" targets the VPN user, "-c emccabe" targets a LAN device
    # named emccabe if one exists, else falls back to the VPN user).
    client_ip = client
    if client and not client.replace(".", "").isdigit():
        want = client.lower()
        exact = next((ip for ip, n in hostmap.items() if n.lower() == want), None)
        if exact is None:
            exact = next(
                (ip for ip, n in hostmap.items() if n.lower().split(".")[0] == want),
                None,
            )
        if exact is not None:
            client_ip = exact

    def match(name, src):
        if client_ip and src != client_ip:
            return False
        if domain and domain.lower() not in name.lower():
            return False
        return True

    def who(src):
        host = hostmap.get(src)
        return f"{host} ({src})" if host else src

    if top:
        cmd = ["journalctl", "-u", "dnsmasq", "--no-pager", "-o", "cat"]
        result = run_cmd(cmd, check=False)
        domains: dict = {}
        clients: dict = {}
        for line in result.stdout.splitlines():
            m = _QUERY_RE.search(line)
            if not m:
                continue
            qtype, name, src = m.groups()
            if not match(name, src):
                continue
            domains[name] = domains.get(name, 0) + 1
            clients[src] = clients.get(src, 0) + 1
        print("\n  Top domains:")
        for name, count in sorted(domains.items(), key=lambda x: -x[1])[:15]:
            print(f"    {count:>6,}  {name}")
        print("\n  Top clients:")
        for src, count in sorted(clients.items(), key=lambda x: -x[1])[:15]:
            print(f"    {count:>6,}  {who(src)}")
        print()
        return

    if follow:
        print("Streaming DNS queries (Ctrl-C to stop)...\n")
        proc = subprocess.Popen(
            ["journalctl", "-u", "dnsmasq", "-f", "-o", "cat", "-n", "0"],
            stdout=subprocess.PIPE, text=True,
        )
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                m = _QUERY_RE.search(line)
                if not m:
                    continue
                qtype, name, src = m.groups()
                if match(name, src):
                    print(f"  {who(src):<28} {qtype:<5} {name}")
        except KeyboardInterrupt:
            proc.terminate()
            print()
        return

    # Recent history: pull the log, filter, show the last `limit` matches.
    result = run_cmd(
        ["journalctl", "-u", "dnsmasq", "--no-pager", "-o", "short-iso"],
        check=False,
    )
    rows = []
    for line in result.stdout.splitlines():
        m = _QUERY_RE.search(line)
        if not m:
            continue
        qtype, name, src = m.groups()
        if not match(name, src):
            continue
        ts = line.split(None, 1)[0][:19].replace("T", " ")
        rows.append((ts, who(src), qtype, name))

    if not rows:
        print("  No matching DNS queries found.")
        print("  (Ensure 'log-queries' is enabled in dnsmasq.)")
        return

    print(f"\n  {'Time':<19} {'Client':<28} {'Type':<5} Domain")
    print("  " + "-" * 78)
    for ts, src, qtype, name in rows[-limit:]:
        print(f"  {ts:<19} {src:<28} {qtype:<5} {name}")
    print()


def show_leases() -> None:
    """Display dnsmasq DHCP leases with liveness and readable expiry."""
    import subprocess
    from datetime import datetime

    leases_path = Path(LEASES_FILE)
    if not leases_path.exists():
        print("No leases file found at", LEASES_FILE)
        return

    content = leases_path.read_text().strip()
    if not content:
        print("No active DHCP leases.")
        return

    leases = []
    for line in content.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            leases.append({
                "expires": parts[0],
                "mac": parts[1],
                "ip": parts[2],
                "hostname": parts[3],
            })

    # Probe every leased IP concurrently so the neighbor table reflects
    # who is actually on the wire right now (a lease alone only proves
    # the device was here when it was granted).
    probes = [
        subprocess.Popen(
            ["ping", "-c", "1", "-W", "1", lease["ip"]],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        for lease in leases
    ]
    for probe in probes:
        probe.wait()

    neigh_states: dict[str, str] = {}
    result = run_cmd(["ip", "-4", "neigh", "show"], check=False)
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            neigh_states[parts[0]] = parts[-1]

    online_states = {"REACHABLE", "DELAY", "PROBE"}
    now = datetime.now()

    # Colorize only on a real terminal, and degrade gracefully without jblib.
    bold = green = red = dim = off = ""
    if sys.stdout.isatty():
        try:
            from jblib import Color
            bold, green, red, dim, off = (
                Color.BOLD, Color.GREEN, Color.RED, Color.DIM, Color.OFF,  # pyright: ignore[reportAttributeAccessIssue]
            )
        except ImportError:
            pass

    header = f"{'Online':<8} {'Expires':<24} {'MAC':<20} {'IP':<16} {'Hostname'}"
    print(f"\n{bold}{header}{off}")
    print("-" * 92)
    for lease in leases:
        is_online = neigh_states.get(lease["ip"]) in online_states
        online_color = green if is_online else red
        online = f"{online_color}{'yes' if is_online else 'no':<8}{off} "
        expired = False
        try:
            expires_dt = datetime.fromtimestamp(int(lease["expires"]))
            expires = expires_dt.strftime("%Y-%m-%d %H:%M")
            if expires_dt < now:
                expires += " (expired)"
                expired = True
        except ValueError:
            expires = lease["expires"]
        row = f"{expires:<24} {lease['mac']:<20} {lease['ip']:<16} "
        hostname = f"{online_color}{lease['hostname']}{off}"
        print(online + (f"{dim}{row}{off}" if expired else row) + hostname)
    print()
