"""Monitoring and status module for bardcastle-firewall.

Sets up vnstat bandwidth monitoring and journald retention, and
provides a comprehensive system status dashboard.
"""

import json
import shutil
from pathlib import Path

from bardcastle.events import emit_event
from bardcastle.utils import (
    enable_and_start,
    mark_configured,
    require_root,
    run_cmd,
    save_config,
    write_config_file,
)

JOURNALD_CONF = "/etc/systemd/journald.conf.d/bardcastle.conf"
DNSMASQ_LEASES = "/var/lib/misc/dnsmasq.leases"


def setup(config: dict) -> dict:
    """Configure monitoring services.

    - Enable vnstat on WAN and LAN interfaces
    - Configure journald log retention
    - Restart journald

    Args:
        config: The current bardcastle config dict.
    """
    require_root()

    print("=" * 60)
    print("  Bardcastle Firewall - Monitoring Setup")
    print("=" * 60)

    network = config["network"]
    wan_interface = network["wan_interface"]
    lan_interface = network["lan_interface"]

    # Enable vnstat on both interfaces
    print("\n--- Configuring vnstat ---")
    for iface in (wan_interface, lan_interface):
        print(f"Adding vnstat interface: {iface}")
        run_cmd(["vnstat", "--add", "-i", iface], check=False)

    enable_and_start("vnstat")
    print("vnstat enabled and started.")

    # Configure journald: persistent storage with a size cap.
    # Persistent (on-disk /var/log/journal) so logs survive reboots - DHCP
    # fingerprints, DNS history, and IDS events accumulate over time instead of
    # being wiped every boot, which matters for after-the-fact investigation.
    # SystemMaxUse caps disk use so verbose logging (DNS/DHCP) cannot fill the
    # disk; raise it if you want a longer retention window.
    print("\n--- Configuring journald (persistent) ---")
    content = "[Journal]\nStorage=persistent\nSystemMaxUse=500M\n"
    write_config_file(JOURNALD_CONF, content, mode=0o644, backup=True)
    print(f"Wrote {JOURNALD_CONF}")

    # Ensure the persistent journal directory exists before the restart so
    # journald switches to it immediately (Storage=persistent creates it, but
    # this makes the first flush deterministic).
    run_cmd(["mkdir", "-p", "/var/log/journal"])
    run_cmd(["systemd-tmpfiles", "--create", "--prefix", "/var/log/journal"])

    print("Restarting systemd-journald...")
    run_cmd(["systemctl", "restart", "systemd-journald"])
    run_cmd(["journalctl", "--flush"])
    print("journald configured for persistent storage.")

    # Mark as configured and save
    mark_configured(config, "monitoring")
    save_config(config)

    emit_event("config_change", {
        "module": "monitoring",
        "action": "setup",
    })

    print("\n--- Monitoring setup complete ---\n")
    return config


def _section(title: str) -> None:
    """Print a section header."""
    print(f"\n{'=' * 50}")
    print(f"  {title}")
    print(f"{'=' * 50}")


def _show_interfaces() -> None:
    """Show interface IPs and link status."""
    _section("Network Interfaces")
    result = run_cmd(["ip", "-j", "addr", "show"], check=False)
    if result.returncode != 0:
        print("  Could not query interfaces.")
        return

    try:
        ifaces = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        print("  Could not parse interface data.")
        return

    for iface in ifaces:
        name = iface.get("ifname", "?")
        state = iface.get("operstate", "unknown")
        addrs = []
        for addr_info in iface.get("addr_info", []):
            local = addr_info.get("local", "")
            prefix = addr_info.get("prefixlen", "")
            if local:
                addrs.append(f"{local}/{prefix}")
        addr_str = ", ".join(addrs) if addrs else "no address"
        print(f"  {name:<16} {state:<10} {addr_str}")


def _show_dhcp_leases() -> None:
    """Show DHCP lease count."""
    _section("DHCP Leases")
    leases_path = Path(DNSMASQ_LEASES)
    if not leases_path.exists():
        print("  Lease file not found (dnsmasq not configured).")
        return

    lines = [l for l in leases_path.read_text().splitlines() if l.strip()]
    print(f"  Active leases: {len(lines)}")


def _show_wireguard() -> None:
    """Show WireGuard peer status."""
    _section("WireGuard VPN")
    result = run_cmd(["wg", "show"], check=False)
    if result.returncode != 0:
        print("  WireGuard not running or not configured.")
        return

    output = result.stdout.strip()
    if not output:
        print("  No WireGuard interfaces active.")
    else:
        for line in output.splitlines():
            print(f"  {line}")


def _humanize_bytes(n: int) -> str:
    """Format a byte count as a compact human-readable string."""
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


def _nft_ruleset():
    """Return the parsed nftables ruleset, or None if unavailable."""
    result = run_cmd(["nft", "-j", "list", "ruleset"], check=False)
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout or "{}").get("nftables", [])
    except json.JSONDecodeError:
        return None


def _blocklist_sizes() -> tuple:
    """Return (ipv4_count, ipv6_count) currently loaded in the blocklist sets."""
    v4 = v6 = 0
    for item in _nft_ruleset() or []:
        if "set" in item:
            s = item["set"]
            if s.get("name") == "blocklist_v4":
                v4 = len(s.get("elem", []))
            elif s.get("name") == "blocklist_v6":
                v6 = len(s.get("elem", []))
    return v4, v6


def _svc(unit: str) -> tuple:
    """Return (active_state, enabled_state) for a systemd unit."""
    active = run_cmd(["systemctl", "is-active", unit], check=False).stdout.strip()
    enabled = run_cmd(["systemctl", "is-enabled", unit], check=False).stdout.strip()
    return active or "unknown", enabled or "unknown"


def _svc_line(label: str, unit: str) -> None:
    """Print a service's active/enabled state in a consistent format."""
    active, enabled = _svc(unit)
    print(f"  {label:<20} {active} ({enabled} at boot)")


def _firewall_counters() -> None:
    """Print blocklist size and drop counters (no section header)."""
    ruleset = _nft_ruleset()
    if ruleset is None:
        print("  nftables not running or not configured.")
        return

    # Blocklist set sizes (our threat-intel sets in the inet filter table).
    set_sizes: dict[str, int] = {}
    drops: list[tuple[str, int, int]] = []  # (label, packets, bytes)

    for item in ruleset:
        if "set" in item:
            s = item["set"]
            if s.get("table") == "filter" and "blocklist" in s.get("name", ""):
                set_sizes[s["name"]] = len(s.get("elem", []))
        elif "rule" in item:
            rule = item["rule"]
            # Only our own labelled counters in the inet filter table.
            if rule.get("family") != "inet" or rule.get("table") != "filter":
                continue
            comment = rule.get("comment")
            if not comment:
                continue
            for expr in rule.get("expr", []):
                if "counter" in expr:
                    c = expr["counter"]
                    drops.append((comment, c.get("packets", 0), c.get("bytes", 0)))
                    break

    v4 = set_sizes.get("blocklist_v4", 0)
    v6 = set_sizes.get("blocklist_v6", 0)
    print(f"  Blocklist entries : {v4:,} IPv4, {v6:,} IPv6")
    print()

    if not drops:
        print("  Firewall loaded (no counter data to display).")
        return

    print("  Dropped traffic (since last apply/reboot):")
    label_w = max(len(label) for label, _, _ in drops)
    total_pkts = total_bytes = 0
    for label, pkts, byts in drops:
        total_pkts += pkts
        total_bytes += byts
        print(f"    {label:<{label_w}}  {pkts:>10,} pkts  {_humanize_bytes(byts):>10}")
    print(f"    {'':<{label_w}}  {'-' * 10}")
    print(f"    {'Total':<{label_w}}  {total_pkts:>10,} pkts  {_humanize_bytes(total_bytes):>10}")


def _show_firewall() -> None:
    """Show a readable summary of firewall drop counters and blocklist size."""
    _section("Firewall (nftables)")
    _firewall_counters()


def _show_crowdsec() -> None:
    """Show CrowdSec blocked IPs count."""
    _section("CrowdSec")
    if not shutil.which("cscli"):
        print("  CrowdSec not installed.")
        return
    result = run_cmd(["cscli", "decisions", "list", "-o", "json"], check=False)
    if result.returncode != 0:
        print("  CrowdSec not installed or not running.")
        return

    try:
        decisions = json.loads(result.stdout or "null")
        if decisions is None:
            count = 0
        elif isinstance(decisions, list):
            count = len(decisions)
        else:
            count = 0
        print(f"  Blocked IPs: {count}")
    except (json.JSONDecodeError, TypeError):
        print("  Could not parse CrowdSec output.")


def _show_resources() -> None:
    """Show RAM and CPU usage."""
    _section("System Resources")

    # RAM from /proc/meminfo
    meminfo_path = Path("/proc/meminfo")
    if meminfo_path.exists():
        meminfo = {}
        for line in meminfo_path.read_text().splitlines():
            parts = line.split(":")
            if len(parts) == 2:
                key = parts[0].strip()
                val = parts[1].strip().split()[0]  # value in kB
                try:
                    meminfo[key] = int(val)
                except ValueError:
                    pass

        total = meminfo.get("MemTotal", 0)
        available = meminfo.get("MemAvailable", 0)
        used = total - available
        if total > 0:
            pct = (used / total) * 100
            print(
                f"  RAM: {used // 1024} MB used / {total // 1024} MB total "
                f"({pct:.1f}%)"
            )
        else:
            print("  RAM: could not determine.")
    else:
        print("  RAM: /proc/meminfo not available.")

    # CPU load from /proc/loadavg
    loadavg_path = Path("/proc/loadavg")
    if loadavg_path.exists():
        parts = loadavg_path.read_text().strip().split()
        if len(parts) >= 3:
            print(f"  Load average: {parts[0]} {parts[1]} {parts[2]}  (1/5/15 min)")
        else:
            print("  Load average: could not parse.")
    else:
        print("  Load average: /proc/loadavg not available.")


def _show_bandwidth(config: dict) -> None:
    """Show WAN bandwidth via vnstat."""
    _section("WAN Bandwidth")
    wan_iface = config.get("network", {}).get("wan_interface")
    if not wan_iface:
        print("  WAN interface not configured.")
        return

    result = run_cmd(["vnstat", "-i", wan_iface, "--oneline"], check=False)
    if result.returncode != 0:
        print("  vnstat not running or no data available.")
        return

    output = result.stdout.strip()
    if not output:
        print("  No bandwidth data available yet.")
        return

    # vnstat --oneline fields (semicolon-separated):
    # 0:version 1:name 2:days_since 3:today_rx 4:today_tx 5:today_total
    # 6:today_avg 7:month_rx 8:month_tx 9:month_total 10:month_avg
    # 11:alltime_rx 12:alltime_tx 13:alltime_total
    fields = output.split(";")
    if len(fields) >= 6:
        print(f"  Today RX: {fields[3]}")
        print(f"  Today TX: {fields[4]}")
        print(f"  Today total: {fields[5]}")
    if len(fields) >= 10:
        print(f"  Month RX: {fields[7]}")
        print(f"  Month TX: {fields[8]}")
        print(f"  Month total: {fields[9]}")


def network_status(config: dict) -> None:
    """Show networking service state and interface assignment."""
    _section("Network")
    _svc_line("systemd-networkd", "systemd-networkd")

    net = config.get("network", {})
    wan = net.get("wan_interface")
    lan = net.get("lan_interface")

    addrs = {}
    result = run_cmd(["ip", "-j", "addr", "show"], check=False)
    if result.returncode == 0:
        try:
            for iface in json.loads(result.stdout):
                ips = [f"{a['local']}/{a['prefixlen']}"
                       for a in iface.get("addr_info", [])
                       if a.get("family") == "inet"]
                addrs[iface.get("ifname")] = (iface.get("operstate", "?"), ips)
        except (json.JSONDecodeError, TypeError):
            pass

    for role, iface in (("WAN", wan), ("LAN", lan)):
        if not iface:
            print(f"  {role}: not configured")
            continue
        state, ips = addrs.get(iface, ("absent", []))
        print(f"  {role} ({iface}): {state}, {', '.join(ips) or 'no address'}")

    fwd = Path("/proc/sys/net/ipv4/ip_forward")
    if fwd.exists():
        on = fwd.read_text().strip() == "1"
        print(f"  IP forwarding: {'enabled' if on else 'DISABLED'}")


def firewall_status(config: dict) -> None:
    """Show firewall service state plus the drop/blocklist summary."""
    _section("Firewall")
    _svc_line("nftables", "nftables")
    loaded = bool(_nft_ruleset())
    print(f"  Ruleset: {'loaded' if loaded else 'NOT loaded'}")
    print()
    _firewall_counters()


def dns_status(config: dict) -> None:
    """Show DNS/DHCP service state, upstreams, leases, and logging."""
    _section("DNS / DHCP (dnsmasq)")
    _svc_line("dnsmasq", "dnsmasq")

    dns = config.get("dns", {})
    upstreams = dns.get("upstream_servers", [])
    if upstreams:
        print(f"  Upstream DNS: {', '.join(upstreams)}")
    print(f"  Local domain: {dns.get('domain', '(unset)')}")

    leases_path = Path(DNSMASQ_LEASES)
    if leases_path.exists():
        count = len([l for l in leases_path.read_text().splitlines() if l.strip()])
        print(f"  Active DHCP leases: {count}")

    conf = Path("/etc/dnsmasq.conf")
    logging_on = conf.exists() and any(
        line.strip() == "log-queries" for line in conf.read_text().splitlines()
    )
    print(f"  DNS query logging: {'enabled' if logging_on else 'disabled'}")


def vpn_status(config: dict) -> None:
    """Show WireGuard service state, port, and peers."""
    _section("VPN (WireGuard)")
    _svc_line("wg-quick@wg0", "wg-quick@wg0")

    vpn = config.get("vpn", {})
    if vpn.get("port"):
        print(f"  Listen port: {vpn['port']}/udp")
    clients = vpn.get("clients", [])
    print(f"  Configured clients: {len(clients)}")

    result = run_cmd(["wg", "show"], check=False)
    if result.returncode == 0 and result.stdout.strip():
        peers = result.stdout.count("peer:")
        print(f"  Active peers: {peers}")
    else:
        print("  Tunnel not active.")


def blocklist_status(config: dict) -> None:
    """Show blocklist set sizes, last refresh, cron, and CrowdSec decisions."""
    _section("Blocklists")
    v4, v6 = _blocklist_sizes()
    print(f"  Loaded entries: {v4:,} IPv4, {v6:,} IPv6")

    cron = Path("/etc/cron.d/bardcastle-blocklists")
    print(f"  Nightly refresh cron: {'installed' if cron.exists() else 'not installed'}")

    # Last refresh time from the event log.
    events_log = Path("/var/log/bardcastle/events.jsonl")
    last = None
    if events_log.exists():
        for line in events_log.read_text().splitlines():
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("type") == "blocklist_update":
                last = ev.get("timestamp")
    print(f"  Last update: {last or 'never'}")

    _show_crowdsec()


def ids_status(config: dict) -> None:
    """Show IDS/IPS state: Suricata and CrowdSec."""
    _section("IDS / IPS")

    if shutil.which("suricata"):
        _svc_line("Suricata", "suricata")
    else:
        print("  Suricata: not installed")

    if shutil.which("cscli"):
        _svc_line("CrowdSec", "crowdsec")
        _svc_line("CrowdSec bouncer", "crowdsec-firewall-bouncer")
        result = run_cmd(["cscli", "decisions", "list", "-o", "json"], check=False)
        if result.returncode == 0:
            try:
                decisions = json.loads(result.stdout or "null")
                count = len(decisions) if isinstance(decisions, list) else 0
                print(f"  Active CrowdSec bans: {count}")
            except (json.JSONDecodeError, TypeError):
                pass
        cols = run_cmd(["cscli", "collections", "list", "-o", "raw"], check=False)
        if cols.returncode == 0:
            names = [line.split(",")[0] for line in cols.stdout.splitlines()[1:]
                     if line.strip()]
            if names:
                print(f"  Collections: {', '.join(names)}")
    else:
        print("  CrowdSec: not installed")


def show_status(config: dict) -> None:
    """Display a comprehensive system status dashboard.

    All sections are non-fatal: if a service is not running or
    not installed, a friendly message is shown instead of an error.

    Args:
        config: The current bardcastle config dict.
    """
    print("=" * 50)
    print("  Bardcastle Firewall - System Status")
    print("=" * 50)

    _show_interfaces()
    _show_dhcp_leases()
    _show_wireguard()
    _show_firewall()
    _show_crowdsec()
    _show_resources()
    _show_bandwidth(config)

    print()
