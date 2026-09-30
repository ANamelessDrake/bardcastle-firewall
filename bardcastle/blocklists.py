"""Blocklist management module for bardcastle-firewall.

Manages CrowdSec hub collections, FireHOL blocklists loaded into
nftables sets, Suricata IDS configuration, and cron-based updates.
"""

import ipaddress
import json
import shutil

import click

from bardcastle import events
from bardcastle.utils import (
    disable_and_stop,
    enable_and_start,
    mark_configured,
    run_cmd,
    run_shell,
    save_config,
    write_config_file,
)

FIREHOL_URL = "https://iplists.firehol.org/files/firehol_level1.netset"
BLOCKLIST_NETSET = "/tmp/firehol_level1.netset"
CRON_FILE = "/etc/cron.d/bardcastle-blocklists"

# FireHOL level1 is IPv4-only (its header literally declares "ipv4 hash:net
# ipset"), and FireHOL publishes no IPv6 equivalent. The IPv6 set is fed from
# the Spamhaus IPv6 DROP list instead, which is the closest maintained analogue:
# hijacked and criminal-controlled netblocks, safe to drop wholesale.
SPAMHAUS_V6_URL = "https://www.spamhaus.org/drop/dropv6.txt"
BLOCKLIST_NETSET_V6 = "/tmp/spamhaus_dropv6.txt"

# FireHOL level1 targets internet edges and includes all private/reserved
# space. Loading those into the blocklist drops the router's own LAN (and,
# behind another NAT, its WAN) — a total self-inflicted outage. Never load
# anything overlapping these.
EXCLUDED_RANGES = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8",        # "this network"
    "10.0.0.0/8",       # RFC1918
    "100.64.0.0/10",    # CGNAT
    "127.0.0.0/8",      # loopback
    "169.254.0.0/16",   # link-local
    "172.16.0.0/12",    # RFC1918
    "192.168.0.0/16",   # RFC1918
    "198.18.0.0/15",    # benchmarking
    "224.0.0.0/4",      # multicast
    "240.0.0.0/4",      # reserved
)]

# The IPv6 equivalents. fc00::/7 matters most here: the WireGuard tunnel's ULA
# prefix lives inside it, so without this exclusion a bad feed entry could
# blackhole every VPN client. Cross-family overlaps() returns False rather than
# raising, so an IPv4-only exclusion list would silently pass all of these
# through instead of failing loudly.
EXCLUDED_RANGES_V6 = [ipaddress.ip_network(n) for n in (
    "::/128",           # unspecified
    "::1/128",          # loopback
    "::ffff:0:0/96",    # IPv4-mapped
    "fc00::/7",         # ULA (includes the VPN tunnel prefix)
    "fe80::/10",        # link-local
    "ff00::/8",         # multicast
    "2001:db8::/32",    # documentation
)]

_EXCLUDED_BY_VERSION = {4: EXCLUDED_RANGES, 6: EXCLUDED_RANGES_V6}


def _filter_public(entries: list[str], version: int = 4) -> tuple[list[str], int]:
    """Drop entries that overlap private/reserved space for the given family.

    `version` is 4 or 6 and selects both the exclusion list and the family of
    entry accepted; an entry from the wrong family is skipped rather than
    loaded, since each nftables set is typed to one family and would reject it.

    Returns (kept_entries, skipped_count). Unparseable lines are skipped.
    """
    kept: list[str] = []
    skipped = 0
    excluded = _EXCLUDED_BY_VERSION[version]
    for entry in entries:
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            skipped += 1
            continue
        if net.version != version:
            skipped += 1
            continue
        if any(net.overlaps(excl) for excl in excluded):
            skipped += 1
            continue
        kept.append(entry)
    return kept, skipped


def _parse_netset(path: str) -> list[str]:
    """Read CIDR entries from a netset/DROP file.

    Handles both FireHOL ('#' comments, bare CIDRs) and Spamhaus DROP
    (';' comments, and a trailing '; SBL<id>' annotation after each CIDR).
    """
    entries: list[str] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line[0] in "#;":
                continue
            entry = line.split(";")[0].strip()
            if entry:
                entries.append(entry)
    return entries


def _load_ips_nftables(ips: list[str], set_name: str = "blocklist_v4") -> None:
    """Load a list of IPs/CIDRs into the named nftables set.

    `set_name` is blocklist_v4 or blocklist_v6, both declared in
    nftables.conf.j2. Tries python3-nftables bindings first, falls back to the
    nft CLI.
    """
    try:
        import nftables  # type: ignore[import-untyped]

        nft = nftables.Nftables()
        nft.set_json_output(True)

        # Flush the existing set
        nft.cmd(f"flush set inet filter {set_name}")

        # Add elements in batches to avoid command-line length limits
        batch_size = 500
        for i in range(0, len(ips), batch_size):
            batch = ips[i:i + batch_size]
            elements = ", ".join(batch)
            nft.cmd(f"add element inet filter {set_name} {{ {elements} }}")

        click.echo(f"Loaded {len(ips)} entries into {set_name} via python3-nftables bindings.")
    except (ImportError, Exception) as exc:
        click.echo(f"nftables bindings unavailable ({exc}), falling back to nft CLI.")

        # Flush the existing set
        run_cmd(["nft", "flush", "set", "inet", "filter", set_name])

        # Add elements in batches
        batch_size = 500
        for i in range(0, len(ips), batch_size):
            batch = ips[i:i + batch_size]
            elements = ", ".join(batch)
            run_cmd(["nft", "add", "element", "inet", "filter", set_name,
                      f"{{ {elements} }}"])

        click.echo(f"Loaded {len(ips)} entries into {set_name} via nft CLI.")


def _refresh_blocklist_set(source: str, url: str, path: str,
                           set_name: str, version: int) -> int | None:
    """Download one feed and load it into its nftables set.

    Returns the number of entries loaded, or None if the feed could not be
    used. On failure the existing set is deliberately left in place: stale
    blocklist entries are better than an empty set.
    """
    click.echo(f"Downloading {source}...")
    # -f so an HTTP error is a non-zero exit instead of an error page written
    # to the file, -L to follow redirects, and a short retry for transient DNS.
    result = run_cmd(["curl", "-fsS", "-L", "--retry", "2", "--max-time", "60",
                      "-o", path, url], check=False)
    if result.returncode != 0:
        click.echo(f"Warning: download failed for {source} "
                   f"(curl exit {result.returncode}); leaving {set_name} unchanged.")
        return None

    try:
        entries = _parse_netset(path)
    except OSError as exc:
        click.echo(f"Warning: could not read {path} for {source} ({exc}); "
                   f"leaving {set_name} unchanged.")
        return None

    if not entries:
        click.echo(f"Warning: no entries found in {source}; "
                   f"leaving {set_name} unchanged.")
        return None

    entries, skipped = _filter_public(entries, version=version)
    click.echo(
        f"Parsed {len(entries)} public entries from {source} "
        f"({skipped} private/reserved/wrong-family entries excluded)."
    )
    if not entries:
        click.echo(f"Warning: nothing left after filtering {source}; "
                   f"leaving {set_name} unchanged.")
        return None

    _load_ips_nftables(entries, set_name=set_name)
    return len(entries)


def update(config: dict) -> dict:
    """Update blocklists from CrowdSec, FireHOL (IPv4) and Spamhaus (IPv6).

    If CrowdSec is installed, updates the hub and installs the base Linux
    collection. Downloads the FireHOL level-1 netset into blocklist_v4 and the
    Spamhaus IPv6 DROP list into blocklist_v6. Each feed is refreshed
    independently so one failing source cannot take the other down.

    Args:
        config: The current bardcastle config dict.

    Returns:
        The updated config dict.
    """
    click.echo("\n--- Updating Blocklists ---")

    # CrowdSec update (if installed)
    if shutil.which("cscli"):
        click.echo("Updating CrowdSec hub...")
        run_cmd(["cscli", "hub", "update"])
        run_cmd(["cscli", "collections", "install", "crowdsecurity/linux"])
        click.echo("CrowdSec collections updated.")
    else:
        click.echo("CrowdSec not installed; skipping hub update.")

    # Refresh each family independently: a Spamhaus outage must not stop the
    # IPv4 refresh, and vice versa.
    loaded = 0
    for source, url, path, set_name, version in (
        ("firehol_level1", FIREHOL_URL, BLOCKLIST_NETSET, "blocklist_v4", 4),
        ("spamhaus_dropv6", SPAMHAUS_V6_URL, BLOCKLIST_NETSET_V6, "blocklist_v6", 6),
    ):
        count = _refresh_blocklist_set(source, url, path, set_name, version)
        if count is not None:
            loaded += 1
            events.emit_event("blocklist_update", {
                "source": source,
                "count": count,
            })

    if not loaded:
        click.echo("Warning: no blocklist could be refreshed; sets left unchanged.")
        return config

    mark_configured(config, "blocklists")
    save_config(config)
    click.echo("Blocklist update complete.\n")
    return config


def setup_cron() -> None:
    """Create a daily cron job to refresh blocklists.

    Writes to /etc/cron.d/bardcastle-blocklists.
    """
    click.echo("\n--- Setting up blocklist cron job ---")
    cron_content = (
        "# Bardcastle-firewall: daily blocklist refresh\n"
        "SHELL=/bin/bash\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
        "0 4 * * * root bardcastle-fw blocklist update > /dev/null 2>&1\n"
    )
    write_config_file(CRON_FILE, cron_content, mode=0o644, backup=False)
    click.echo(f"Cron job written to {CRON_FILE} (runs daily at 04:00).\n")


def show_stats() -> None:
    """Display blocklist and IDS statistics.

    Shows the number of entries in nftables blocklist sets and, if
    CrowdSec is installed, the current decisions count.
    """
    click.echo("\n--- Blocklist Statistics ---")

    # nftables set counts
    for set_name, pattern in (("blocklist_v4", "[0-9]"), ("blocklist_v6", "[0-9a-fA-F:]")):
        try:
            result = run_shell(
                f"nft list set inet filter {set_name} 2>/dev/null | "
                f"grep -c -E '^\\s+{pattern}'",
                check=False,
            )
            count = result.stdout.strip() if result.returncode == 0 else "0"
            click.echo(f"nftables {set_name} entries: {count}")
        except Exception:
            click.echo(f"Could not query nftables {set_name} set.")

    # CrowdSec decisions
    if shutil.which("cscli"):
        try:
            result = run_cmd(["cscli", "decisions", "list", "-o", "raw"],
                             check=False)
            if result.returncode == 0 and result.stdout:
                # Raw output is CSV-like; subtract header line
                lines = [l for l in result.stdout.strip().splitlines() if l]
                decision_count = max(len(lines) - 1, 0)
                click.echo(f"CrowdSec active decisions: {decision_count}")
            else:
                click.echo("CrowdSec active decisions: 0")
        except Exception:
            click.echo("Could not query CrowdSec decisions.")
    else:
        click.echo("CrowdSec not installed.")

    click.echo()


def enable_ids(config: dict) -> dict:
    """Enable Suricata in inline IPS mode.

    Checks that Suricata is installed, configures it for the WAN
    interface, downloads ET Open rules, and starts the service.

    Args:
        config: The current bardcastle config dict.

    Returns:
        The updated config dict.
    """
    click.echo("\n--- Enabling Suricata IDS/IPS ---")

    if not shutil.which("suricata"):
        click.echo("Error: Suricata is not installed. Run bootstrap first.", err=True)
        return config

    wan_iface = config.get("network", {}).get("wan_interface", "eth0")
    click.echo(f"Configuring Suricata for inline IPS on {wan_iface}...")

    # Set the interface in suricata.yaml
    run_shell(
        f"sed -i 's/^\\(\\s*- interface:\\s*\\).*/\\1{wan_iface}/' "
        f"/etc/suricata/suricata.yaml"
    )

    # Enable inline (IPS) mode via af-packet
    run_shell(
        "sed -i 's/^\\(\\s*\\)# *\\(- interface: default\\)/\\1\\2/' "
        "/etc/suricata/suricata.yaml"
    )

    # Update rules via suricata-update
    click.echo("Downloading ET Open rules...")
    run_cmd(["suricata-update"])

    # Enable and start
    enable_and_start("suricata")
    click.echo("Suricata IDS/IPS enabled and running.")

    config.setdefault("services", {})["suricata"] = True
    save_config(config)

    events.emit_event("config_change", {
        "module": "blocklists",
        "action": "enable_ids",
        "wan_interface": wan_iface,
    })

    click.echo("IDS/IPS setup complete.\n")
    return config


def disable_ids(config: dict) -> dict:
    """Disable Suricata IDS/IPS.

    Stops and disables the suricata service.

    Args:
        config: The current bardcastle config dict.

    Returns:
        The updated config dict.
    """
    click.echo("\n--- Disabling Suricata IDS/IPS ---")

    disable_and_stop("suricata")
    config.setdefault("services", {})["suricata"] = False
    save_config(config)

    click.echo("Suricata IDS/IPS disabled.\n")
    return config


# ---------------------------------------------------------------------------
# CrowdSec IDS data views (wrappers around cscli with readable tables)
# ---------------------------------------------------------------------------

def _cscli_json(args: list):
    """Run a cscli command with JSON output; return parsed data or None."""
    if not shutil.which("cscli"):
        return None
    result = run_cmd(["cscli"] + args, check=False)
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout or "null")
    except json.JSONDecodeError:
        return None


def _table(headers: tuple, rows: list) -> None:
    """Print a simple aligned text table."""
    if not rows:
        print("  (none)")
        return
    widths = [max(len(str(r[i])) for r in [headers] + rows)
              for i in range(len(headers))]

    def fmt(cols):
        return "  " + "  ".join(
            str(c).ljust(widths[i]) for i, c in enumerate(cols)
        )

    print()
    print(fmt(headers))
    print("  " + "  ".join("-" * w for w in widths))
    for r in rows:
        print(fmt(r))
    print()


def _no_crowdsec() -> bool:
    """Print a message and return True if CrowdSec is unavailable."""
    if not shutil.which("cscli"):
        print("CrowdSec is not installed. Run 'bardcastle-fw setup' or install "
              "crowdsec to enable IDS data.")
        return True
    return False


def show_decisions() -> None:
    """Show active CrowdSec decisions (currently-banned sources)."""
    if _no_crowdsec():
        return
    data = _cscli_json(["decisions", "list", "-o", "json"]) or []
    rows = []
    for alert in data:
        src = alert.get("source", {}) or {}
        country = src.get("cn", "") or ""
        for d in alert.get("decisions", []) or []:
            rows.append([
                d.get("value", ""),
                d.get("type", ""),
                d.get("scenario", ""),
                d.get("duration", ""),
                d.get("origin", ""),
                country,
            ])
    print("\n=== Active CrowdSec Decisions ===")
    _table(("Source", "Action", "Scenario", "Expires in", "Origin", "Country"), rows)


def show_alerts(limit: int = 25) -> None:
    """Show recent CrowdSec alerts (detection history)."""
    if _no_crowdsec():
        return
    data = _cscli_json(["alerts", "list", "-o", "json"]) or []
    rows = []
    for alert in data[:limit]:
        src = alert.get("source", {}) or {}
        as_name = (src.get("as_name", "") or "")[:22]
        rows.append([
            str(alert.get("id", "")),
            src.get("value", "") or alert.get("scenario", ""),
            alert.get("scenario", ""),
            src.get("cn", "") or "",
            as_name,
            str(alert.get("events_count", "")),
            (alert.get("created_at", "") or "")[:19].replace("T", " "),
        ])
    print("\n=== Recent CrowdSec Alerts ===")
    _table(("ID", "Source", "Scenario", "Cty", "AS", "Events", "When"), rows)


def show_scenarios() -> None:
    """Show enabled CrowdSec detection scenarios."""
    if _no_crowdsec():
        return
    result = run_cmd(["cscli", "scenarios", "list", "-o", "raw"], check=False)
    rows = []
    if result.returncode == 0:
        for line in result.stdout.splitlines()[1:]:  # skip CSV header
            parts = line.split(",", 3)
            if len(parts) >= 4:
                rows.append([parts[0], parts[1], parts[3]])
    print("\n=== Enabled Detection Scenarios ===")
    _table(("Scenario", "Status", "Description"), rows)


def show_metrics() -> None:
    """Show CrowdSec engine metrics (acquisition, scenarios, bouncers)."""
    if _no_crowdsec():
        return
    result = run_cmd(["cscli", "metrics"], check=False)
    print(result.stdout if result.returncode == 0 else "  Metrics unavailable.")
