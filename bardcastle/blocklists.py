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


def _filter_public(entries: list[str]) -> tuple[list[str], int]:
    """Drop entries that overlap private/reserved space.

    Returns (kept_entries, skipped_count). Unparseable lines are skipped.
    """
    kept: list[str] = []
    skipped = 0
    for entry in entries:
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            skipped += 1
            continue
        if any(net.overlaps(excl) for excl in EXCLUDED_RANGES):
            skipped += 1
            continue
        kept.append(entry)
    return kept, skipped


def _load_ips_nftables(ips: list[str]) -> None:
    """Load a list of IPs/CIDRs into the nftables blocklist_v4 set.

    Tries python3-nftables bindings first, falls back to the nft CLI.
    """
    try:
        import nftables  # type: ignore[import-untyped]

        nft = nftables.Nftables()
        nft.set_json_output(True)

        # Flush the existing set
        nft.cmd("flush set inet filter blocklist_v4")

        # Add elements in batches to avoid command-line length limits
        batch_size = 500
        for i in range(0, len(ips), batch_size):
            batch = ips[i:i + batch_size]
            elements = ", ".join(batch)
            nft.cmd(f"add element inet filter blocklist_v4 {{ {elements} }}")

        click.echo("Loaded IPs via python3-nftables bindings.")
    except (ImportError, Exception) as exc:
        click.echo(f"nftables bindings unavailable ({exc}), falling back to nft CLI.")

        # Flush the existing set
        run_cmd(["nft", "flush", "set", "inet", "filter", "blocklist_v4"])

        # Add elements in batches
        batch_size = 500
        for i in range(0, len(ips), batch_size):
            batch = ips[i:i + batch_size]
            elements = ", ".join(batch)
            run_cmd(["nft", "add", "element", "inet", "filter", "blocklist_v4",
                      f"{{ {elements} }}"])

        click.echo("Loaded IPs via nft CLI.")


def update(config: dict) -> dict:
    """Update blocklists from CrowdSec and FireHOL.

    If CrowdSec is installed, updates the hub and installs the base
    Linux collection. Downloads the FireHOL level-1 netset and loads
    all IPs into the nftables blocklist_v4 set.

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

    # Download FireHOL level1 blocklist
    click.echo("Downloading FireHOL level1 blocklist...")
    run_cmd(["curl", "-s", "-o", BLOCKLIST_NETSET, FIREHOL_URL])

    # Parse the netset file
    ips: list[str] = []
    with open(BLOCKLIST_NETSET) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ips.append(line)

    if not ips:
        click.echo("Warning: no IPs found in the blocklist file.")
        return config

    ips, skipped = _filter_public(ips)
    click.echo(
        f"Parsed {len(ips)} public entries from FireHOL level1 "
        f"({skipped} private/reserved entries excluded)."
    )
    if not ips:
        click.echo("Warning: no public IPs left after filtering; not loading.")
        return config

    # Load into nftables
    _load_ips_nftables(ips)

    events.emit_event("blocklist_update", {
        "source": "firehol_level1",
        "count": len(ips),
    })

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
    try:
        result = run_shell(
            "nft list set inet filter blocklist_v4 2>/dev/null | "
            "grep -c -E '^\\s+[0-9]'",
            check=False,
        )
        count = result.stdout.strip() if result.returncode == 0 else "0"
        click.echo(f"nftables blocklist_v4 entries: {count}")
    except Exception:
        click.echo("Could not query nftables blocklist_v4 set.")

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
