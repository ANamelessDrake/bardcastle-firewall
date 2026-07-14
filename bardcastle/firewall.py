"""Firewall module using nftables for bardcastle-firewall."""

import sys

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

NFTABLES_CONF = "/etc/nftables.conf"


def apply(config: dict) -> dict:
    """Apply nftables firewall rules from config.

    Reads network interfaces and VPN port from config, renders the
    nftables.conf.j2 template, validates the ruleset with a dry run,
    and applies it.
    """
    require_root()

    network = config["network"]
    wan_interface = network["wan_interface"]
    lan_interface = network["lan_interface"]
    vpn_port = config.get("vpn", {}).get("port", 51820)

    # Only VPN clients flagged as dashboard admins may reach the web UI over
    # the tunnel; the template gates ports 80/443 on wg0 to these source IPs.
    from bardcastle.vpn import admin_client_ips
    admin_vpn_ips = admin_client_ips(config)

    print(f"WAN interface : {wan_interface}")
    print(f"LAN interface : {lan_interface}")
    print(f"VPN port      : {vpn_port}")
    print(f"Dashboard VPN admins : {', '.join(admin_vpn_ips) or '(none)'}")

    # Render the nftables configuration from template
    content = render_template("nftables.conf.j2", {
        "wan_interface": wan_interface,
        "lan_interface": lan_interface,
        "vpn_port": vpn_port,
        "admin_vpn_ips": admin_vpn_ips,
    })

    # Write with backup
    write_config_file(NFTABLES_CONF, content, mode=0o600, backup=True)
    print(f"Wrote {NFTABLES_CONF}")

    # Validate with dry run
    print("Validating nftables configuration...")
    try:
        run_cmd(["nft", "-c", "-f", NFTABLES_CONF])
    except Exception:
        print("ERROR: nftables config validation failed!", file=sys.stderr)
        print("The config file has been written but NOT applied.", file=sys.stderr)
        raise

    # Apply the validated ruleset
    print("Applying nftables ruleset...")
    run_cmd(["nft", "-f", NFTABLES_CONF])

    # Enable and start the nftables service
    print("Enabling nftables service...")
    enable_and_start("nftables")

    # Mark as configured and save
    mark_configured(config, "firewall")
    save_config(config)

    emit_event("config_change", {
        "module": "firewall",
        "action": "apply",
        "wan_interface": wan_interface,
        "lan_interface": lan_interface,
        "vpn_port": vpn_port,
    })

    print("Firewall configured and applied successfully.")
    return config


def show() -> None:
    """Display the current nftables ruleset."""
    require_root()
    result = run_cmd(["nft", "list", "ruleset"], check=True, capture=True)
    print(result.stdout)


def _fmt_value(val) -> str:
    """Format an nft match right-hand side (int, set, or range) as text."""
    if isinstance(val, dict):
        if "set" in val:
            parts = [_fmt_value(v) for v in val["set"]]
            return ",".join(parts)
        if "range" in val:
            lo, hi = val["range"]
            return f"{lo}-{hi}"
        if "prefix" in val:
            p = val["prefix"]
            return f"{p.get('addr')}/{p.get('len')}"
    return str(val)


def _parse_rule(expr: list) -> dict:
    """Extract interface/proto/port/action fields from one rule's expr list."""
    row = {"iif": "", "oif": "", "proto": "", "port": "", "action": ""}
    for e in expr:
        if "match" in e:
            left = e["match"].get("left", {})
            right = e["match"].get("right")
            if "meta" in left:
                key = left["meta"].get("key")
                if key == "iifname":
                    row["iif"] = _fmt_value(right)
                elif key == "oifname":
                    row["oif"] = _fmt_value(right)
                elif key == "l4proto":
                    row["proto"] = _fmt_value(right)
            elif "payload" in left:
                field = left["payload"].get("field")
                if field == "dport":
                    row["proto"] = left["payload"].get("protocol", row["proto"])
                    row["port"] = _fmt_value(right)
                elif field in ("protocol", "nexthdr"):
                    row["proto"] = _fmt_value(right)
        elif "accept" in e:
            row["action"] = "ALLOW"
        elif "drop" in e:
            row["action"] = "DENY"
        elif "reject" in e:
            row["action"] = "REJECT"
        elif "log" in e and not row["action"]:
            row["action"] = "LOG"
    return row


def show_rules(config: dict) -> None:
    """Print a human-readable table of the firewall's filter rules."""
    require_root()
    result = run_cmd(["nft", "-j", "list", "ruleset"], check=False)
    if result.returncode != 0:
        print("nftables not running or not configured.")
        return
    import json
    try:
        ruleset = json.loads(result.stdout or "{}").get("nftables", [])
    except json.JSONDecodeError:
        print("Could not parse nftables ruleset.")
        return

    net = config.get("network", {})

    def role(name: str) -> str:
        if not name:
            return "any"
        if name == net.get("wan_interface"):
            return f"WAN ({name})"
        if name == net.get("lan_interface"):
            return f"LAN ({name})"
        if name == "wg0":
            return "VPN (wg0)"
        return name

    rows = []  # (chain, in_iface, out_iface, proto, port, action, description)
    for item in ruleset:
        rule = item.get("rule")
        if not rule or rule.get("family") != "inet" or rule.get("table") != "filter":
            continue
        parsed = _parse_rule(rule.get("expr", []))
        if not parsed["action"]:
            continue
        rows.append((
            rule.get("chain", ""),
            role(parsed["iif"]),
            role(parsed["oif"]) if parsed["oif"] else "any",
            parsed["proto"] or "any",
            parsed["port"] or "any",
            parsed["action"],
            rule.get("comment", ""),
        ))

    if not rows:
        print("No filter rules loaded. Run 'bardcastle-fw firewall apply'.")
        return

    headers = ("Chain", "In", "Out", "Proto", "Port", "Action", "Description")
    widths = [max(len(str(r[i])) for r in (headers,) + tuple(rows))
              for i in range(len(headers))]

    def line(cols):
        return "  " + "  ".join(
            str(c).ljust(widths[i]) for i, c in enumerate(cols)
        )

    print()
    print(line(headers))
    print("  " + "  ".join("-" * w for w in widths))
    last_chain = None
    for r in rows:
        if r[0] != last_chain and last_chain is not None:
            print()
        print(line(r))
        last_chain = r[0]
    print()


def show_counters() -> None:
    """Display nftables rules with hit counters."""
    require_root()
    result = run_cmd(["nft", "list", "ruleset"], check=True, capture=True)
    print("=== Firewall Rule Counters ===\n")
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if "counter" in stripped or stripped.startswith("table") or stripped.startswith("chain"):
            print(line)
    if not result.stdout.strip():
        print("No rules loaded.")
