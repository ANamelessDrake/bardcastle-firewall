"""Dynamic DNS module for bardcastle-firewall.

Keeps a Route 53 A record pointed at the appliance's current public IP,
so VPN clients can use a stable hostname instead of a changing residential
IP. Uses a dedicated, minimally-scoped IAM credential stored root-only.

Optionally does the same for IPv6, publishing an AAAA record with the WAN's
current global address. ISPs delegate the IPv6 prefix dynamically, so anything
that needs to know this appliance's current IPv6 (a remote allowlist, for
example) can resolve the record instead of being updated out of band.

The AAAA is normally published on its own hostname rather than the VPN one.
An AAAA on the VPN hostname makes clients try to reach the endpoint over IPv6,
which only works if inbound UDP on the VPN port is permitted over IPv6 all the
way upstream; a separate name keeps that risk away from VPN connectivity.
"""

import configparser
import json
import sys
import urllib.request

import click

from bardcastle.events import emit_event
from bardcastle.utils import mark_configured, require_root, run_cmd, save_config

CHECKIP_URL = "https://checkip.amazonaws.com"
DEFAULT_CREDS_FILE = "/etc/bardcastle/aws-ddns.credentials"


def _public_ip() -> str:
    """Discover the appliance's public IP (works from behind NAT)."""
    with urllib.request.urlopen(CHECKIP_URL, timeout=10) as resp:
        return resp.read().decode().strip()


def _wan_ipv6(wan_interface: str) -> str | None:
    """The WAN's stable global IPv6 address, or None if the WAN has no IPv6.

    Read locally rather than from an echo service. IPv6 is routed rather than
    NATed, so the address on the WAN interface *is* the appliance's public
    address; there is nothing to discover from outside, and this keeps working
    when the echo service is IPv4-only or unreachable.

    Privacy/temporary addresses are skipped: they rotate on their own and would
    churn the DNS record.
    """
    result = run_cmd(
        ["ip", "-6", "-j", "addr", "show", "dev", wan_interface, "scope", "global"],
        check=False, capture=True,
    )
    if not result or result.returncode != 0:
        return None
    try:
        links = json.loads(result.stdout or "[]")
    except json.JSONDecodeError:
        return None
    for link in links:
        for addr in link.get("addr_info", []):
            if addr.get("family") != "inet6":
                continue
            if addr.get("temporary") or addr.get("deprecated"):
                continue
            return addr.get("local")
    return None


def _route53(creds_file: str):
    """Build a boto3 Route 53 client from the root-only credentials file."""
    import boto3

    parser = configparser.ConfigParser()
    if not parser.read(creds_file):
        raise RuntimeError(f"Credentials file not found: {creds_file}")
    section = parser["default"]
    return boto3.client(
        "route53",
        region_name="us-east-1",  # Route 53 is global; region is a formality
        aws_access_key_id=section["aws_access_key_id"],
        aws_secret_access_key=section["aws_secret_access_key"],
    )


def _current_record(client, zone_id: str, hostname: str, rtype: str = "A"):
    """Return the record's current value, or None if unset."""
    resp = client.list_resource_record_sets(
        HostedZoneId=zone_id,
        StartRecordName=hostname,
        StartRecordType=rtype,
        MaxItems="1",
    )
    for rs in resp.get("ResourceRecordSets", []):
        if rs["Name"].rstrip(".") == hostname.rstrip(".") and rs["Type"] == rtype:
            records = rs.get("ResourceRecords", [])
            return records[0]["Value"] if records else None
    return None


def _upsert_record(client, zone_id: str, hostname: str, rtype: str, value: str) -> None:
    """Point hostname's record of this type at value."""
    client.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            "Comment": "bardcastle-fw dynamic DNS update",
            "Changes": [{
                "Action": "UPSERT",
                "ResourceRecordSet": {
                    "Name": hostname,
                    "Type": rtype,
                    "TTL": 60,
                    "ResourceRecords": [{"Value": value}],
                },
            }],
        },
    )


def setup(config: dict) -> dict:
    """Interactively configure dynamic DNS settings."""
    require_root()
    click.echo("\n--- Dynamic DNS (Route 53) Setup ---")

    existing = config.get("ddns", {})
    hostname = click.prompt("Hostname to keep updated",
                            default=existing.get("hostname", "vpn.example.com"))
    zone_id = click.prompt("Route 53 hosted zone ID",
                           default=existing.get("zone_id", ""))
    creds_file = click.prompt("AWS credentials file (root-only)",
                              default=existing.get("credentials_file", DEFAULT_CREDS_FILE))

    # IPv6 is opt-in. The ISP-delegated prefix is dynamic, so publishing it as
    # an AAAA gives anything that needs this appliance's current IPv6 a stable
    # name to resolve instead of being updated out of band.
    ipv6 = click.confirm(
        "Also publish the WAN's IPv6 address as an AAAA record?",
        default=bool(existing.get("ipv6")),
    )

    hostname6 = existing.get("hostname6", "")
    if ipv6:
        # Default to a separate name. An AAAA on the VPN hostname makes clients
        # try the endpoint over IPv6, which fails unless inbound UDP on the VPN
        # port works over IPv6 upstream, so keep the two records apart.
        suggested = hostname6 or (
            f"wan6.{hostname.split('.', 1)[1]}" if "." in hostname else "wan6"
        )
        hostname6 = click.prompt(
            "Hostname for the AAAA record (keep it separate from the VPN name)",
            default=suggested,
        ).strip()
        if hostname6 == hostname:
            click.echo(
                "  Warning: this is the VPN hostname. Clients will try to reach\n"
                "  the endpoint over IPv6, which only works if inbound UDP on the\n"
                "  VPN port is permitted over IPv6 upstream.")

    config["ddns"] = {
        "hostname": hostname,
        "zone_id": zone_id,
        "credentials_file": creds_file,
        "ipv6": ipv6,
        "hostname6": hostname6,
        "last_ip": existing.get("last_ip"),
        "last_ipv6": existing.get("last_ipv6"),
    }

    config = mark_configured(config, "ddns")
    save_config(config)
    click.echo("DDNS configured. Run 'bardcastle-fw ddns update' to apply now.")
    return config


def _update_ipv6(config: dict, ddns: dict, r53, zone_id: str) -> None:
    """Publish the WAN's current global IPv6 as an AAAA record.

    Runs independently of the IPv4 update: the ISP can rotate the delegated
    IPv6 prefix without the IPv4 address changing, and vice versa.
    """
    hostname6 = ddns.get("hostname6") or ddns.get("hostname")
    if not hostname6:
        click.echo("  IPv6: no hostname6 configured; skipping.", err=True)
        return

    wan = config.get("network", {}).get("wan_interface")
    if not wan:
        click.echo("  IPv6: no wan_interface in config; skipping.", err=True)
        return

    address = _wan_ipv6(wan)
    if not address:
        click.echo(f"  IPv6: {wan} has no global IPv6 address; skipping.")
        return

    current = _current_record(r53, zone_id, hostname6, "AAAA")
    if current == address:
        click.echo(f"  IPv6: {hostname6} already points at {address}; no change.")
    else:
        _upsert_record(r53, zone_id, hostname6, "AAAA", address)
        click.echo(f"  IPv6: updated {hostname6}: {current or 'unset'} -> {address}")
        emit_event("config_change", {
            "module": "ddns", "action": "update_aaaa",
            "hostname": hostname6, "ip": address, "previous": current,
        })
    ddns["last_ipv6"] = address


def update(config: dict) -> dict:
    """Point the configured records at the current public addresses."""
    require_root()
    ddns = config.get("ddns")
    if not ddns or not ddns.get("zone_id"):
        click.echo("DDNS is not configured. Run 'bardcastle-fw ddns setup'.", err=True)
        return config

    hostname = ddns["hostname"]
    zone_id = ddns["zone_id"]
    creds_file = ddns.get("credentials_file", DEFAULT_CREDS_FILE)

    try:
        ip = _public_ip()
    except Exception as exc:
        click.echo(f"Could not determine public IP: {exc}", err=True)
        return config

    client = _route53(creds_file)
    current = _current_record(client, zone_id, hostname, "A")

    if current == ip:
        click.echo(f"{hostname} already points at {ip}; no change.")
    else:
        _upsert_record(client, zone_id, hostname, "A", ip)
        click.echo(f"Updated {hostname}: {current or 'unset'} -> {ip}")
        emit_event("config_change", {
            "module": "ddns",
            "action": "update",
            "hostname": hostname,
            "ip": ip,
            "previous": current,
        })
    ddns["last_ip"] = ip

    if ddns.get("ipv6"):
        _update_ipv6(config, ddns, client, zone_id)

    save_config(config)
    return config


def status(config: dict) -> None:
    """Show DDNS configuration and whether the record is current."""
    print("\n" + "=" * 50)
    print("  Dynamic DNS (Route 53)")
    print("=" * 50)

    ddns = config.get("ddns")
    if not ddns or not ddns.get("zone_id"):
        print("  Not configured. Run 'bardcastle-fw ddns setup'.")
        return

    print(f"  Hostname   : {ddns['hostname']}")
    print(f"  Zone ID    : {ddns['zone_id']}")
    print(f"  Last known : {ddns.get('last_ip') or '(none)'}")

    try:
        ip = _public_ip()
        print(f"  Current IP : {ip}")
    except Exception as exc:
        print(f"  Current IP : (lookup failed: {exc})")
        return

    creds_file = ddns.get("credentials_file", DEFAULT_CREDS_FILE)
    try:
        client = _route53(creds_file)
        record = _current_record(client, ddns["zone_id"], ddns["hostname"], "A")
        match = "in sync" if record == ip else "STALE - run 'ddns update'"
        print(f"  DNS record : {record or '(unset)'}  ({match})")
    except Exception as exc:
        print(f"  DNS record : (query failed: {exc})", file=sys.stderr)
        return

    if not ddns.get("ipv6"):
        print("  IPv6       : disabled (set ddns.ipv6 to publish an AAAA record)")
        return

    hostname6 = ddns.get("hostname6") or ddns["hostname"]
    wan = config.get("network", {}).get("wan_interface", "")
    address = _wan_ipv6(wan) if wan else None
    if not address:
        print(f"  IPv6       : no global address on {wan or '(no wan_interface)'}")
        return

    print(f"  AAAA name  : {hostname6}")
    print(f"  Current v6 : {address}")
    try:
        record6 = _current_record(client, ddns["zone_id"], hostname6, "AAAA")
        match6 = "in sync" if record6 == address else "STALE - run 'ddns update'"
        print(f"  AAAA record: {record6 or '(unset)'}  ({match6})")
    except Exception as exc:
        print(f"  AAAA record: (query failed: {exc})", file=sys.stderr)
