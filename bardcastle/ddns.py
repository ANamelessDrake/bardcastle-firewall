"""Dynamic DNS module for bardcastle-firewall.

Keeps a Route 53 A record pointed at the appliance's current public IP,
so VPN clients can use a stable hostname instead of a changing residential
IP. Uses a dedicated, minimally-scoped IAM credential stored root-only.
"""

import configparser
import sys
import urllib.request

import click

from bardcastle.events import emit_event
from bardcastle.utils import mark_configured, require_root, save_config

CHECKIP_URL = "https://checkip.amazonaws.com"
DEFAULT_CREDS_FILE = "/etc/bardcastle/aws-ddns.credentials"


def _public_ip() -> str:
    """Discover the appliance's public IP (works from behind NAT)."""
    with urllib.request.urlopen(CHECKIP_URL, timeout=10) as resp:
        return resp.read().decode().strip()


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


def _current_record(client, zone_id: str, hostname: str):
    """Return the A record's current value, or None if unset."""
    resp = client.list_resource_record_sets(
        HostedZoneId=zone_id,
        StartRecordName=hostname,
        StartRecordType="A",
        MaxItems="1",
    )
    for rs in resp.get("ResourceRecordSets", []):
        if rs["Name"].rstrip(".") == hostname.rstrip(".") and rs["Type"] == "A":
            records = rs.get("ResourceRecords", [])
            return records[0]["Value"] if records else None
    return None


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

    config["ddns"] = {
        "hostname": hostname,
        "zone_id": zone_id,
        "credentials_file": creds_file,
        "last_ip": existing.get("last_ip"),
    }
    config = mark_configured(config, "ddns")
    save_config(config)
    click.echo("DDNS configured. Run 'bardcastle-fw ddns update' to apply now.")
    return config


def update(config: dict) -> dict:
    """Point the configured record at the current public IP if it changed."""
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
    current = _current_record(client, zone_id, hostname)

    if current == ip:
        click.echo(f"{hostname} already points at {ip}; no change.")
        ddns["last_ip"] = ip
        save_config(config)
        return config

    client.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            "Comment": "bardcastle-fw dynamic DNS update",
            "Changes": [{
                "Action": "UPSERT",
                "ResourceRecordSet": {
                    "Name": hostname,
                    "Type": "A",
                    "TTL": 60,
                    "ResourceRecords": [{"Value": ip}],
                },
            }],
        },
    )
    click.echo(f"Updated {hostname}: {current or 'unset'} -> {ip}")
    ddns["last_ip"] = ip
    save_config(config)

    emit_event("config_change", {
        "module": "ddns",
        "action": "update",
        "hostname": hostname,
        "ip": ip,
        "previous": current,
    })
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

    try:
        client = _route53(ddns.get("credentials_file", DEFAULT_CREDS_FILE))
        record = _current_record(client, ddns["zone_id"], ddns["hostname"])
        match = "in sync" if record == ip else "STALE - run 'ddns update'"
        print(f"  DNS record : {record or '(unset)'}  ({match})")
    except Exception as exc:
        print(f"  DNS record : (query failed: {exc})", file=sys.stderr)
