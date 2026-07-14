"""Network configuration module for bardcastle-firewall.

Configures systemd-networkd for WAN/LAN interfaces, sets up IP
forwarding via sysctl, and assigns LAN addressing with DHCP range
defaults.
"""

import sys

import click

from bardcastle import events
from bardcastle.utils import (
    detect_interfaces,
    mark_configured,
    print_interfaces,
    render_template,
    require_root,
    run_cmd,
    save_config,
    systemctl,
    write_config_file,
)


def _select_interface(interfaces: list[dict], role: str,
                      exclude: str | None = None) -> str:
    """Prompt the user to select an interface for a given role.

    Args:
        interfaces: List of detected interface dicts.
        role: Human-readable role name (e.g. "WAN", "LAN").
        exclude: Interface name to exclude from choices.

    Returns:
        The chosen interface name.
    """
    available = [iface["name"] for iface in interfaces if iface["name"] != exclude]
    if not available:
        click.echo(f"Error: no available interfaces for {role}.", err=True)
        sys.exit(1)

    choice = click.prompt(
        f"Select {role} interface",
        type=click.Choice(available, case_sensitive=True),
    )
    return choice


def setup(config: dict) -> dict:
    """Configure systemd-networkd for WAN and LAN interfaces.

    Args:
        config: The current bardcastle config dict.

    Returns:
        The updated config dict with network settings and marked configured.
    """
    require_root()

    click.echo("=" * 60)
    click.echo("  Bardcastle Firewall - Network Configuration")
    click.echo("=" * 60)

    # Detect and display interfaces
    interfaces = detect_interfaces()
    click.echo("\nDetected network interfaces:")
    print_interfaces(interfaces)

    if len(interfaces) < 2:
        click.echo(
            "Error: at least two physical network interfaces are required "
            "(one WAN, one LAN).",
            err=True,
        )
        sys.exit(1)

    # Select WAN and LAN interfaces
    wan_iface = _select_interface(interfaces, "WAN")
    lan_iface = _select_interface(interfaces, "LAN", exclude=wan_iface)

    # LAN addressing
    lan_ip = click.prompt("LAN IP address", default="10.0.1.1")
    lan_subnet = click.prompt("LAN subnet prefix length", default=24, type=int)

    # DHCP range
    dhcp_start = click.prompt("DHCP range start", default="10.0.1.100")
    dhcp_end = click.prompt("DHCP range end", default="10.0.1.200")

    # Domain name
    domain = click.prompt("Domain name", default="example.com")

    click.echo(f"\n--- Writing systemd-networkd configuration ---")

    # Template context
    template_ctx = {
        "wan_interface": wan_iface,
        "lan_interface": lan_iface,
        "lan_ip": lan_ip,
        "lan_subnet": lan_subnet,
        "dhcp_start": dhcp_start,
        "dhcp_end": dhcp_end,
        "domain": domain,
    }

    # Render and write WAN network file
    wan_content = render_template("systemd-networkd/wan.network.j2", template_ctx)
    write_config_file("/etc/systemd/network/10-wan.network", wan_content)
    click.echo("Wrote /etc/systemd/network/10-wan.network")

    # Render and write LAN network file
    lan_content = render_template("systemd-networkd/lan.network.j2", template_ctx)
    write_config_file("/etc/systemd/network/20-lan.network", lan_content)
    click.echo("Wrote /etc/systemd/network/20-lan.network")

    # Render and write sysctl router config
    sysctl_content = render_template("sysctl-router.conf.j2", template_ctx)
    write_config_file("/etc/sysctl.d/99-router.conf", sysctl_content)
    click.echo("Wrote /etc/sysctl.d/99-router.conf")

    # Apply sysctl settings
    click.echo("\n--- Applying sysctl settings ---")
    run_cmd(["sysctl", "--system"])

    # Restart systemd-networkd to pick up new config
    click.echo("\n--- Restarting systemd-networkd ---")
    systemctl("restart", "systemd-networkd")
    click.echo("systemd-networkd restarted.")

    # Save network configuration
    config["network"] = {
        "wan_interface": wan_iface,
        "lan_interface": lan_iface,
        "lan_ip": lan_ip,
        "lan_subnet": lan_subnet,
        "dhcp_start": dhcp_start,
        "dhcp_end": dhcp_end,
        "domain": domain,
    }
    config = mark_configured(config, "network")
    save_config(config)

    events.emit_event("config_change", {
        "module": "network",
        "action": "network_configured",
        "wan_interface": wan_iface,
        "lan_interface": lan_iface,
        "lan_ip": lan_ip,
        "lan_subnet": lan_subnet,
    })

    click.echo("\n--- Network configuration complete ---\n")
    return config
