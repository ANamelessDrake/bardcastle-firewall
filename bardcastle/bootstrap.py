"""Bootstrap module for bardcastle-firewall.

Removes bloat packages, installs required dependencies, resolves
systemd-resolved conflicts, and optionally installs CrowdSec and
Suricata IDS.
"""

import click

from bardcastle import events
from bardcastle.utils import (
    disable_and_stop,
    enable_and_start,
    mark_configured,
    require_root,
    run_cmd,
    run_shell,
    save_config,
    write_config_file,
)

BLOAT_PACKAGES = [
    "snapd",
    "cloud-init",
    "netplan.io",
    "network-manager",
]

REQUIRED_PACKAGES = [
    "python3",
    "python3-pip",
    "python3-venv",
    "python3-nftables",
    "nftables",
    "dnsmasq",
    "wireguard-tools",
    "vnstat",
    "htop",
    "tmux",
    "fail2ban",
    "curl",
]


def _remove_bloat() -> None:
    """Purge unnecessary packages."""
    click.echo("\n--- Removing bloat packages ---")
    cmd = ["apt", "purge", "-y"] + BLOAT_PACKAGES
    try:
        run_cmd(cmd)
        click.echo("Bloat packages removed.")
    except Exception as exc:
        click.echo(f"Warning: some bloat packages may not have been installed: {exc}")


def _install_required() -> None:
    """Install the required system packages."""
    click.echo("\n--- Installing required packages ---")
    run_cmd(["apt", "update"])
    cmd = ["apt", "install", "-y"] + REQUIRED_PACKAGES
    run_cmd(cmd)
    click.echo("Required packages installed.")


def _disable_systemd_resolved() -> None:
    """Stop and disable systemd-resolved to free port 53 for dnsmasq."""
    click.echo("\n--- Disabling systemd-resolved (port 53 conflict) ---")
    try:
        disable_and_stop("systemd-resolved")
    except Exception:
        click.echo("systemd-resolved was not active; continuing.")

    resolv_path = "/etc/resolv.conf"

    # Remove the symlink managed by systemd-resolved
    import os
    if os.path.islink(resolv_path):
        os.unlink(resolv_path)
        click.echo("Removed /etc/resolv.conf symlink.")

    # Write a temporary static resolv.conf
    write_config_file(
        resolv_path,
        "# Temporary resolver written by bardcastle bootstrap\nnameserver 1.1.1.1\n",
        backup=False,
    )
    click.echo("Wrote static /etc/resolv.conf with nameserver 1.1.1.1.")


def _enable_systemd_networkd() -> None:
    """Enable and start systemd-networkd."""
    click.echo("\n--- Enabling systemd-networkd ---")
    enable_and_start("systemd-networkd")
    click.echo("systemd-networkd enabled and started.")


def _install_crowdsec() -> None:
    """Add the CrowdSec repository and install CrowdSec with nftables bouncer."""
    click.echo("\n--- Installing CrowdSec ---")
    run_shell(
        "curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash"
    )
    run_cmd(["apt", "install", "-y", "crowdsec", "crowdsec-firewall-bouncer-nftables"])
    enable_and_start("crowdsec")
    click.echo("CrowdSec installed and enabled.")


def _install_suricata() -> None:
    """Install Suricata IDS."""
    click.echo("\n--- Installing Suricata IDS ---")
    run_shell("add-apt-repository -y ppa:oisf/suricata-stable 2>/dev/null || true")
    run_cmd(["apt", "update"])
    run_cmd(["apt", "install", "-y", "suricata"])
    enable_and_start("suricata")
    click.echo("Suricata IDS installed and enabled.")


def run(config: dict) -> dict:
    """Perform the full bootstrap sequence.

    Args:
        config: The current bardcastle config dict.

    Returns:
        The updated config dict with bootstrap marked as configured.
    """
    require_root()

    click.echo("=" * 60)
    click.echo("  Bardcastle Firewall - Bootstrap")
    click.echo("=" * 60)

    # Core bootstrap steps
    _remove_bloat()
    _install_required()
    _disable_systemd_resolved()
    _enable_systemd_networkd()

    # Optional: CrowdSec
    if click.confirm("\nInstall CrowdSec (community threat intelligence)?", default=False):
        _install_crowdsec()
        config.setdefault("services", {})["crowdsec"] = True
        events.emit_event("config_change", {
            "module": "bootstrap",
            "action": "install_crowdsec",
        })
    else:
        click.echo("Skipping CrowdSec.")

    # Optional: Suricata IDS
    click.echo(
        "\nSuricata IDS provides network intrusion detection but uses "
        "~200-400 MB of RAM. On a 2 GB system this is significant."
    )
    if click.confirm("Install Suricata IDS?", default=False):
        _install_suricata()
        config.setdefault("services", {})["suricata"] = True
        events.emit_event("config_change", {
            "module": "bootstrap",
            "action": "install_suricata",
        })
    else:
        click.echo("Skipping Suricata IDS.")

    # Mark bootstrap as configured
    config = mark_configured(config, "bootstrap")
    save_config(config)

    events.emit_event("config_change", {
        "module": "bootstrap",
        "action": "bootstrap_complete",
    })

    click.echo("\n--- Bootstrap complete ---\n")
    return config
