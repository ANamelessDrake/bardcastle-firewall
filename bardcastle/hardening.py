"""System hardening module for bardcastle-firewall.

Hardens SSH, configures fail2ban, enables unattended security
updates, and sets restrictive file permissions.
"""

import os
import sys

import click

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

SSHD_CONF = "/etc/ssh/sshd_config.d/99-bardcastle.conf"
FAIL2BAN_CONF = "/etc/fail2ban/jail.d/bardcastle.conf"
APT_UNATTENDED_CONF = "/etc/apt/apt.conf.d/50bardcastle"


def _create_user(config: dict) -> None:
    """Prompt to create a new admin user and optionally disable the default."""
    print("\n--- Create User ---")
    if not click.confirm("Create a new user?", default=True):
        return

    username = click.prompt("Username")

    # Check if user already exists
    result = run_cmd(["id", username], check=False)
    if result.returncode == 0:
        print(f"User '{username}' already exists.")
    else:
        run_cmd(["useradd", "-m", "-s", "/bin/bash", "-G", "sudo", username])
        print(f"User '{username}' created and added to sudo group.")
        print(f"Set a password for '{username}':")
        run_cmd(["passwd", username], capture=False)

    # Copy SSH authorized_keys from admin if they exist
    admin_keys = "/home/admin/.ssh/authorized_keys"
    user_ssh_dir = f"/home/{username}/.ssh"
    if os.path.exists(admin_keys):
        os.makedirs(user_ssh_dir, mode=0o700, exist_ok=True)
        import shutil
        shutil.copy2(admin_keys, f"{user_ssh_dir}/authorized_keys")
        run_cmd(["chown", "-R", f"{username}:{username}", user_ssh_dir])
        print(f"Copied SSH keys from admin to {username}.")

    config.setdefault("hardening", {})["user"] = username

    # Optionally disable the default admin account
    if click.confirm("Disable the default 'admin' account?", default=False):
        run_cmd(["passwd", "-l", "admin"])
        print("Default 'admin' account locked.")


def _harden_ssh(config: dict) -> None:
    """Render and apply a hardened sshd configuration."""
    default_user = config.get("hardening", {}).get("user", "admin")
    ssh_user = click.prompt(
        "SSH user to allow", default=default_user, type=str,
    )

    content = render_template("sshd-hardening.conf.j2", {
        "ssh_user": ssh_user,
    })

    write_config_file(SSHD_CONF, content, mode=0o644, backup=True)
    print(f"Wrote {SSHD_CONF}")

    # Validate sshd config before restarting
    print("Testing sshd configuration...")
    try:
        run_cmd(["sshd", "-t"])
    except Exception:
        print(
            "ERROR: sshd config test failed! The config file has been "
            "written but sshd has NOT been restarted.",
            file=sys.stderr,
        )
        raise

    print("Restarting sshd...")
    # Ubuntu's unit is ssh.service; the sshd alias only exists once enabled
    run_cmd(["systemctl", "restart", "ssh"])
    print("SSH hardening applied.")

    config.setdefault("hardening", {})["ssh_user"] = ssh_user


def _configure_fail2ban() -> None:
    """Write a fail2ban jail config for SSH and enable the service."""
    print("\n--- Configuring fail2ban ---")

    content = (
        "[sshd]\n"
        "enabled = true\n"
        "port = ssh\n"
        "filter = sshd\n"
        "maxretry = 5\n"
        "bantime = 3600\n"
        "findtime = 600\n"
    )

    write_config_file(FAIL2BAN_CONF, content, mode=0o644, backup=True)
    print(f"Wrote {FAIL2BAN_CONF}")

    enable_and_start("fail2ban")
    print("fail2ban enabled and started.")


def _configure_unattended_upgrades() -> None:
    """Install and configure unattended-upgrades for security-only updates."""
    print("\n--- Configuring unattended-upgrades ---")

    # Install if not already present
    try:
        run_cmd(["dpkg", "-s", "unattended-upgrades"], capture=True)
        print("unattended-upgrades already installed.")
    except Exception:
        print("Installing unattended-upgrades...")
        run_cmd(["apt", "install", "-y", "unattended-upgrades"])

    content = (
        '// Bardcastle: security-only unattended upgrades\n'
        'Unattended-Upgrade::Allowed-Origins {\n'
        '    "${distro_id}:${distro_codename}-security";\n'
        '};\n'
        'Unattended-Upgrade::Automatic-Reboot "false";\n'
        'Unattended-Upgrade::Mail "";\n'
    )

    write_config_file(APT_UNATTENDED_CONF, content, mode=0o644, backup=True)
    print(f"Wrote {APT_UNATTENDED_CONF}")
    print("Unattended security upgrades configured.")


def _set_permissions() -> None:
    """Set restrictive permissions on sensitive directories and files."""
    print("\n--- Setting restrictive file permissions ---")

    targets = [
        ("/etc/wireguard", 0o700),
        ("/etc/nftables.conf", 0o600),
        ("/etc/bardcastle", 0o700),
    ]

    for path, mode in targets:
        if os.path.exists(path):
            os.chmod(path, mode)
            print(f"  {path} -> {oct(mode)}")
        else:
            print(f"  {path} (not found, skipping)")


def apply(config: dict) -> dict:
    """Apply full system hardening.

    - Harden SSH configuration
    - Configure fail2ban for SSH brute-force protection
    - Enable unattended security upgrades
    - Set restrictive file permissions

    Args:
        config: The current bardcastle config dict.
    """
    require_root()

    print("=" * 60)
    print("  Bardcastle Firewall - System Hardening")
    print("=" * 60)

    _create_user(config)
    _harden_ssh(config)
    _configure_fail2ban()
    _configure_unattended_upgrades()
    _set_permissions()

    # Mark as configured and save
    mark_configured(config, "hardening")
    save_config(config)

    emit_event("config_change", {
        "module": "hardening",
        "action": "apply",
    })

    print("\n--- System hardening complete ---\n")
    return config
