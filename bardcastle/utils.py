"""Shared helpers for bardcastle-firewall."""

import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = PROJECT_ROOT / "templates"
CONFIG_PATH = Path("/etc/bardcastle/config.yaml")
BACKUP_DIR = PROJECT_ROOT / "backups"


def run_cmd(cmd: list[str], check: bool = True, capture: bool = True,
            env: dict | None = None) -> subprocess.CompletedProcess:
    """Run a shell command and return the result."""
    merged_env = {**os.environ, **(env or {})}
    try:
        return subprocess.run(
            cmd, check=check, capture_output=capture, text=True, env=merged_env,
        )
    except FileNotFoundError:
        # Missing executable. subprocess raises this regardless of `check`,
        # so callers using check=False to probe optional tools would still
        # crash; surface it as a non-zero result instead.
        if not check:
            return subprocess.CompletedProcess(cmd, returncode=127, stdout="", stderr="")
        print(f"Command not found: {cmd[0]}", file=sys.stderr)
        raise
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {' '.join(cmd)}", file=sys.stderr)
        if e.stdout:
            print(e.stdout, file=sys.stderr)
        if e.stderr:
            print(e.stderr, file=sys.stderr)
        raise


def run_shell(cmd: str, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    """Run a shell command string."""
    try:
        return subprocess.run(
            cmd, shell=True, check=check, capture_output=capture, text=True,
        )
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {cmd}", file=sys.stderr)
        if e.stdout:
            print(e.stdout, file=sys.stderr)
        if e.stderr:
            print(e.stderr, file=sys.stderr)
        raise


def detect_interfaces() -> list[dict]:
    """Detect physical network interfaces and their state."""
    interfaces = []
    net_dir = Path("/sys/class/net")
    if not net_dir.exists():
        return interfaces

    for iface_path in sorted(net_dir.iterdir()):
        name = iface_path.name
        if name == "lo":
            continue

        # Skip virtual interfaces
        device_path = iface_path / "device"
        if not device_path.exists():
            continue

        operstate = "unknown"
        state_file = iface_path / "operstate"
        if state_file.exists():
            operstate = state_file.read_text().strip()

        mac = "unknown"
        mac_file = iface_path / "address"
        if mac_file.exists():
            mac = mac_file.read_text().strip()

        speed = "unknown"
        speed_file = iface_path / "speed"
        if speed_file.exists():
            try:
                speed = f"{speed_file.read_text().strip()} Mbps"
            except (OSError, ValueError):
                pass

        driver = "unknown"
        driver_link = iface_path / "device" / "driver"
        if driver_link.exists():
            try:
                driver = driver_link.resolve().name
            except OSError:
                pass

        interfaces.append({
            "name": name,
            "mac": mac,
            "state": operstate,
            "speed": speed,
            "driver": driver,
        })

    return interfaces


def print_interfaces(interfaces: list[dict]) -> None:
    """Pretty-print detected interfaces."""
    if not interfaces:
        print("No physical network interfaces detected!")
        return

    print(f"\n{'Name':<12} {'MAC':<20} {'State':<8} {'Speed':<12} {'Driver':<10}")
    print("-" * 62)
    for iface in interfaces:
        print(
            f"{iface['name']:<12} {iface['mac']:<20} {iface['state']:<8} "
            f"{iface['speed']:<12} {iface['driver']:<10}"
        )
    print()


def load_config() -> dict:
    """Load config from /etc/bardcastle/config.yaml, or return defaults."""
    if CONFIG_PATH.exists():
        return yaml.safe_load(CONFIG_PATH.read_text()) or {}
    return {"configured": {}}


def save_config(config: dict) -> None:
    """Save config to /etc/bardcastle/config.yaml."""
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(yaml.dump(config, default_flow_style=False, sort_keys=False))
    os.chmod(CONFIG_PATH, 0o600)


def backup_file(path: str | Path) -> Path | None:
    """Backup a file before overwriting it."""
    path = Path(path)
    if not path.exists():
        return None
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = BACKUP_DIR / f"{path.name}.{timestamp}.bak"
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, backup_path)
    return backup_path


def render_template(template_name: str, context: dict) -> str:
    """Render a Jinja2 template from the templates directory."""
    from jinja2 import Environment, FileSystemLoader
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        keep_trailing_newline=True,
    )
    template = env.get_template(template_name)
    return template.render(**context)


def write_config_file(path: str | Path, content: str,
                      mode: int = 0o644, backup: bool = True) -> None:
    """Write a config file with optional backup and permissions."""
    path = Path(path)
    if backup:
        backup_file(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    os.chmod(path, mode)


def require_root() -> None:
    """Exit if not running as root."""
    if os.geteuid() != 0:
        print("Error: this command must be run as root (use sudo).", file=sys.stderr)
        sys.exit(1)


def is_module_configured(config: dict, module: str) -> bool:
    """Check if a module is marked as configured."""
    return config.get("configured", {}).get(module, False)


def mark_configured(config: dict, module: str) -> dict:
    """Mark a module as configured and return updated config."""
    if "configured" not in config:
        config["configured"] = {}
    config["configured"][module] = True
    return config


def prompt_reconfigure(module_name: str, config: dict) -> bool:
    """Prompt user to reconfigure or skip an already-configured module.

    Returns True if user wants to (re)configure, False to skip.
    """
    if not is_module_configured(config, module_name):
        return True

    import click
    choice = click.prompt(
        f"\n{module_name.capitalize()}: already configured. "
        f"[R]econfigure / [S]kip",
        type=click.Choice(["R", "S", "r", "s"], case_sensitive=False),
        default="S",
    )
    return choice.upper() == "R"


def systemctl(action: str, unit: str) -> None:
    """Run systemctl action on a unit."""
    run_cmd(["systemctl", action, unit])


def enable_and_start(unit: str) -> None:
    """Enable and start a systemd unit."""
    systemctl("enable", unit)
    systemctl("start", unit)


def disable_and_stop(unit: str) -> None:
    """Disable and stop a systemd unit."""
    systemctl("disable", unit)
    systemctl("stop", unit)
