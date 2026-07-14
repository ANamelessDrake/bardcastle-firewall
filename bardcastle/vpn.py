"""WireGuard VPN module for bardcastle-firewall.

Handles server setup, client management, and peer status display.
"""

import base64
import ipaddress
import shutil
import subprocess
import sys
from pathlib import Path

import click

from bardcastle import events
from bardcastle.utils import (
    enable_and_start,
    mark_configured,
    render_template,
    require_root,
    run_cmd,
    run_shell,
    save_config,
    write_config_file,
)


# Kept outside the 0700 /etc/bardcastle dir: dnsmasq drops privileges to an
# unprivileged user and must be able to read this file (it holds only
# non-secret name->VPN-IP mappings).
VPN_HOSTS_FILE = "/var/lib/bardcastle/vpn-hosts"


def _vpn_domain(config: dict) -> str:
    """The subdomain VPN clients are published under, e.g. vpn.example.com."""
    domain = config.get("network", {}).get("domain", "bardcastle.lan")
    return f"vpn.{domain}"


def _sync_vpn_hosts(config: dict) -> None:
    """Regenerate the dnsmasq addn-hosts file from the client list and reload.

    Maps each client's label to its VPN IP as <name>.vpn.<domain>, so clients
    are reachable by name. Rebuilt wholesale from config (the source of truth)
    on every add/remove, then dnsmasq is reloaded (SIGHUP) to pick it up.
    """
    domain = _vpn_domain(config)
    # Publish both the FQDN (<name>.vpn.<domain>) and the short <name>.vpn.
    # The short form has a dot, so dnsmasq serves it verbatim (expand-hosts
    # only touches dotless names), which lets clients resolve "<name>.vpn"
    # directly without depending on their search-domain behavior.
    lines = [
        f"{c['ip']} {c['name']}.{domain} {c['name']}.vpn"
        for c in config.get("vpn", {}).get("clients", [])
    ]
    path = Path(VPN_HOSTS_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o755)   # dnsmasq's unprivileged user must traverse
    path.write_text("\n".join(lines) + ("\n" if lines else ""))
    path.chmod(0o644)          # ...and read the file
    # SIGHUP via systemctl reload makes dnsmasq re-read hosts files without
    # dropping the service; ignore failure if dnsmasq is not running yet.
    run_cmd(["systemctl", "reload", "dnsmasq"], check=False)


def _validate_pubkey(key: str) -> str:
    """Validate a WireGuard public key (32 bytes, base64). Returns it trimmed."""
    key = key.strip()
    try:
        if len(base64.b64decode(key)) != 32:
            raise ValueError
    except Exception:
        raise click.ClickException(
            "Invalid WireGuard public key (expected 44-char base64, e.g. the "
            "output of 'wg pubkey')."
        )
    return key


def _is_byo(client: dict) -> bool:
    """True if the client brought its own key (server holds no private key)."""
    return not client.get("private_key")


def _generate_keypair() -> tuple[str, str]:
    """Generate a WireGuard private/public keypair.

    Returns:
        A (private_key, public_key) tuple.
    """
    result = run_shell("wg genkey")
    private_key = result.stdout.strip()
    result = run_shell(f"echo '{private_key}' | wg pubkey")
    public_key = result.stdout.strip()
    return private_key, public_key


def _render_and_apply_server_config(config: dict) -> None:
    """Re-render wg0.conf from the current VPN config and reload."""
    vpn = config["vpn"]
    content = render_template("wg0.conf.j2", {
        "server_private_key": vpn["server_private_key"],
        "server_ip": vpn["server_ip"],
        "vpn_port": vpn["port"],
        "clients": vpn.get("clients", []),
    })
    write_config_file("/etc/wireguard/wg0.conf", content, mode=0o600)


def setup(config: dict) -> dict:
    """Set up the WireGuard VPN server.

    Generates server keys, prompts for network settings, writes the
    server configuration, and enables the wg-quick service.

    Args:
        config: The current bardcastle config dict.

    Returns:
        The updated config dict.
    """
    click.echo("\n--- WireGuard VPN Setup ---")

    # Generate server keypair
    click.echo("Generating server keypair...")
    private_key, public_key = _generate_keypair()

    # Prompt for VPN settings
    server_ip = click.prompt("VPN server IP", default="10.10.10.1")
    vpn_port = click.prompt("VPN listen port", default=51820, type=int)

    # Store VPN config
    config["vpn"] = {
        "server_ip": server_ip,
        "port": vpn_port,
        "server_public_key": public_key,
        "server_private_key": private_key,
        "clients": [],
    }

    # Render and write server config
    _render_and_apply_server_config(config)
    click.echo("Wrote /etc/wireguard/wg0.conf")

    # Enable and start the WireGuard interface
    enable_and_start("wg-quick@wg0")
    click.echo("WireGuard interface wg0 is up.")

    # Mark configured and save
    config = mark_configured(config, "vpn")
    save_config(config)

    events.emit_event("config_change", {
        "module": "vpn",
        "action": "setup",
        "server_ip": server_ip,
        "port": vpn_port,
    })

    click.echo("VPN setup complete.\n")
    return config


def _next_available_ip(config: dict) -> str:
    """Find the next available IP in the 10.10.10.0/24 range.

    The server occupies .1 by convention; clients start at .2.
    """
    network = ipaddress.IPv4Network("10.10.10.0/24", strict=False)
    vpn = config.get("vpn", {})
    server_ip = vpn.get("server_ip", "10.10.10.1")

    used = {ipaddress.IPv4Address(server_ip)}
    for client in vpn.get("clients", []):
        used.add(ipaddress.IPv4Address(client["ip"]))

    # Skip network (.0) and broadcast (.255) addresses
    for host in network.hosts():
        if host not in used:
            return str(host)

    raise RuntimeError("No available IPs in the 10.10.10.0/24 range.")


def add_client(config: dict, name: str, pubkey: str | None = None,
               server_generate: bool = False) -> dict:
    """Add a VPN client peer.

    Assigns the next available IP, updates the server config, and prints the
    client configuration.

    Key handling:
    - Default: the server generates the keypair and prints a complete config,
      but stores only the public key (the private key is used once here and
      then discarded). Convenient and the server never retains the key.
    - ``pubkey``: the client generated its own keypair and supplies the public
      key; the printed config carries a placeholder for the private key, which
      never touches the server (most secure).
    - ``server_generate=True``: like the default but also stores the private
      key, so ``show-client`` can reprint the config later.

    Args:
        config: The current bardcastle config dict.
        name: A human-readable name for the client.
        pubkey: Client-generated public key (bring-your-own-key).
        server_generate: If True, store the generated private key too.

    Returns:
        The updated config dict.
    """
    vpn = config.get("vpn", {})
    if not vpn:
        click.echo("Error: VPN is not configured. Run setup first.", err=True)
        return config

    if _find_client(config, name):
        click.echo(f"Error: a client named '{name}' already exists.", err=True)
        return config

    click.echo(f"\n--- Adding VPN client: {name} ---")

    # Resolve the keypair. `display_private` is the private key used for the
    # printed config; it is only *stored* when explicitly requested.
    if pubkey:
        client_public = _validate_pubkey(pubkey)
        display_private = None
        click.echo("Using client-provided public key (server holds no private key).")
    else:
        display_private, client_public = _generate_keypair()

    # Assign next available IP
    client_ip = _next_available_ip(config)
    click.echo(f"Assigned IP: {client_ip}/24")

    # Store the private key only when explicitly requested (--server-key).
    client_entry = {
        "name": name,
        "ip": client_ip,
        "public_key": client_public,
    }
    if display_private and server_generate:
        client_entry["private_key"] = display_private
    config["vpn"].setdefault("clients", []).append(client_entry)

    # Re-render and apply server config with new peer
    _render_and_apply_server_config(config)
    run_cmd(["systemctl", "restart", "wg-quick@wg0"])
    click.echo("Server config updated and reloaded.")

    # Persist now, before any cosmetic output, so a display error can never
    # leave wg0.conf and the saved config out of sync.
    save_config(config)

    # Publish the client's name in DNS (<name>.vpn.<domain> -> VPN IP).
    _sync_vpn_hosts(config)

    # Render and display the client config + QR. Pass the generated key so the
    # config is complete even when it is not stored on the server.
    _emit_client_config(config, client_entry, private_key=display_private)

    events.emit_event("vpn_connect", {
        "client_name": name,
        "client_ip": client_ip,
    })

    click.echo(f"Client '{name}' added successfully.\n")
    return config


def _client_endpoint(config: dict) -> str:
    """Pick the endpoint clients dial: DDNS hostname, WAN IP, or prompt."""
    endpoint = (config.get("ddns", {}).get("hostname")
                or config.get("network", {}).get("wan_ip"))
    if not endpoint:
        endpoint = click.prompt(
            "WAN IP or hostname for VPN endpoint (clients connect to this)",
            default="your-public-ip-or-hostname",
        )
    return endpoint


def _emit_client_config(config: dict, client: dict, qr_file: str | None = None,
                        private_key: str | None = None) -> None:
    """Render, print, and QR-encode a client's WireGuard config.

    ``private_key`` supplies the key for a server-generated client whose key
    is not stored on the server (it is used once here and then discarded). If
    no key is available anywhere, the client brought its own key, so the
    printed config carries a placeholder and no QR (a QR without the real key
    would be useless).

    If ``qr_file`` is given, also write a PNG QR to that path — more reliable
    to scan than the terminal QR, which the WireGuard app's scanner often
    can't read.
    """
    vpn = config["vpn"]
    # The private key may be supplied here (server-generated but not stored)
    # or read from the client entry (server-generated and stored). If neither
    # exists, the client brought its own key and we print a placeholder.
    priv = private_key or client.get("private_key")
    byo = priv is None
    priv_str = priv or "<PASTE_THIS_DEVICES_PRIVATE_KEY>"
    client_config = render_template("wg-client.conf.j2", {
        "client_private_key": priv_str,
        "client_ip": client["ip"],
        "dns_server": config.get("network", {}).get("lan_ip", "10.0.1.1"),
        "server_public_key": vpn["server_public_key"],
        "endpoint": _client_endpoint(config),
        "vpn_port": vpn["port"],
    })

    click.echo("\n========== Client Configuration ==========")
    click.echo(client_config)
    click.echo("==========================================\n")

    if byo:
        click.echo(
            "This client uses its own key. Replace the PrivateKey placeholder "
            "with the device's private key (or paste only the [Peer] and\n"
            "Address/DNS lines into the tunnel you already created on the "
            "device). No QR is shown because the server has no private key."
        )
        return

    # Encode ONLY the functional lines in the QR. Comments/blank lines are
    # ignored by WireGuard but bloat the QR's density until it is too large
    # to fit the terminal and too fine to scan. Stripping them keeps the QR
    # small and scannable; the full commented config is still printed above.
    qr_config = "\n".join(
        line for line in client_config.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    if not shutil.which("qrencode"):
        click.echo("Tip: install qrencode to display a scannable QR code.")
        return

    if qr_file:
        try:
            subprocess.run(
                ["qrencode", "-o", qr_file, "-s", "8", "-m", "2"],
                input=qr_config, text=True, check=True,
            )
            click.echo(f"Wrote QR image to {qr_file} — open it on a screen and "
                       f"scan it with the WireGuard app (more reliable than the "
                       f"terminal QR below).\n")
        except (subprocess.CalledProcessError, OSError) as exc:
            click.echo(f"(Could not write QR image: {exc})")

    click.echo("QR code (scan with WireGuard mobile app):\n")
    try:
        subprocess.run(
            ["qrencode", "-t", "ansiutf8", "-m", "1"],
            input=qr_config, text=True, check=True,
        )
        click.echo()
    except (subprocess.CalledProcessError, OSError) as exc:
        click.echo(f"(Could not render QR code: {exc})")


def _find_client(config: dict, name: str):
    """Return the client entry with this name, or None."""
    for client in config.get("vpn", {}).get("clients", []):
        if client["name"] == name:
            return client
    return None


def admin_client_ips(config: dict) -> list:
    """VPN IPs of clients flagged as dashboard admins.

    Only these clients may reach the web dashboard over the tunnel; the
    firewall rule (nftables.conf.j2) is driven off this list. See set_admin.
    """
    return [c["ip"] for c in config.get("vpn", {}).get("clients", [])
            if c.get("admin")]


def set_admin(config: dict, name: str, admin: bool = True) -> dict:
    """Flag (or unflag) a VPN client as a dashboard admin.

    Admin clients are the only VPN peers allowed to reach the web dashboard
    (ports 80/443) over the tunnel; every other VPN user is denied by the
    firewall's default-drop policy. The caller must re-apply the firewall for
    the change to take effect (the CLI does this automatically).
    """
    client = _find_client(config, name)
    if not client:
        raise click.ClickException(
            f"No VPN client named '{name}'. See 'bardcastle-fw vpn clients'.")
    client["admin"] = admin
    click.echo(f"VPN client '{name}' ({client['ip']}) is now "
               f"{'a dashboard admin' if admin else 'not a dashboard admin'}.")
    events.emit_event("config_change", {
        "module": "vpn", "action": "set_admin",
        "client": name, "admin": admin,
    })
    return config


def list_clients(config: dict) -> None:
    """List VPN clients with their connection status."""
    import time

    clients = config.get("vpn", {}).get("clients", [])
    if not clients:
        click.echo("No VPN clients configured. Add one with "
                   "'bardcastle-fw vpn add-client <name>'.")
        return

    # Live peer data keyed by public key, from `wg show wg0 dump`.
    peers = {}
    result = run_cmd(["wg", "show", "wg0", "dump"], check=False)
    if result.returncode == 0:
        for line in result.stdout.strip().splitlines()[1:]:  # skip iface line
            f = line.split("\t")
            if len(f) >= 7:
                peers[f[0]] = {
                    "handshake": int(f[4]), "rx": int(f[5]), "tx": int(f[6]),
                }

    now = int(time.time())

    def ago(ts):
        if not ts:
            return "never"
        d = now - ts
        if d < 60:
            return f"{d}s ago"
        if d < 3600:
            return f"{d // 60}m ago"
        if d < 86400:
            return f"{d // 3600}h ago"
        return f"{d // 86400}d ago"

    def human(n):
        size = float(n)
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024 or unit == "GB":
                return f"{size:.0f}{unit}" if unit == "B" else f"{size:.1f}{unit}"
            size /= 1024
        return f"{n}B"

    rows = []
    for c in clients:
        p = peers.get(c["public_key"], {})
        hs = p.get("handshake", 0)
        online = "yes" if hs and (now - hs) < 180 else "no"
        transfer = f"{human(p.get('rx', 0))}/{human(p.get('tx', 0))}" if p else "-"
        admin = "yes" if c.get("admin") else "-"
        rows.append((c["name"], c["ip"], online, ago(hs), transfer, admin))

    headers = ("Name", "VPN IP", "Online", "Last handshake", "Rx/Tx", "Admin")
    widths = [max(len(str(r[i])) for r in (headers,) + tuple(rows))
              for i in range(len(headers))]

    # Colorize on a real terminal (green online / red offline); degrade
    # gracefully to plain text when piped or if jblib is unavailable.
    bold = green = red = off = ""
    if sys.stdout.isatty():
        try:
            from jblib import Color
            bold, green, red, off = (
                Color.BOLD, Color.GREEN, Color.RED, Color.OFF,  # pyright: ignore[reportAttributeAccessIssue]
            )
        except ImportError:
            pass

    header = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print(f"\n  {bold}{header}{off}")
    print("  " + "  ".join("-" * w for w in widths))
    for r in rows:
        color = green if r[2] == "yes" else red
        name = f"{color}{str(r[0]).ljust(widths[0])}{off}"
        online = f"{color}{str(r[2]).ljust(widths[2])}{off}"
        cells = [
            name,
            str(r[1]).ljust(widths[1]),
            online,
            str(r[3]).ljust(widths[3]),
            str(r[4]).ljust(widths[4]),
            str(r[5]).ljust(widths[5]),
        ]
        print("  " + "  ".join(cells))
    print()


def remove_client(config: dict, name: str) -> dict:
    """Revoke a VPN client: remove its peer and reload the server."""
    require_root()
    client = _find_client(config, name)
    if not client:
        click.echo(f"No VPN client named '{name}'.", err=True)
        return config

    config["vpn"]["clients"] = [
        c for c in config["vpn"]["clients"] if c["name"] != name
    ]
    _render_and_apply_server_config(config)
    run_cmd(["systemctl", "restart", "wg-quick@wg0"])
    save_config(config)

    # Drop the client's DNS name.
    _sync_vpn_hosts(config)

    events.emit_event("vpn_disconnect", {
        "client_name": name,
        "client_ip": client["ip"],
        "action": "revoked",
    })
    click.echo(f"Revoked VPN client '{name}' ({client['ip']}).")
    return config


def show_client(config: dict, name: str, qr_file: str | None = None) -> None:
    """Re-display an existing client's config and QR (no new key)."""
    client = _find_client(config, name)
    if not client:
        click.echo(f"No VPN client named '{name}'.", err=True)
        return
    _emit_client_config(config, client, qr_file=qr_file)


def rotate_client(config: dict, name: str, pubkey: str | None = None,
                  server_generate: bool = False) -> dict:
    """Re-key a client, keeping its name and IP.

    Default (strict) mode: the device generated a new keypair and supplies its
    new ``pubkey``; the server never sees the private key. Pass
    ``server_generate=True`` to have the server generate the new keypair.
    Either way the old public key is removed on reload, so the previous config
    stops working at once.
    """
    require_root()
    client = _find_client(config, name)
    if not client:
        click.echo(f"No VPN client named '{name}'.", err=True)
        return config

    if pubkey:
        client["public_key"] = _validate_pubkey(pubkey)
        client.pop("private_key", None)
        display_private = None
    else:
        display_private, new_public = _generate_keypair()
        client["public_key"] = new_public
        if server_generate:
            client["private_key"] = display_private
        else:
            client.pop("private_key", None)

    _render_and_apply_server_config(config)
    run_cmd(["systemctl", "restart", "wg-quick@wg0"])
    save_config(config)

    events.emit_event("config_change", {
        "module": "vpn",
        "action": "rotate_client",
        "client_name": name,
        "client_ip": client["ip"],
    })

    click.echo(f"\nRotated keys for '{name}'. The old config is now invalid — "
               f"load this new one:\n")
    _emit_client_config(config, client, private_key=display_private)
    return config


def rotate_all(config: dict) -> dict:
    """Re-key every server-managed client at once (server-compromise drill).

    Regenerates keypairs for all clients whose private key was stored on the
    server (the ones a server compromise would expose). Bring-your-own-key
    clients are left untouched and reported as safe, because their private
    keys never lived on the server.
    """
    require_root()
    clients = config.get("vpn", {}).get("clients", [])
    if not clients:
        click.echo("No VPN clients to rotate.")
        return config

    rotated, safe = [], []
    for client in clients:
        if _is_byo(client):
            safe.append(client)
            continue
        new_private, new_public = _generate_keypair()
        client["private_key"] = new_private
        client["public_key"] = new_public
        rotated.append(client)

    _render_and_apply_server_config(config)
    run_cmd(["systemctl", "restart", "wg-quick@wg0"])
    save_config(config)

    events.emit_event("config_change", {
        "module": "vpn",
        "action": "rotate_all",
        "rotated": [c["name"] for c in rotated],
        "unaffected": [c["name"] for c in safe],
    })

    click.echo(f"\nRotated {len(rotated)} server-managed client(s); "
               f"{len(safe)} bring-your-own-key client(s) left untouched.")
    if safe:
        click.echo("Unaffected (private key never on server): "
                   + ", ".join(c["name"] for c in safe))
    for client in rotated:
        click.echo(f"\n----- New config for '{client['name']}' -----")
        _emit_client_config(config, client)
    return config


def show_peers() -> None:
    """Display current WireGuard peer status."""
    click.echo("\n--- WireGuard Peers ---")
    result = run_cmd(["wg", "show"], capture=False, check=False)
    if result.returncode != 0:
        click.echo("WireGuard interface is not active or not configured.")
    click.echo()
