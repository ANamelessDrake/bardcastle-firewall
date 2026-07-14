"""Click CLI entry point for bardcastle-fw command."""

import click

from bardcastle.utils import load_config, save_config, require_root, prompt_reconfigure


class HelpfulGroup(click.Group):
    """A Group where 'help' works like '--help' at any level.

    Enables 'bardcastle-fw help', 'bardcastle-fw help dns',
    'bardcastle-fw dns help', and 'bardcastle-fw dns help queries'.
    """

    def resolve_command(self, ctx, args):
        if args and args[0] == "help":
            rest = args[1:]
            if rest:
                # 'help SUBCOMMAND' -> 'SUBCOMMAND --help' (recurses for groups)
                return super().resolve_command(ctx, rest + ["--help"])
            # bare 'help' -> show this group's help and exit
            click.echo(ctx.get_help())
            ctx.exit()
        name, cmd, rest = super().resolve_command(ctx, args)
        # 'GROUP LEAFCOMMAND help' -> 'LEAFCOMMAND --help'. (Subgroups handle
        # a trailing 'help' via their own resolve_command.)
        if rest and rest[-1] == "help" and not isinstance(cmd, click.Group):
            rest = rest[:-1] + ["--help"]
        return name, cmd, rest


@click.group(cls=HelpfulGroup)
@click.version_option(package_name="bardcastle-firewall")
def main():
    """Bardcastle Firewall - configure and manage an Ubuntu LTS router/firewall.

    A single tool that turns a stock Ubuntu Server box into a router:
    networking, an nftables firewall, DNS/DHCP, WireGuard VPN, threat-intel
    blocklists, an optional Suricata IDS, system hardening, and monitoring.

    Commands that change the system must be run as root (sudo).

    \b
    Common commands:
      bardcastle-fw setup            Run the full guided setup
      bardcastle-fw status           Show the system status dashboard
      bardcastle-fw dns leases       List DHCP leases
      bardcastle-fw dns queries -t   Top DNS lookups by domain/client

    Run 'bardcastle-fw COMMAND --help' (or 'GROUP COMMAND --help') for
    details on any command.
    """


@main.command()
def setup():
    """Run the full interactive setup wizard (all phases).

    Walks through every module in order - bootstrap, network, firewall,
    DNS/DHCP, VPN, blocklists, hardening, monitoring - prompting to
    [R]econfigure or [S]kip each one that is already configured. Safe to
    re-run; unchanged phases can be skipped.

    Requires root. Run from a local console, since the network phase
    briefly drops connectivity.
    """
    require_root()
    config = load_config()

    from bardcastle.bootstrap import run as bootstrap_run
    from bardcastle.network import setup as network_setup
    from bardcastle.firewall import apply as firewall_apply
    from bardcastle.dns_dhcp import setup as dns_setup
    from bardcastle.vpn import setup as vpn_setup
    from bardcastle.blocklists import update as blocklist_update, setup_cron
    from bardcastle.hardening import apply as hardening_apply
    from bardcastle.monitoring import setup as monitoring_setup

    phases = [
        ("bootstrap", bootstrap_run),
        ("network", network_setup),
        ("firewall", firewall_apply),
        ("dns", dns_setup),
        ("vpn", vpn_setup),
        ("blocklists", blocklist_update),
        ("hardening", hardening_apply),
        ("monitoring", monitoring_setup),
    ]

    for module_name, func in phases:
        if not prompt_reconfigure(module_name, config):
            continue

        try:
            config = func(config)
            save_config(config)
            click.echo(f"\n[OK] {module_name.capitalize()} completed.\n")
        except KeyboardInterrupt:
            click.echo(f"\n{module_name.capitalize()} interrupted.")
            save_config(config)
            raise SystemExit(1)
        except Exception as e:
            click.echo(f"\n[ERROR] {module_name.capitalize()} failed: {e}")
            if not click.confirm("Continue with next phase?", default=True):
                save_config(config)
                raise SystemExit(1)

    # Set up blocklist cron after all phases
    if config.get("configured", {}).get("blocklists"):
        setup_cron()

    save_config(config)
    click.echo("\nSetup complete. Run 'bardcastle-fw status' to verify.")


# -- Network subcommands --

@main.group(cls=HelpfulGroup)
def network():
    """Configure and inspect LAN/WAN networking (systemd-networkd)."""


@network.command("status")
def network_status_cmd():
    """Show networking service state and interface assignment."""
    require_root()
    from bardcastle.monitoring import network_status
    network_status(load_config())


@network.command("setup")
def network_setup_cmd():
    """Detect NICs and configure WAN (DHCP) and LAN (static) interfaces.

    Writes systemd-networkd .network files, enables IP forwarding, and
    records the interface assignment in the config. Requires root.
    """
    require_root()
    config = load_config()
    from bardcastle.network import setup as network_setup
    config = network_setup(config)
    save_config(config)
    click.echo("\n[OK] Network configured.")


# -- Firewall subcommands --

@main.group(cls=HelpfulGroup)
def firewall():
    """Manage the nftables firewall ruleset."""


@firewall.command("status")
def firewall_status_cmd():
    """Show firewall service state, blocklist size, and drop counters."""
    require_root()
    from bardcastle.monitoring import firewall_status
    firewall_status(load_config())


@firewall.command("apply")
def firewall_apply_cmd():
    """Render and apply the nftables ruleset from config.

    Regenerates /etc/nftables.conf from the template, validates it with a
    dry run, then applies and enables it. Requires root.
    """
    require_root()
    config = load_config()
    from bardcastle.firewall import apply as firewall_apply
    config = firewall_apply(config)
    save_config(config)
    click.echo("\n[OK] Firewall rules applied.")


@firewall.command("rules")
def firewall_rules_cmd():
    """Show a readable table of filter rules (interface/proto/port/action).

    Requires root.
    """
    require_root()
    from bardcastle.firewall import show_rules
    show_rules(load_config())


@firewall.command("show")
def firewall_show_cmd():
    """Print the live nftables ruleset (raw). Requires root."""
    from bardcastle.firewall import show
    show()


# -- DNS subcommands --

@main.group(cls=HelpfulGroup)
def dns():
    """DNS and DHCP services (dnsmasq): setup, leases, and query log."""


@dns.command("status")
def dns_status_cmd():
    """Show DNS/DHCP service state, upstreams, leases, and logging."""
    require_root()
    from bardcastle.monitoring import dns_status
    dns_status(load_config())


@dns.command("setup")
def dns_setup_cmd():
    """Configure dnsmasq for DNS forwarding and LAN DHCP.

    Prompts for upstream DNS servers, renders the dnsmasq config, installs
    the DHCP event hook, and starts the service. Requires root.
    """
    require_root()
    config = load_config()
    from bardcastle.dns_dhcp import setup as dns_setup
    config = dns_setup(config)
    save_config(config)
    click.echo("\n[OK] DNS/DHCP configured.")


@dns.command("leases")
def dns_leases_cmd():
    """List DHCP leases with online status and readable expiry.

    Shows every current lease, marks which devices are reachable right now
    (green = online, red = absent), and prints human-readable expiry times.
    """
    from bardcastle.dns_dhcp import show_leases
    show_leases()


@dns.command("queries")
@click.option("-c", "--client", help="Only show queries from this IP or hostname.")
@click.option("-d", "--domain", help="Only show queries whose name contains this string.")
@click.option("-n", "--limit", default=50, show_default=True,
              help="Number of recent queries to show.")
@click.option("-f", "--follow", is_flag=True, help="Stream queries live (Ctrl-C to stop).")
@click.option("-t", "--top", is_flag=True, help="Summarize top domains and clients instead.")
def dns_queries_cmd(client, domain, limit, follow, top):
    """Browse the DNS query log (needs 'log-queries' enabled).

    Shows which domains each client looked up. By default prints the most
    recent queries; use the options to filter, follow live, or summarize.
    Requires root (reads the system journal).

    \b
    Examples:
      bardcastle-fw dns queries                 Recent queries
      bardcastle-fw dns queries -f              Live tail
      bardcastle-fw dns queries -c Galaxy-S22   One device (name or IP)
      bardcastle-fw dns queries -d instagram    Filter by domain
      bardcastle-fw dns queries --top           Top domains and clients
    """
    require_root()
    from bardcastle.dns_dhcp import show_queries
    show_queries(client=client, domain=domain, limit=limit, follow=follow, top=top)


# -- VPN subcommands --

@main.group(cls=HelpfulGroup)
def vpn():
    """WireGuard VPN server setup and client management."""


@vpn.command("status")
def vpn_status_cmd():
    """Show WireGuard service state, port, and active peers."""
    require_root()
    from bardcastle.monitoring import vpn_status
    vpn_status(load_config())


@vpn.command("setup")
def vpn_setup_cmd():
    """Set up the WireGuard VPN server.

    Generates the server keypair, writes the wg0 interface config, opens
    the VPN port in the firewall, and starts the tunnel. Requires root and
    a reachable WAN address/port.
    """
    require_root()
    config = load_config()
    from bardcastle.vpn import setup as vpn_setup
    config = vpn_setup(config)
    save_config(config)
    click.echo("\n[OK] VPN configured.")


@vpn.command("add-client")
@click.argument("name", metavar="NAME")
@click.option("--pubkey", default=None,
              help="Bring-your-own-key: the device's public key. The printed "
                   "config carries a placeholder and the private key never "
                   "touches the server (most secure).")
@click.option("--server-key", "server_key", is_flag=True,
              help="Also store the generated private key so 'show-client' can "
                   "reprint the config later.")
def vpn_add_client_cmd(name, pubkey, server_key):
    """Create a new VPN client and print a ready-to-use config and QR code.

    NAME is a label for the client (e.g. 'phone', 'laptop').

    By default the server generates the keypair and prints a complete config
    (with QR), but stores only the public key - the private key is shown once
    and then discarded. Use --pubkey for bring-your-own-key (the private key
    never touches the server), or --server-key to also store the key so it can
    be reprinted later. Requires root.
    """
    require_root()
    config = load_config()
    from bardcastle.vpn import add_client
    config = add_client(config, name, pubkey=pubkey, server_generate=server_key)
    save_config(config)


@vpn.command("peers")
def vpn_peers_cmd():
    """Show WireGuard peers and their last handshake times. Requires root."""
    from bardcastle.vpn import show_peers
    show_peers()


@vpn.command("clients")
def vpn_clients_cmd():
    """List VPN clients with their connection status. Requires root."""
    require_root()
    from bardcastle.vpn import list_clients
    list_clients(load_config())


@vpn.command("admin")
@click.argument("name", metavar="NAME")
@click.option("--revoke", is_flag=True,
              help="Remove dashboard-admin access from this client instead.")
def vpn_admin_cmd(name, revoke):
    """Grant (or revoke) web-dashboard access over the VPN for a client.

    NAME is the VPN client. Only clients granted admin may reach the dashboard
    (ports 80/443) through the tunnel; all other VPN users are denied. The
    firewall is re-applied immediately so the change takes effect. Requires
    root.
    """
    require_root()
    config = load_config()
    from bardcastle.vpn import set_admin
    config = set_admin(config, name, admin=not revoke)
    save_config(config)
    # Re-apply the firewall so the wg0 dashboard allowlist reflects the change.
    from bardcastle.firewall import apply as firewall_apply
    firewall_apply(config)


@vpn.command("show-client")
@click.argument("name", metavar="NAME")
@click.option("--qr-file", default=None, metavar="PATH",
              help="Also write a PNG QR to PATH (easier to scan than the "
                   "terminal QR).")
def vpn_show_client_cmd(name, qr_file):
    """Re-display an existing client's config and QR code (no new key).

    NAME is the client to re-provision. Use --qr-file to save a scannable
    PNG. Requires root.
    """
    require_root()
    from bardcastle.vpn import show_client
    show_client(load_config(), name, qr_file=qr_file)


@vpn.command("remove-client")
@click.argument("name", metavar="NAME")
def vpn_remove_client_cmd(name):
    """Revoke a VPN client and reload the server.

    NAME is the client to remove; its access is cut immediately. Requires root.
    """
    require_root()
    config = load_config()
    from bardcastle.vpn import remove_client
    config = remove_client(config, name)
    save_config(config)


@vpn.command("rotate-client")
@click.argument("name", metavar="NAME")
@click.option("--pubkey", default=None,
              help="Bring-your-own-key: the device's new public key.")
@click.option("--server-key", "server_key", is_flag=True,
              help="Also store the generated private key.")
def vpn_rotate_client_cmd(name, pubkey, server_key):
    """Re-key a client, keeping its name and IP.

    NAME is the client to re-key. The old config stops working immediately.
    By default the server generates the new key and prints a complete config
    without storing the private key; --pubkey takes a device-generated key,
    and --server-key also stores the new key. Requires root.
    """
    require_root()
    config = load_config()
    from bardcastle.vpn import rotate_client
    rotate_client(config, name, pubkey=pubkey, server_generate=server_key)


@vpn.command("rotate-all")
@click.confirmation_option(
    prompt="Re-key every server-managed VPN client? All their current configs "
           "will stop working until redistributed.")
def vpn_rotate_all_cmd():
    """Re-key all server-managed clients at once (server-compromise drill).

    Regenerates keys for every client whose private key was stored on the
    server. Bring-your-own-key clients are left untouched. Requires root.
    """
    require_root()
    config = load_config()
    from bardcastle.vpn import rotate_all
    rotate_all(config)


# -- Blocklist subcommands --

@main.group(cls=HelpfulGroup)
def blocklist():
    """Threat-intelligence IP blocklists (CrowdSec + FireHOL)."""


@blocklist.command("status")
def blocklist_status_cmd():
    """Show blocklist sizes, last refresh, cron, and CrowdSec bans."""
    require_root()
    from bardcastle.monitoring import blocklist_status
    blocklist_status(load_config())


@blocklist.command("update")
def blocklist_update_cmd():
    """Download and load IP blocklists into the firewall.

    Refreshes CrowdSec (if installed) and the FireHOL level-1 netset,
    filters out private/reserved ranges, and loads the result into the
    nftables blocklist set. Runs nightly via cron once configured.
    Requires root.
    """
    require_root()
    config = load_config()
    from bardcastle.blocklists import update
    config = update(config)
    save_config(config)
    click.echo("\n[OK] Blocklists updated.")


@blocklist.command("stats")
def blocklist_stats_cmd():
    """Show blocklist sizes and recent block activity."""
    from bardcastle.blocklists import show_stats
    show_stats()


# -- IDS subcommands --

@main.group(cls=HelpfulGroup)
def ids():
    """Optional Suricata intrusion detection / prevention."""


@ids.command("status")
def ids_status_cmd():
    """Show IDS/IPS state: Suricata and CrowdSec, with active bans."""
    require_root()
    from bardcastle.monitoring import ids_status
    ids_status(load_config())


@ids.command("decisions")
def ids_decisions_cmd():
    """List sources CrowdSec is currently blocking. Requires root."""
    require_root()
    from bardcastle.blocklists import show_decisions
    show_decisions()


@ids.command("alerts")
@click.option("-n", "--limit", default=25, show_default=True,
              help="Number of recent alerts to show.")
def ids_alerts_cmd(limit):
    """Show recent CrowdSec detection alerts (with GeoIP). Requires root."""
    require_root()
    from bardcastle.blocklists import show_alerts
    show_alerts(limit=limit)


@ids.command("scenarios")
def ids_scenarios_cmd():
    """List enabled CrowdSec detection scenarios. Requires root."""
    require_root()
    from bardcastle.blocklists import show_scenarios
    show_scenarios()


@ids.command("metrics")
def ids_metrics_cmd():
    """Show CrowdSec engine metrics (acquisition, buckets, bouncers). Requires root."""
    require_root()
    from bardcastle.blocklists import show_metrics
    show_metrics()


@ids.command("enable")
def ids_enable_cmd():
    """Install and enable the Suricata IDS on the WAN interface.

    Configures Suricata for inline IPS, downloads the ET Open ruleset, and
    starts the service. Memory-hungry - intended for boxes with RAM to
    spare. Requires root.
    """
    require_root()
    config = load_config()
    from bardcastle.blocklists import enable_ids
    config = enable_ids(config)
    save_config(config)
    click.echo("\n[OK] Suricata IDS enabled.")


@ids.command("disable")
def ids_disable_cmd():
    """Stop and disable the Suricata IDS service. Requires root."""
    require_root()
    config = load_config()
    from bardcastle.blocklists import disable_ids
    config = disable_ids(config)
    save_config(config)
    click.echo("\n[OK] Suricata IDS disabled.")


# -- Dynamic DNS subcommands --

@main.group(cls=HelpfulGroup)
def ddns():
    """Dynamic DNS: keep a Route 53 record on the current public IP."""


@ddns.command("setup")
def ddns_setup_cmd():
    """Configure the hostname, hosted zone, and credentials. Requires root."""
    require_root()
    config = load_config()
    from bardcastle.ddns import setup as ddns_setup
    ddns_setup(config)


@ddns.command("update")
def ddns_update_cmd():
    """Update the record to the current public IP if it changed. Requires root."""
    require_root()
    config = load_config()
    from bardcastle.ddns import update as ddns_update
    ddns_update(config)


@ddns.command("status")
def ddns_status_cmd():
    """Show DDNS config and whether the record is in sync. Requires root."""
    require_root()
    config = load_config()
    from bardcastle.ddns import status as ddns_status
    ddns_status(config)


# -- Web dashboard subcommands --

@main.group(cls=HelpfulGroup)
def webui():
    """Local web dashboard (read-only)."""


@webui.command("set-password")
def webui_set_password_cmd():
    """Set the dashboard login password. Requires root."""
    require_root()
    import subprocess
    pw = click.prompt("Dashboard password", hide_input=True,
                      confirmation_prompt=True)
    # Write the password file as the service user so the running dashboard
    # (which runs as bardcastle-web) can read it.
    proc = subprocess.run(
        ["sudo", "-u", "bardcastle-web",
         "/opt/bardcastle-webui/venv/bin/python", "auth.py", "set-password"],
        input=pw + "\n", text=True, cwd="/opt/bardcastle-firewall/webui/backend",
    )
    if proc.returncode != 0:
        raise SystemExit(1)
    click.echo("Password set. The dashboard is at https://<lan-ip>/")


@webui.command("status")
def webui_status_cmd():
    """Show the dashboard service status. Requires root."""
    require_root()
    from bardcastle.utils import run_cmd
    for unit in ("bardcastle-webui.service", "bardcastle-webui-redirect.service"):
        r = run_cmd(["systemctl", "is-active", unit], check=False)
        click.echo(f"  {unit:<36} {r.stdout.strip()}")


# -- Status command --

@main.command()
def status():
    """Show the system status dashboard.

    Interfaces, DHCP leases, WireGuard peers, firewall drop counters,
    CrowdSec decisions, blocklist size, bandwidth, and resource usage in a
    single overview. Requires root (reads root-only config and counters).
    """
    config = load_config()
    from bardcastle.monitoring import show_status
    show_status(config)


if __name__ == "__main__":
    main()
