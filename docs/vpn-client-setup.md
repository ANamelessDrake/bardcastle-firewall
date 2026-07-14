# Bardcastle Firewall - VPN Setup Guide

This guide covers connecting a device to the company WireGuard VPN so you can
reach internal resources from anywhere.

It has two parts:

- **For employees** (below): set up the VPN on your own device. This is the
  part you follow. It uses no administrator or firewall commands.
- **For administrators**: provision a client on the firewall. Employees do not
  need this section.

---

# For employees: connect your device

Your IT administrator provisions your access one of two ways, and how you set
up depends on which they used:

- **Option A:** they send you a **QR code or a configuration file** to import.
- **Option B:** they ask you to **generate a key on your device** and send
  them the public part.

Follow whichever option matches what IT gave you. In both cases, install the
WireGuard app first.

## Install WireGuard

Install the official WireGuard software for your operating system. WireGuard
is free and open source; only install it from the official sources below.

### Windows

1. Open <https://www.wireguard.com/install/> in a browser.
2. Under "Windows", click **Download Windows Installer** (a `.exe` file).
3. Run the downloaded installer and accept the prompts. WireGuard opens when
   it finishes.
4. If Windows asks whether to allow WireGuard through the firewall, allow it.

### macOS

1. Open the **App Store**.
2. Search for **WireGuard** (by "WireGuard Development Team") and click **Get**
   or the install button.
3. Open the app once it installs. If prompted, allow it to add VPN
   configurations.

(Advanced/CLI users can instead run `brew install wireguard-tools`.)

### iOS / iPadOS

1. Open the **App Store**.
2. Search for **WireGuard** (by "WireGuard Development Team") and tap **Get**.
3. Open the app. When you later add a tunnel, tap **Allow** if iOS asks to add
   VPN configurations.

### Android

1. Open the **Google Play Store**.
2. Search for **WireGuard** (by "WireGuard Development Team") and tap
   **Install**.
3. Open the app. Allow it to add a VPN configuration when prompted.

### Linux

Install the WireGuard tools with your distribution's package manager, then
verify:

- **Debian / Ubuntu / Raspberry Pi OS:**

  ```bash
  sudo apt update && sudo apt install -y wireguard
  ```

- **Fedora:**

  ```bash
  sudo dnf install -y wireguard-tools
  ```

- **RHEL / CentOS / Rocky / AlmaLinux** (enable EPEL first):

  ```bash
  sudo dnf install -y epel-release && sudo dnf install -y wireguard-tools
  ```

- **Arch / Manjaro:**

  ```bash
  sudo pacman -S wireguard-tools
  ```

- **openSUSE:**

  ```bash
  sudo zypper install wireguard-tools
  ```

Confirm it installed:

```bash
wg --version
```

Desktop Linux users get a graphical on/off toggle for free: NetworkManager
(built into GNOME, KDE Plasma, and most desktops) supports WireGuard natively,
so you can import the config and manage the tunnel from the network menu. See
the "Linux desktop (GUI)" steps under Option A below. The command-line steps
also work everywhere.

## Option A: You received a QR code or config file

**iOS / Android (QR code):**

1. Open the WireGuard app.
2. Tap **+**, then **Create from QR code**.
3. Scan the QR code IT sent you.
4. Give the tunnel a name and enable it.

**iOS / Android (config file):**

1. Save the `.conf` file IT sent you to your device.
2. In the WireGuard app, tap **+**, then **Create from file or archive**, and
   pick the file.
3. Enable the tunnel.

**Windows / macOS:**

1. Save the `.conf` file IT sent you.
2. Open the WireGuard app and choose **Import tunnel(s) from file** (on macOS
   you can also drag the file into the window).
3. Select the tunnel and click **Activate**.

**Linux desktop (GUI, recommended):** on any desktop that uses
NetworkManager (GNOME, KDE Plasma, Cinnamon, XFCE, and most others), import
the config once and then turn the VPN on and off from the network menu, no
terminal needed. Save the `.conf` IT sent you to
`/etc/wireguard/bardcastle-vpn.conf`, then either:

- Import from the command line once:

  ```bash
  nmcli connection import type wireguard file /etc/wireguard/bardcastle-vpn.conf
  ```

- Or import through the settings app:
  - **GNOME:** Settings > Network > VPN > **+** > **Import from file**, pick the `.conf`.
  - **KDE Plasma:** System Settings > Connections > **+** > **Import VPN connection**, pick the `.conf`.

After importing, toggle the tunnel from the system tray / network menu (in
GNOME, the top-right Quick Settings; in KDE, the network widget).

**Auto-connect on boot:** an imported connection is set to connect
automatically by default, so NetworkManager will bring the VPN up on every
boot. For a laptop this is usually not what you want (you do not want a
full-tunnel VPN active at home or on trusted networks). To make it on-demand
instead, disable auto-connect:

```bash
nmcli connection modify bardcastle-vpn connection.autoconnect no
```

Or in the GUI: **KDE** System Settings > Connections > the connection > uncheck
**Connect automatically**; **GNOME** Settings > Network > the VPN's gear icon >
turn off **Connect automatically**. Then it only comes up when you toggle it.

**Auto-connect everywhere except home (optional):** to have the VPN come up
automatically whenever you are away but stay down on the home network, add a
NetworkManager dispatcher script. It runs on every network change and brings
the tunnel up unless the machine holds a home-LAN address (`10.0.1.x`). Turn
off the plain auto-connect above first, then create
`/etc/NetworkManager/dispatcher.d/50-bardcastle-vpn`, owned by root with mode
`0755`:

```bash
#!/bin/bash
# NetworkManager dispatcher: auto-connect the VPN except on the home LAN.
interface="$1"; action="$2"; VPN="bardcastle-vpn"
[ "$interface" = "$VPN" ] && exit 0
case "$action" in
    up|connectivity-change|dhcp4-change)
        if ip -4 addr show | grep -q 'inet 10\.0\.1\.'; then
            nmcli connection down "$VPN" >/dev/null 2>&1 || true
        else
            nmcli connection up   "$VPN" >/dev/null 2>&1 || true
        fi ;;
esac
```

Adjust the `10.0.1.` subnet and the `bardcastle-vpn` name if yours differ.

Do not also run `wg-quick up` for the same tunnel; let NetworkManager manage
it so the GUI toggle stays in sync.

**Linux (command line):** if you prefer the terminal or are on a headless
machine, save the config to `/etc/wireguard/bardcastle-vpn.conf` (the file's
name before `.conf` is the tunnel name `wg-quick` uses):

```bash
# save the config IT sent you as /etc/wireguard/bardcastle-vpn.conf, then:
sudo chmod 600 /etc/wireguard/bardcastle-vpn.conf
sudo wg-quick up bardcastle-vpn
sudo systemctl enable wg-quick@bardcastle-vpn   # optional: reconnect at boot
```

Skip to "Verify you are connected" below.

## Option B: You were asked for a public key

In this option your private key never leaves your device, which is the more
secure setup.

### 1. Generate a keypair on your device

**Windows:** open the WireGuard app, click **Add Tunnel**, then **Add empty
tunnel**. It fills in a `PrivateKey` and shows a **Public key** at the top.
Copy the public key. Leave this window open; you finish in step 3.

**macOS:** open the WireGuard app, click **+**, then **Add empty tunnel**. Copy
the **Public key** it shows.

**iOS / Android:** in the WireGuard app, tap **+**, then **Create from
scratch**. Copy the **Public key** it shows.

**Linux:**

```bash
wg genkey | tee privatekey | wg pubkey > publickey
cat publickey   # copy this value
```

### 2. Send IT your public key

Send your administrator **only the public key**, along with your name and what
device it is (for example "laptop" or "phone"). Never send your private key;
it stays on your device.

### 3. Finish the config IT sends back

IT replies with a configuration that has a `PrivateKey` placeholder. Put your
own private key in its place:

**Windows / macOS:** in the empty tunnel you created in step 1, replace its
contents with the config IT sent, but keep the `PrivateKey` line the app
already generated. Save, then activate the tunnel.

**iOS / Android:** in the tunnel you created in step 1, add the `[Peer]` block
and the `Address` and `DNS` lines from the config IT sent. Leave the
`PrivateKey` the app generated. Save and enable it.

**Linux:** save the config to `/etc/wireguard/bardcastle-vpn.conf` and replace
the `PrivateKey` placeholder with the contents of the `privatekey` file from
step 1. Then either import it into NetworkManager for a GUI toggle (see the
"Linux desktop (GUI)" steps under Option A) or bring it up from the terminal:

```bash
sudo chmod 600 /etc/wireguard/bardcastle-vpn.conf
sudo wg-quick up bardcastle-vpn
sudo systemctl enable wg-quick@bardcastle-vpn   # optional: reconnect at boot
```

## Verify you are connected

- On mobile, the tunnel shows as active and the data counters climb.
- On desktop, `sudo wg show` (Linux/macOS CLI) or the app shows a recent
  handshake.
- Try reaching an internal resource your administrator told you to test.

If it does not connect, tell IT which step failed and what error you saw. Do
not troubleshoot the firewall yourself; that is on the administrator's side.

## Keep your key safe

- Never share your private key or send it over email or chat.
- If your device is lost or stolen, tell IT immediately so they can revoke it.
- Do not copy one device's config to another. Each device gets its own key.

---

# For administrators: provision a client

Everything in this section runs **on the firewall** over SSH and requires
`sudo`. Employees do not run any of it.

## Naming convention

Name each client for the person who owns it, using their **first initial and
last name**. For John Smith, that is `jsmith`. If someone has more than one
device, add the device type: `jsmith-laptop`, `jsmith-phone`. Consistent names
make `vpn clients` easy to read and make it obvious whose access to revoke.

## Provision the client

There are three modes, differing only in where the key is made and whether the
server keeps it.

### Default: server generates, key not stored (recommended)

```bash
sudo bardcastle-fw vpn add-client jsmith
```

The firewall generates the keypair, assigns an IP, and prints a **complete,
ready-to-use config plus a QR code**. It stores only the public key; the
private key is shown once and then discarded. Send the config (Option A above)
to the employee to import or scan.

For a reliable QR to send, write a PNG and share that image:

```bash
sudo bardcastle-fw vpn show-client jsmith --qr-file /tmp/jsmith.png
```

Note: because the private key is not kept, `show-client` cannot reprint a
default client's config later. If a config is lost, rotate the client to issue
a fresh one.

### Bring-your-own-key (most secure)

```bash
sudo bardcastle-fw vpn add-client jsmith --pubkey <employee-public-key>
```

The employee generates the keypair on their device (Option B above) and sends
you only the public key. The printed config carries a `PrivateKey` placeholder
that the employee fills in; the private key never touches the server.

### Server-generated and stored (reprintable)

```bash
sudo bardcastle-fw vpn add-client jsmith --server-key
```

Same as the default, but the server also keeps the private key so you can
reprint the config or QR anytime with `show-client`. The trade-off is that a
server compromise would expose every stored key.

## Managing clients

```bash
sudo bardcastle-fw vpn clients            # list clients: online status, last handshake, data used, admin
sudo bardcastle-fw vpn status             # server overview (service, port, active peers)
sudo bardcastle-fw vpn show-client NAME   # reprint a server-generated client's config/QR
sudo bardcastle-fw vpn admin NAME         # allow this client to reach the web dashboard over the VPN
sudo bardcastle-fw vpn admin NAME --revoke # remove that dashboard access
sudo bardcastle-fw vpn rotate-client NAME # re-key a client (old config stops working at once)
sudo bardcastle-fw vpn remove-client NAME # revoke a client immediately (lost device, offboarding)
sudo bardcastle-fw vpn rotate-all         # re-key every server-managed client (compromise drill)
```

**Dashboard access over the VPN:** by default no VPN client can reach the web
dashboard (ports 80/443) through the tunnel. Grant it per client with `vpn
admin NAME`; only those clients are allowed, every other VPN user is denied by
the firewall's default-drop policy. The command re-applies the firewall
immediately, and the `Admin` column in `vpn clients` shows who has access.
Dashboard access is independent of SSH: VPN users still have no shell access
(only your account holds an SSH key), and revoking admin does not disconnect
the VPN, it only closes the dashboard ports for that client.

**Offboarding or a lost device:** run `remove-client NAME`. It removes the
peer's public key from the server, so that device can no longer connect. This
works for both key modes and needs nothing from the device.

**Rotating a key:** `rotate-client` keeps the client's name and IP but issues
a new key and prints a complete config, without storing the key (like the
default `add-client`). Use `--pubkey` for a device-generated key, or
`--server-key` to also store it.

**After a suspected server compromise:** run `rotate-all`. It re-keys every
client whose private key was stored on the server (that is, only clients
created with `--server-key`) and prints new configs to redistribute. Clients
whose key was never stored - the default and bring-your-own-key clients - are
left untouched and reported as safe.

## Reaching clients by name

Each VPN client is published in DNS under two names pointing at its VPN IP,
where `<name>` is the label you gave it in `add-client`: the full
`<name>.vpn.<domain>` and the short `<name>.vpn`. For a client `jsmith` on the
`example.com` network, that is `jsmith.vpn.example.com` and
`jsmith.vpn`. Both are served directly by the firewall's DNS (the `.vpn`
pseudo-TLD is treated as local), so they resolve without any search-domain
setup on the client. This is maintained automatically: `add-client` adds the
records and `remove-client` removes them, so the names always match the
current client list.

So you can reach a client by either name instead of hunting for its IP:

```bash
ssh someuser@jsmith.vpn.example.com
ssh someuser@jsmith.vpn
```

Notes:

- These names resolve on **any device that uses the firewall for DNS**: every
  LAN device (they are handed `10.0.1.1` as their resolver via DHCP) and every
  connected VPN client. It is not per-machine setup; the firewall's DNS answers
  the query. A device pointed at a different DNS server (or using
  DNS-over-HTTPS) will not resolve these names, since `.vpn` is local to this
  network and does not exist in public DNS.
- The name is the **`add-client` label**, not the device's own hostname. To
  reach a client as `test.vpn`, create it as `add-client test`. Use DNS-safe
  labels (letters, digits, hyphens).
- The firewall permits full communication to VPN clients: LAN hosts can reach
  them, and VPN clients can reach each other and the LAN. `bardcastle-fw vpn
  clients` still shows the name-to-IP mapping if you prefer the IP.

## What the client config contains

```ini
[Interface]
PrivateKey = <client private key>
Address    = 10.10.10.2/24        # this client's VPN address
DNS        = 10.0.1.1             # resolves internal hostnames over the VPN

[Peer]
PublicKey           = <server public key>
Endpoint            = vpn.example.com:51820   # the firewall's DDNS hostname
AllowedIPs          = 0.0.0.0/0, ::/0             # full tunnel: all traffic via the company
PersistentKeepalive = 25
```

`AllowedIPs = 0.0.0.0/0, ::/0` means **full tunnel**, so all of the device's
traffic routes through the company network. For split tunnel (reach only
internal resources, with personal traffic going out directly), replace it with
the internal subnets, for example `10.0.1.0/24, 10.10.10.0/24`.

## Verifying and troubleshooting (admin)

```bash
sudo bardcastle-fw vpn clients
```

A working client shows `Online: yes` and a recent handshake once it connects.

- **Test from outside the company network** (for example cellular data). You
  generally cannot test the external path from inside the network.
- **No handshake:** confirm UDP `51820` is forwarded on the upstream
  router/gateway to the firewall's WAN IP, and that `vpn.example.com`
  resolves to the current public IP (`sudo bardcastle-fw ddns status`).
- **Connected but no internal access (full tunnel):** check the firewall's NAT
  and that `DNS = 10.0.1.1` is set in the client config.
- **Was working, now dead:** the client's key may have been rotated or the
  client revoked. Re-provision with a fresh config.
