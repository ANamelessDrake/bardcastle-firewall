# Bardcastle Firewall - Device Policy Design

Design for two related capabilities:

1. **New device detection.** Know when something joins the network that has not
   been seen before.
2. **Per-device content policy.** Apply age-appropriate DNS filtering to a
   named device rather than to the whole LAN.

This is a design document, not an implementation record. Nothing described here
is built yet. Section 9 is the rollout order.

## Contents

- [1. Purpose and scope](#1-purpose-and-scope)
- [2. Goals and non-goals](#2-goals-and-non-goals)
- [3. What already exists](#3-what-already-exists)
- [4. Device identity](#4-device-identity)
- [5. New device detection](#5-new-device-detection)
- [6. DNS enforcement](#6-dns-enforcement)
- [7. Bypass analysis](#7-bypass-analysis)
- [8. Controls to pair this with](#8-controls-to-pair-this-with)
- [9. Rollout and rollback](#9-rollout-and-rollback)
- [10. Open questions](#10-open-questions)

## 1. Purpose and scope

The router already sees every DNS query and every DHCP lease on the LAN. Both
features are about attaching an identity to that traffic: turning "10.0.1.147
looked up example.com" into "this person's tablet looked up example.com", and
then acting on it.

In scope: DNS-layer content policy per device, and first-sight device
detection with an event surfaced in the existing dashboard.

Out of scope: transparent TLS interception, per-application control, time
accounting, and any form of content inspection. Those need an agent on the
device or a CA installed on it, which is a different project with a much
worse failure mode.

## 2. Goals and non-goals

**Goals**

- A device can be assigned a named policy, and the policy is enforced whether
  or not the device cooperates.
- Policy state is declarative and survives a config re-render, like every other
  subsystem here.
- An unrecognised device produces exactly one event, not one per lease renewal.
- No personal data (device owners, people's names) enters the repository.
- The failure mode is restrictive, not permissive. See section 4.

**Non-goals**

- Defeating a determined, technically capable user. Section 7 is explicit about
  this. A network filter is a speed bump; if the goal is to stop someone who is
  actively trying to get around it, this is the wrong layer and section 8 is the
  right one.
- Filtering inside a site. DNS sees `youtube.com`, not which video.
- Covering a device that is not on this network. A phone on cellular data is
  outside the router's view entirely.

## 3. What already exists

More of this is scaffolded than it first appears.

| Piece | State |
|---|---|
| `new_device` event type | Declared in `events.py`. Never emitted. |
| Dashboard rendering for it | Done. `describeEvent` handles `new_device` and it has its own style. No frontend work needed. |
| DHCP event hook | Installed at `/usr/local/bin/bardcastle-dhcp-hook`, wired via `dhcp-script`. Emits a generic `dhcp_lease` for every action. |
| Static reservation file | `dhcp-hostsfile=/var/lib/bardcastle/dhcp-hosts` is referenced by the dnsmasq template and managed by nothing. Currently hand-edited. |
| Per-device DNS visibility | `log-queries` is on and the dashboard already has a per-host DNS drill-down. |
| Firewall as single chokepoint | `nftables.conf.j2` is re-rendered wholesale and validated with `nft -c -f` before apply. An `ip nat prerouting` chain already exists. |

Two measurements that shaped this design:

- **The event log is mostly noise.** Of 3,887 events, 3,405 are `dhcp_lease`
  with action `old`, which is a lease renewal. 88 percent of the log carries no
  information. A `new_device` event only means something if renewals stop being
  logged as events.
- **Memory is not a constraint.** `docs/architecture.md` describes a 2 GB RAM
  budget driving component choices such as dnsmasq over BIND. The current
  appliance has 31,870 MB with roughly 1,100 MB in use, and dnsmasq's resident
  size is 3.4 MB. That budget statement is stale and should not be used to rule
  out a second resolver instance. The architecture doc should be corrected
  separately.

## 4. Device identity

This is where the design nearly goes wrong, so it comes before the enforcement
mechanics.

### The obvious approach, and why it is not enough

dnsmasq already supports tagging a host by MAC. The reservation file format
extends naturally:

```
# /var/lib/bardcastle/dhcp-hosts
# <mac>,set:<policy>,<reserved-ip>,<name>
aa:bb:cc:dd:ee:ff,set:restricted,10.0.1.50,some-tablet
```

and the tag can then drive a DHCP option:

```
dhcp-option=tag:restricted,option:dns-server,<filtered resolver>
```

Keeping the mapping in `/var/lib/bardcastle/dhcp-hosts` rather than in the
template follows the convention the template already documents: device-to-owner
mappings and reserved IPs survive config re-renders and never carry personal
data into the repo. Policy *definitions* (what `restricted` means) are not
personal and belong in `config.yaml`.

### Why MAC identity is unreliable here

This was measured on the live network, not assumed. Of 34 distinct MACs seen
via DHCP, **13 are locally administered**, meaning randomized rather than
hardware OUI addresses. More pointedly:

- One device has appeared under **three different MACs** over time, and another
  under two, identifiable because the DHCP hostname stayed the same.
- The single reservation currently pinned by hand in `dhcp-hosts` is itself a
  randomized MAC, so that pin will silently stop matching when the device next
  rotates.

iOS 14+ and Android 10+ randomize the MAC per SSID by default, and rotate it
periodically. A user can also force a new one by toggling the private address
setting, which takes two taps and requires no technical knowledge.

### The consequence: invert the default

If policy is keyed to a known MAC and unknown devices are unfiltered, then MAC
rotation is an escape hatch, and it is one the device may take on its own
without anyone intending it. The filter would fail open, quietly.

So the default must be inverted:

- An **unknown** device gets the restrictive policy.
- Only devices on an explicit allowlist get unrestricted DNS.

Then a rotation moves a device *into* the restricted bucket, which is visible
and annoying rather than invisible and permissive. A device that matters gets
its randomization disabled for this SSID and a real reservation, once.

This has a cost worth stating plainly: every guest phone lands on the filtered
resolver until someone allows it. For a household that is probably correct. If
it is not, the alternative is a separate SSID per policy, which moves the
enforcement boundary to the access point and out of this tool's control.

### Enforcement keys on IP, populated from identity

nftables matches addresses, not MACs, on forwarded traffic. So identity
resolves to a set of IPs:

- Devices with a reservation have a stable IP by construction.
- The restricted set is then best expressed as *the DHCP pool minus the
  allowlisted reservations*, rather than as an enumeration of restricted hosts.
  That is what makes the inverted default hold: a device that appears with an
  unexpected address is already in the set.
- A device that self-assigns a static IP outside the pool must therefore also
  be caught, which means the restricted set should be "the LAN subnet minus
  allowlisted addresses", not "the pool minus allowlisted addresses".

## 5. New device detection

### Mechanism

The DHCP hook already receives `<action> <mac> <ip> <hostname>`. The change is
to give it a registry to compare against:

1. Maintain `/var/lib/bardcastle/known-devices` (MAC, first seen, last seen,
   name).
2. On action `add`, if the MAC is absent from the registry, append it and emit
   `new_device`. Otherwise update `last_seen` and emit nothing.
3. Stop emitting an event for action `old`. Renewals are not news, and they are
   88 percent of the current log.

The event payload must carry `mac`, `ip` and `hostname`, because that is what
the dashboard's `describeEvent` already reads to render
"New device joined: `<hostname>` (`<ip>`)".

### Alerting

Dashboard event feed only, by decision. The event lands in the existing SSE
stream and renders with its existing style, so there is no new dependency, no
outbound channel, and no secret to manage. The tradeoff is accepted: an alert
is only seen when someone opens the dashboard.

`events.py` already anticipates outbound notification ("future notification
system integration (AWS SNS, webhooks)"). If that is wanted later, the event is
already structured for it and nothing in this design needs to change.

### The static-IP gap

A DHCP hook only fires for devices that ask for a lease. A device configured
with a static address never appears. Closing that needs a periodic neighbour
table sweep (`ip neigh`) on a systemd timer, following the existing
`bardcastle-ddns.timer` pattern, comparing observed MAC/IP pairs against the
registry. Worth building, but it is a second phase: the DHCP path covers
virtually every consumer device.

### Expected noise

Given the measured MAC rotation, a rotating phone will generate a `new_device`
event on each rotation. Options, in increasing complexity:

- Accept it. Roughly a dozen devices rotate; this is a handful of events a
  month, and each one is arguably worth seeing.
- Suppress when the DHCP hostname matches a known device with a randomized MAC.
  Cheap, and correct most of the time.
- Do not attempt fingerprinting beyond that. Matching on DHCP option
  fingerprints is fragile and would produce confident wrong answers.

The first option is the honest default, and the registry makes the second a
small change later.

## 6. DNS enforcement

### Filtering resolver

A second dnsmasq instance, DNS only, listening on the LAN IP at a non-standard
port:

```
# /etc/dnsmasq-filtered.conf  (its own instance, does NOT read /etc/dnsmasq.d)
port=5354
listen-address=127.0.0.1,<lan_ip>
bind-dynamic
no-resolv
server=<family resolver>          # e.g. 1.1.1.3 / 1.0.0.3, or 94.140.14.15
domain=<domain>
expand-hosts
host-record=<router_name>,<router_name>.<domain>,<lan_ip>
addn-hosts=/var/lib/bardcastle/vpn-hosts
cache-size=1000
# deliberately no dhcp-range: only one DHCP server on this network
```

Run under its own unit, `bardcastle-dnsmasq-filtered.service`.

Two reasons to run a local instance rather than pointing devices straight at a
public family resolver:

- Internal name resolution keeps working. A device sent directly to `1.1.1.3`
  can no longer resolve LAN hostnames, the router's own name, or `.vpn` names.
- Upstream does the category work. Cloudflare for Families and AdGuard Family
  already enforce SafeSearch and block adult content, so there is no local
  domain list to curate and nothing that rots. This is the main reason to prefer
  it over hand-maintained `address=/.../` pins, which break whenever the target
  service changes IP.

### Enforcement, not suggestion

Handing out a DNS server via DHCP option 6 is a suggestion. Any device can
ignore it and query `8.8.8.8` directly. The enforcement lives in nftables:

```
# ip nat prerouting: all port 53 from restricted sources, to any destination,
# is rewritten to the filtered resolver. Hardcoding a public resolver does
# nothing.
iifname <lan> ip saddr @restricted_devices udp dport 53 dnat to <lan_ip>:5354
iifname <lan> ip saddr @restricted_devices tcp dport 53 dnat to <lan_ip>:5354
```

```
# inet filter input: after DNAT the packet is addressed to the router, so the
# input chain has to accept it.
iifname <lan> ip saddr @restricted_devices udp dport 5354 accept
iifname <lan> ip saddr @restricted_devices tcp dport 5354 accept
```

```
# inet filter forward: close the encrypted-DNS side doors.
iifname <lan> ip saddr @restricted_devices tcp dport 853 reject    # DoT
iifname <lan> ip saddr @restricted_devices udp dport 853 reject    # DoQ
iifname <lan> ip saddr @restricted_devices ip daddr @doh_endpoints reject
```

Use `reject`, not `drop`, for LAN-side policy. A rejected connection fails
immediately and the device falls back; a dropped one hangs until timeout and
presents as "the internet is broken".

`@doh_endpoints` is a set of known DoH resolver addresses, refreshed on a timer
exactly the way `blocklists.py` already refreshes its feeds. It is inherently
incomplete; see section 7.

Optionally, `udp dport 443 reject` for restricted devices blocks QUIC and
forces HTTP/2, which removes DoH-over-HTTP/3 and makes SNI visible. This is
heavy-handed and will degrade some services, so it should be a per-policy
switch, off by default.

Time windows, if wanted, come free from `meta hour` in the same rules.

### Where this plugs in

Both features fit the existing module contract without new patterns:

- `config.yaml` grows a `devices:` section for policy definitions and an
  allowlist of unrestricted reservations.
- `dnsmasq.conf.j2` grows the tag-driven `dhcp-option` lines.
- `nftables.conf.j2` grows the sets and rules above, populated from config the
  same way `admin_vpn_ips` already is.
- A new `bardcastle-fw device` command group: `list`, `name`, `allow`,
  `restrict`, `forget`.
- The firewall must be re-applied when device policy changes, exactly as
  `vpn admin` already re-applies it. `nft -c -f` validation before apply is
  non-negotiable here, since these rules touch DNS for the whole LAN.

## 7. Bypass analysis

What this design does not stop. This section exists so the capability is not
over-trusted once it is built.

| Bypass | Covered? | Notes |
|---|---|---|
| Hardcoded public resolver (`8.8.8.8`) | Yes | DNAT rewrites all port 53 regardless of destination. |
| DNS over TLS / QUIC (853) | Yes | Rejected outright. |
| DNS over HTTPS to a known endpoint | Partly | Only endpoints on the maintained set. |
| DNS over HTTPS to an unknown endpoint | **No** | Any host serving DoH on 443 works. The list is a moving target and always behind. |
| MAC rotation | Yes, by design | Inverted default puts rotated devices in the restricted set. This is the main reason for that inversion. |
| Self-assigned static IP | Yes, if the set is "subnet minus allowlist" | Fails if the set enumerates restricted hosts instead. |
| Consumer VPN app | **No** | Tunnels all DNS and traffic past every rule. Blocking outbound VPN is an arms race: WireGuard and OpenVPN ports are easy, but commercial services deliberately run over 443. |
| Cellular data | **No** | The device is not on this network. Nothing here applies. |
| Tor | **No** | |
| Content within an allowed domain | **No** | DNS resolves domains, not paths. YouTube Restricted Mode is a partial exception and can be forced via DNS. |
| IPv6 | Not applicable today | See below. |

### The IPv6 caveat

Every rule above is IPv4. That is correct **today**: the LAN interface has no
global IPv6 address, `LinkLocalAddressing=no` is set in the template, there is
no `radvd`, and no `IPv6SendRA` in the networkd config, so LAN clients have no
routable IPv6 and no IPv6 DNS path.

This is a silent dependency. If LAN IPv6 is ever enabled, every filtering rule
here keeps passing its own tests while covering only half the traffic, and a
restricted device gets an unfiltered IPv6 resolver. Two requirements follow:

- Mirror every rule in this design for `ip6` before enabling LAN IPv6.
- Add an explicit guard so enabling LAN IPv6 while device policy is active is a
  loud error rather than a silent regression.

### Honest summary

This stops accidental exposure: a search that goes somewhere unintended, a link
followed from a chat, an ad. It does not stop deliberate circumvention by
someone willing to install an app or turn off wifi. Those are different
problems, and conflating them is how a filter comes to be trusted for something
it never did.

## 8. Controls to pair this with

Network filtering is one layer and cannot be the only one, because the two
largest holes (cellular data and in-app content) are structurally invisible to
a router.

- **OS-level parental controls.** Google Family Link or Apple Screen Time apply
  on the device, so they survive leaving the house and can restrict app
  installation, which is what actually closes the VPN-app bypass.
- **Disable private wifi addressing** for this SSID on managed devices. One
  setting, and it makes the reservation and the allowlist reliable.
- **Per-policy SSID**, if the inverted default proves too blunt. Moves policy to
  the access point, at the cost of taking it out of this tool.

The network layer's distinct contribution is that it covers every device on the
LAN including ones with no parental control story at all, such as a smart TV or
a games console, and that it gives visibility through the DNS query log that
device-side controls do not report centrally.

## 9. Rollout and rollback

Deliberately staged so that nothing which can break DNS for the whole LAN ships
before the inert parts are proven.

**Phase 1: identity and visibility. No enforcement.**
Device registry, `new_device` emission, stop logging renewals. Zero traffic
impact and it produces the device inventory that every later phase needs.
Rollback is reverting the hook.

**Phase 2: filtered resolver, not yet wired to anything.**
Stand up the second dnsmasq instance and verify it directly with
`dig @<lan_ip> -p 5354 <domain>`: that it resolves normally, that it resolves
internal and `.vpn` names, and that it actually blocks a known-bad category.
No device is pointed at it. Rollback is stopping one unit.

**Phase 3: enforcement for one device.**
Add the sets and rules, with the restricted set containing exactly one test
address. Verify on that device that a hardcoded resolver is redirected, that
DoT fails fast, and that unrestricted devices are untouched. Rollback is
removing the address and re-applying the firewall.

**Phase 4: invert the default.**
Switch the restricted set to "LAN subnet minus allowlist" only after the
allowlist is populated from the Phase 1 inventory. This is the step that can
plausibly filter the whole house by accident, so it goes last and is verified
from a known-allowlisted device first.

Throughout: the firewall is re-rendered wholesale and validated with
`nft -c -f` before apply, which already fails closed by writing the file
without loading it. That property must not be weakened for these rules.

## 10. Open questions

1. **Is the inverted default acceptable?** It is the only thing that makes MAC
   rotation safe, and it means unrecognised guest devices get filtered DNS
   until allowed. This is the central design decision and it is a household
   policy question, not a technical one.
2. **Which upstream family resolver?** Cloudflare `1.1.1.3` and AdGuard Family
   `94.140.14.15` differ in aggressiveness and in what they log. Both are
   third parties that will see the DNS queries of the filtered devices.
3. **One policy class or several?** The design supports any number of tags, but
   each one is a set and a rule group. Starting with one restricted class is
   simpler and extends cleanly.
4. **Block QUIC for restricted devices?** Meaningfully improves DoH resistance,
   measurably degrades some services. Recommended off by default.
5. **Does the static-IP sweep get built in phase 1 or later?** It closes a real
   gap but is not needed for consumer devices.
