# Bardcastle Firewall - Web UI Design

Status: **Proposal** (not yet approved for build)

A design for an optional web application to view and manage the bardcastle
firewall. There are two paths (see section 16 for the decision):

- **Recommended:** a dashboard served from the firewall (LAN and VPN) plus
  event notifications through a third-party push service. Almost all of the
  value, minimal cloud, no public endpoint on the edge device.
- **Alternative:** a full hybrid where the dashboard is hosted in AWS at
  `admin.example.com` (restricted to the home network), backed by a
  serverless AWS backend, with a custom mobile app. The AWS side mirrors the
  a reference CDK project project (Python CDK, S3 + CloudFront + Route 53, API Gateway,
  Lambda, DynamoDB, Cognito, CodePipeline).

This document exists so the decision to build (or not) can be made with the
trade-offs in front of us. Nothing here is implemented yet.

Sections 1 to 11 cover the core (firewall-side) design that both paths share.
Sections 12 to 15 detail the full-hybrid AWS components. Section 16 lays out
the two paths and the recommendation; section 17 covers cost.

## 1. Purpose and scope

The `bardcastle-fw` CLI already does everything: setup, firewall, DNS/DHCP,
VPN, blocklists, IDS, monitoring. A web UI would not add new capability; it
would add a different, more visual way to reach the capability that already
exists, plus dashboards for data that the CLI serves poorly (bandwidth over
time, a live event feed, "who is online right now").

In scope:

- A read-only dashboard of firewall state and activity.
- Optionally, a set of guarded management actions (add/revoke VPN client,
  refresh blocklists, restart a service).

Out of scope:

- Open exposure to the internet. The frontend is hosted in AWS for
  convenience, but access is restricted to the home network (see section 14).
  Sensitive/live firewall data and all management actions stay on the firewall
  and never leave the network.
- Replacing the CLI. The CLI stays the source of truth; the UI calls the same
  code paths.

## 2. Goals and non-goals

**Goals**

- Surface the data that is awkward on the CLI: bandwidth graphs, the DNS query
  log, the event feed, VPN client status, IDS alerts with GeoIP.
- Make the handful of frequent actions fast (add a VPN client and show its QR,
  see DHCP leases, revoke a device).
- Reuse the existing Python modules rather than reimplementing logic.
- Stay LAN/VPN-only and authenticated.

**Non-goals**

- Not a general-purpose config editor. Anything not explicitly modeled stays
  in the CLI.
- Not internet-reachable. Not a cloud service.
- Not a replacement for good CLI hygiene.

## 3. Pros and cons

This is the heart of the decision.

### Pros

- **Visibility.** Bandwidth trends, a live event feed, top DNS talkers, and
  "who is online" are genuinely better as a dashboard than as CLI output.
- **Speed for common tasks.** Adding a VPN client and showing its QR, listing
  leases, or revoking a device becomes a couple of clicks.
- **Accessibility.** Other members of the household or team can glance at
  status without SSH and without root.
- **Reuses existing logic.** A Python backend (FastAPI) can import the
  existing `bardcastle` modules, so the data and actions already exist.
- **Headroom.** The N100 / 32 GB appliance has ample room for a small API
  service and a static site.
- **Mobile friendly.** Manage from a phone on the LAN or over the VPN.
- **Homelab value.** A real full-stack + systems-integration project.

### Cons

- **Attack surface on a security device.** A web app is the single most
  attractive target you can add to a firewall. This directly contradicts a
  founding reason for this project: IPFire and pfSense/OPNsense were passed
  over partly because their web UIs add complexity and are where their CVEs
  historically live.
- **Privilege is the hard part.** Reading state is low risk, but any mutation
  (apply firewall rules, add a VPN peer, restart a service) needs root. A
  single authz/XSS/CSRF slip in a root-capable UI can mean a compromised edge
  device, i.e. the whole network.
- **Maintenance tax.** npm dependency churn, rebuilds, and a long-running
  daemon on a box whose main virtue is being boring and stable for years.
- **Complexity multiplier.** Doing it safely (auth, TLS, CSRF, sessions, a
  privileged broker) is roughly 3x the work of the UI itself.
- **Duplication.** Every feature is additive surface for something the CLI
  already does.
- **More to patch.** Another daemon and a JS toolchain to keep current.

### Net read

The read-only dashboard is high value at low risk. The management (mutation)
half is where the real risk and most of the work live. A phased approach lets
phase 1 deliver most of the value while the phase 2 decision is made
separately and deliberately.

## 4. Architecture

```
  Browser (LAN / VPN client)
        |  HTTPS (self-signed or local CA), LAN-only
        v
  +-----------------------------------------------+
  |  Appliance (bardcastle-fw)                     |
  |                                                |
  |  React SPA (static build)  <-- served by -->   |
  |  FastAPI backend (uvicorn), bound to 10.0.1.1  |
  |     |  imports                                 |
  |     v                                          |
  |  bardcastle/ modules (read paths)              |
  |     |                                          |
  |     |  mutations go through ...                |
  |     v                                          |
  |  privileged broker (whitelisted actions only)  |
  |     |                                          |
  |     v                                          |
  |  nft / systemctl / wg / dnsmasq / cscli        |
  +-----------------------------------------------+
```

- **Frontend:** a React single-page app (Vite build) served as static files.
- **Backend:** FastAPI + uvicorn, a single service. It serves the static SPA
  and exposes a JSON API. It imports the existing `bardcastle` modules for
  read paths.
- **Mutations:** never done by the web process directly. They go through a
  small privileged broker (see Security) that accepts only a fixed set of
  verbs.
- **Real-time:** Server-Sent Events (or WebSocket) for the live event feed,
  DNS query stream, and connection counters.

## 5. Security and privilege model

This is the section that decides whether the project is safe.

### Network exposure

- The API binds to the LAN address (`10.0.1.1`) and optionally the VPN address
  (`10.10.10.1`). Never `0.0.0.0`, never the WAN.
- A single nftables input rule permits the web port from `enp3s0` (and `wg0`
  if desired), mirroring how SSH and DNS are already restricted. The default
  drop policy covers the WAN.
- TLS from the start, even on the LAN, so credentials and sessions are not sent
  in the clear. Self-signed or a small local CA.

### Authentication

- Session-based login with a strong password (or PAM against the system user).
- CSRF tokens on every mutating request.
- Rate limiting and lockout on the login endpoint (fail2ban can watch its log,
  like it watches sshd).

### Privilege separation (the crux)

- The web/API process runs as an **unprivileged** user. It can read most state
  directly (interfaces, leases, vnstat, journald with the right group, config
  via a read-only copy).
- Anything requiring root goes through a **privileged broker**: a tiny,
  auditable component that exposes a **fixed whitelist of verbs**, never a
  generic "run this command" or "apply this config." Examples of allowed
  verbs: `vpn.add_client(name, pubkey?)`, `vpn.revoke(name)`,
  `blocklist.update()`, `service.restart(<name from allowlist>)`.
- Implementation options for the broker: a separate root service reached over a
  local unix socket with a strict message schema, or narrowly scoped
  `sudoers` entries for specific argv. The message-schema daemon is preferred
  because it is easier to audit than shell argv.
- Every mutation is written to the existing `events.jsonl` audit log with the
  authenticated user, verb, and arguments.

### Blast-radius rule

If the web UI is compromised, the damage must be bounded by the broker's verb
list. There must be no path from the UI to arbitrary code or arbitrary config.
This is the single most important design constraint.

## 6. Feature scope, by phase

### Phase 1: read-only dashboard (recommended first)

Maps directly onto data the system already produces:

- **Overview:** interfaces (WAN/LAN state, IPs), uptime, RAM/CPU/load.
- **Devices:** DHCP leases with online status (leases file + ARP), the same
  data as `vpn dns leases`.
- **DNS:** query log viewer per client, top domains and clients
  (dnsmasq `log-queries` in journald).
- **Firewall:** rules table and drop counters, blocklist set sizes (nft JSON).
- **VPN:** client list with online/handshake/transfer, and name mappings.
- **IDS:** CrowdSec decisions, alerts with GeoIP, scenarios, metrics (cscli).
- **Bandwidth:** vnstat daily/monthly graphs.
- **Events:** live feed from `events.jsonl`.
- **DDNS:** current record vs public IP.

Risk: low. Worst case of a compromise is disclosure of LAN metadata (which is
already visible to anyone on the LAN). No mutation path exists in phase 1.

### Phase 2: guarded management (separate decision)

Only if phase 1 proves worth extending, and only through the broker:

- VPN: add client (with QR), revoke, rotate.
- Blocklists: trigger an update.
- Services: restart a service from an allowlist.
- Firewall: toggle specific, pre-modeled rules (not free-form editing).

Risk: high. Requires the full privilege-separation and auth machinery above.

## 7. Data source mapping

Every phase-1 panel already has a backing source, which is why the read-only
tier is cheap:

| Panel | Source |
|---|---|
| Interfaces / resources | `ip -j`, `/proc/meminfo`, `/proc/loadavg` |
| DHCP leases | `/var/lib/misc/dnsmasq.leases` + neighbor table |
| DNS queries | journald (`dnsmasq`, `log-queries`) |
| Firewall counters / blocklist | `nft -j list ruleset` |
| VPN clients | `wg show wg0 dump` + config |
| IDS | `cscli ... -o json` |
| Bandwidth | `vnstat --json` |
| Events | `/var/log/bardcastle/events.jsonl` |
| DDNS | Route 53 record vs `checkip` |

## 8. Tech stack

- **Frontend:** React + Vite, a small component library, a charting library
  for bandwidth. Built to static files at deploy time.
- **Backend:** Python 3 + FastAPI + uvicorn. Reuses `bardcastle` modules.
- **Broker:** a small Python root service over a unix socket, or scoped
  sudoers.
- **Packaging:** a systemd unit for the API service; the SPA served by the API
  process (no separate web server needed). Optionally build the SPA in the ISO
  builder so it ships with the appliance.

## 9. Implementation plan

1. **Spike:** FastAPI service exposing two or three read-only endpoints
   (leases, interfaces, firewall counters), bound to the LAN, behind a login.
   Prove the shape end to end.
2. **Phase 1 UI:** build the read-only panels against those endpoints; add
   SSE for the event feed; add TLS and the LAN-only firewall rule.
3. **Decision gate:** live with phase 1 for a while. Decide whether phase 2 is
   worth the risk.
4. **Phase 2 (optional):** build the broker with a minimal verb set, wire the
   guarded actions, add CSRF and the audit trail.

## 10. Open questions

- Auth backend: app-managed password vs system PAM?
- TLS: self-signed vs a small internal CA (nicer for multiple clients)?
- Should the UI be reachable over the VPN (`wg0`) as well as the LAN?
- Do we ship the SPA in the autoinstall ISO, or install it separately?
- Is phase 2 wanted at all, or is read-only enough given the CLI already does
  mutations well over SSH?

## 11. Recommendation

Build **phase 1 (read-only) only**, and treat **phase 2 as a separate, later
decision**. Phase 1 captures most of the value (the dashboards and visibility
the CLI serves poorly) at low risk, because it has no mutation path and worst
case discloses LAN metadata already visible on the LAN. Keep it LAN/VPN-only,
authenticated, and TLS-protected from day one.

Defer or decline phase 2 unless a specific management task turns out to be
painful enough over SSH to justify the added attack surface and the privilege
broker. If phase 2 is built, the blast-radius rule in section 5 is
non-negotiable: the UI must never have a path to arbitrary code or config,
only to a fixed, audited verb list.

## 12. Hybrid architecture (firewall + AWS)

The dashboard is delivered from AWS but the firewall stays the source of truth
for anything live or sensitive. Responsibilities split cleanly:

**On the firewall (local API + agent):**

- A FastAPI service that reads live state (nftables counters, DHCP leases, the
  DNS query stream, VPN clients, CrowdSec, vnstat) and performs all
  management through the privileged broker from section 5.
- Bound to the LAN and VPN addresses only, behind auth and TLS. This is where
  every mutation happens and where raw/sensitive data (packet counters, full
  DNS logs, keys) lives. None of it leaves the network.
- An **event forwarder** that tails `/var/log/bardcastle/events.jsonl` and
  pushes event *summaries* (not raw logs) to the AWS ingest API for history
  and notifications.

**In AWS (serverless, mirrors a reference CDK project):**

- Hosts the React SPA (S3 + CloudFront at `admin.example.com`).
- Stores durable event history and device inventory (DynamoDB).
- Runs the notification pipeline (Lambda plus SNS or Pinpoint) for the mobile
  app.
- Provides user authentication (Cognito).

The single-page app is served from CloudFront but talks to two backends: the
**firewall's local API** (over LAN or VPN) for live data and management, and
the **AWS API** for history and notifications. If the firewall is unreachable
(you are away and not on the VPN), the app still shows AWS-side history and
receives notifications, but live panels and management are unavailable by
design.

```
  Browser on the home network / VPN
     |                         \
     |  live data + mgmt        \  history + notifications + static app
     v  (LAN/VPN, never public)  v
  Firewall FastAPI + broker     AWS: CloudFront -> S3 (React SPA)
     |  reads local state              API Gateway -> Lambda
     |  event forwarder  --------->        |         \
     v                    (summaries)      v          v
  nft/dnsmasq/wg/cscli/vnstat          DynamoDB     SNS/Pinpoint -> mobile push
```

**Trust boundary:** only event metadata (type, device name/MAC, timestamp,
severity) is sent to AWS, and only for event types you opt in to. Packet
contents, full DNS query logs, configs, and keys never leave the firewall.

## 13. AWS deployment (CDK, mirroring a reference CDK project)

The AWS side is a Python CDK app with the same shape as a reference CDK project, so the
deployment process is familiar: config-driven stacks, a CodePipeline fed from
GitHub through a CodeStar connection, and per-site buildspecs.

**Reused account context:** the `example.com` hosted zone already exists in
the Personal AWS account (zone `Z0123456789ABC`, account `123456789012`), the
same zone the firewall's DDNS uses. `admin.example.com` becomes a record in
it.

**Project layout (mirrors a reference CDK project):**

- `bin/app.py` instantiates the stacks from `config/{dev,prod}.json`.
- `config/prod.json`: `account`, `region` (us-east-1), `base_domain`
  (`example.com`), `hosted_zone_id` (`Z0123456789ABC`),
  `codestar_connection_arn`, `source_repo`, `source_owner`.
- `infrastructure/stacks/`:
  - **SecretsStack** - the firewall-to-AWS API key and Cognito config.
  - **DynamoDbStack** - events history, device inventory, push subscriptions.
  - **LambdaFunctionsStack** - ingest, query, and notify functions.
  - **ApiGatewayStack** - HTTP API v2 with a custom domain
    (`api.admin.example.com`), Route 53 record, and ACM cert, the way
    a reference CDK project's `apiGatewayStack` does it.
  - **ServerlessWebserverStack** - private S3 bucket with Origin Access
    Control, CloudFront distribution, ACM cert, Route 53 A record, and
    security headers, the way a reference CDK project's `serverlessWebserverStack` does it,
    for `admin.example.com`.
  - **AuthStack (Cognito)** - user pool for admin login.
  - **NotificationStack** - SNS or Pinpoint for mobile push.
  - **PipelineStack** - CodePipeline via the CodeStar connection to the
    firewall repo, a CodeBuild stage that builds the React app (a
    `buildspec-admin.yml` mirroring a reference CDK project's `buildspecadmin.yml`) and runs
    `cdk deploy`.
  - **MonitoringStack** - CloudWatch alarms to the alarm email.

**Deploy process:** push to GitHub, the pipeline builds and deploys; or run a
`deployCDK.sh` for a manual deploy, exactly as in a reference CDK project. Region us-east-1
(required for the CloudFront ACM cert).

## 14. Network-restricted admin.example.com

The requirement is that `admin.example.com` is only usable from the home
network. Because the frontend is on CloudFront (a public CDN), this is done
with layered controls rather than a single switch:

1. **WAF IP allowlist.** A WAFv2 WebACL with an IPSet containing only the
   home's current public IP fronts the endpoints; any other source gets a 403.
   Because WAF has two scopes, this takes **two Web ACLs**:

   - a **CLOUDFRONT-scope** ACL (created in us-east-1) for the
     `admin.example.com` CloudFront distribution, and
   - a **REGIONAL-scope** ACL for the regional data endpoints; a single
     regional ACL can cover both the API Gateway and AppSync at once.

   Gate the data endpoints too, not just the frontend, or the network
   restriction is bypassable by calling the API/AppSync directly. Each scope
   has its own IPSet, so the firewall's DDNS updater (which already tracks the
   public IP for Route 53) updates both IPSets when the IP changes, using the
   same scoped-IAM approach. VPN clients on a full tunnel egress through the
   home IP, so remote admin over the VPN still passes the allowlist, which is
   the desired behavior. See section 17 for the cost of the two ACLs.
2. **Cognito authentication.** Even from an allowed IP, you must log in. No
   anonymous access.
3. **Management stays on the firewall.** The live/management API is LAN and VPN
   only (nftables-restricted). So even if someone reached the CloudFront app,
   they could not manage the firewall without being on the network.
4. **Optional split-horizon DNS.** `admin.example.com` can additionally be
   published only via the firewall's dnsmasq for LAN devices, with the public
   record as the fallback for VPN clients.

**Honest caveat:** a WAF IP allowlist is coarse; anyone sharing the home's
public IP (that is, anyone already on the network or its NAT) is permitted at
the WAF layer. The real protection is the combination: WAF narrows it to the
home IP, Cognito requires a login, and the firewall-only management API means
the cloud app cannot change anything on its own. Treat the WAF as a first
filter, not the whole security model.

## 15. Event notifications

Push notifications for network events, using the event stream the firewall
already produces. There are two ways to deliver them, and they differ a lot in
effort.

**Notifiable events** (from the existing `events.jsonl` types): `new_device`,
`ids_alert`, `blocked_ip`, `vpn_connect`, `login_attempt`, `service_restart`.
The user configures which types notify and at what severity.

### Delivery option 1: third-party push service (recommended)

The firewall's event forwarder HTTP-POSTs the event to an existing push
service, and you get a native notification on your phone through that service's
app. No custom app, no APNs/FCM certificates, no App Store review, nothing to
keep patched. Good choices:

- **ntfy** (open source, self-hostable, free)
- **Pushover** (one-time app cost, very simple)
- a **Telegram bot**, or **AWS SNS to SMS/email**

This captures essentially all of the value ("tell me when X happens") for a
tiny fraction of the effort. It also needs no cloud dashboard, so it pairs well
with the recommended local-dashboard path.

### Delivery option 2: custom mobile app

A React Native app that registers its push token, receives notifications, and
shows a read-only feed of recent events and device history. Worth building only
if you want a single branded mobile experience on top of the full-hybrid cloud
dashboard, or if building it is itself a goal. As a delivery mechanism for
alerts alone it is overkill compared with option 1.

If built, the pipeline is: firewall event forwarder -> API Gateway ingest ->
Lambda -> DynamoDB (history) and SNS/Pinpoint -> push (APNs/FCM) -> the app.

**Privacy (either option):** only event metadata (type, device name/MAC,
timestamp, severity) leaves the firewall. Packet contents and full DNS logs
stay local.

## 16. Two paths and recommendation

The dashboard and the notifications got bundled into one "hybrid AWS app"
above, but they are separable, and separating them gives a much leaner design
that keeps almost all of the value. Two paths:

### Recommended path: local dashboard + lightweight notifications

- **Dashboard served from the firewall** (LAN and VPN), not from AWS. Reaching
  a LAN tool through a global CDN and back is backwards, and the VPN already
  provides remote access, so a firewall-hosted dashboard is reachable at home
  and away with no CloudFront, no WAF, and no public endpoint on the edge
  device.
- **Notifications via a third-party push service** (section 15, option 1). The
  firewall POSTs event summaries to ntfy / Pushover / Telegram / SNS. Little to
  no standing AWS footprint, and no custom mobile app.
- **No `admin.example.com` cloud hosting** and no CDK stack to run.

Phasing:

1. Firewall-side read-only dashboard (section 6), served LAN/VPN-only.
2. Event notifications via a push service.
3. Optional guarded mutations via the broker (section 5), later, if wanted.

Why this is the default: it delivers the two things that are actually valuable
(visibility and alerts), keeps the security posture intact (no public,
cloud-connected surface on a security appliance, which is the whole reason this
project exists), and costs close to nothing. Skip cloud-side *management*
essentially permanently; keep the keys to the firewall on the firewall.

### Alternative path: full hybrid (sections 12 to 14)

The AWS-hosted dashboard at `admin.example.com` (CloudFront + WAF + Cognito),
the serverless backend, and a custom mobile app. Worth it if you want a
polished branded cloud app and unified mobile experience, you are already
invested in the serverless build and enjoy it, or you want durable off-box
history and a first-class app. The trade-offs are the ones listed as
"additional cons" below, and the roughly $12 to $20/month in section 17.

Phasing (if chosen): local dashboard first, then the AWS frontend, then event
forwarding + history + mobile app, then optional guarded mutations. Even here,
keep management on the firewall; the cloud is for delivery, history, and
notifications, not for holding the firewall's keys.

**Additional cons of the full-hybrid path:**

- Event metadata leaves the network to AWS. Must stay opt-in and
  metadata-only.
- More moving parts: an AWS account, a CDK app, a pipeline, and ongoing cost
  (section 17).
- A public CloudFront/API endpoint exists, even if WAF-gated. That is new
  attack surface on a security project, and it runs against the project's
  simplicity-for-security thesis.
- An outbound dependency on AWS. The firewall must keep working fully when AWS
  is unavailable (it does, since management is local).

**Additional pros of the full-hybrid path:** a fast global frontend, a
first-class mobile app, durable off-box history, and reuse of the a reference CDK project CDK
patterns and serverless skills.

## 17. Cost estimate

Rough monthly AWS cost at personal scale (a few users, low request volume).
These figures move over time and vary by region, so verify against current AWS
pricing before committing.

| Item | Estimate | Notes |
|---|---|---|
| WAF, 2 Web ACLs | ~$12/mo | $5 per Web ACL plus $1 per rule, times two scopes (one CLOUDFRONT for the frontend, one REGIONAL for API + AppSync). Requests are negligible below 1M/mo at $0.60/M. |
| Route 53 hosted zone | $0.50/mo | Already paid for `example.com`. |
| CloudFront + S3 | a few dollars/mo | Static SPA, low traffic; often near free-tier. |
| API Gateway (HTTP API) | ~$0 | $1.00 per million requests; personal volume is well under. |
| Lambda | ~$0 | Free tier covers 1M requests and 400k GB-seconds per month. |
| DynamoDB (on-demand) | ~$0 | Tiny event/history volume, likely within free tier. |
| Cognito | ~$0 | Free tier covers 50k monthly active users. |
| SNS / Pinpoint push | ~$0 to a few dollars | Mobile push is cheap; the first million SNS publishes is about $0.50. |

**Bottom line:** the fixed cost is dominated by WAF at roughly **$12/month**;
everything else is largely usage-based and mostly free-tier at this scale, so
the whole hybrid runs on the order of **$12 to $20/month**. If cost matters,
the single-WAF option (front the API through CloudFront and skip AppSync)
halves the WAF line to about **$6/month**, at the cost of a slightly less
flexible API layer.
