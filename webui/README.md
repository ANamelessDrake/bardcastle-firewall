# Bardcastle Firewall - Web Dashboard (phase 1)

Phase 1 of the design in `docs/web-ui-design.md`: a **local, read-only**
dashboard served from the firewall on the LAN and VPN. No cloud, no mutations.

Status: **in progress** (backend spike). See the checklist below.

## Layout

```
webui/
  backend/         FastAPI service (read-only JSON API)
    app.py         endpoints
    data.py        read-only data providers (no mutations)
    requirements.txt
  frontend/        React SPA (to be added)
```

## Running the backend (spike)

The API reads system state (nftables, wg, dnsmasq leases, the event log), some
of which needs privilege. For the spike it is run manually, bound to loopback,
and tested locally. It is NOT yet a persistent service and NOT yet exposed on
the LAN (see the checklist before that happens).

```bash
python3 -m venv /opt/bardcastle-webui/venv
/opt/bardcastle-webui/venv/bin/pip install -r requirements.txt
cd webui/backend
sudo /opt/bardcastle-webui/venv/bin/uvicorn app:app --host 127.0.0.1 --port 8080
# then, from the same host:
curl -s http://127.0.0.1:8080/api/status | python3 -m json.tool
```

## Endpoints (read-only)

- `GET /api/health` - liveness
- `GET /api/status` - interfaces + resources (RAM/load/uptime)
- `GET /api/leases` - DHCP leases
- `GET /api/firewall` - blocklist sizes + drop counters
- `GET /api/vpn` - VPN clients with per-client liveness + transfer
- `GET /api/bandwidth` - daily WAN rx/tx history (vnstat)
- `GET /api/dns` - top domains and clients from the query log (last 2h)
- `GET /api/dns/host?ip=<ip>` - one host's DNS detail: totals, top domains,
  query types, and recent queries (click a host in the UI to open this)
- `GET /api/ids` - CrowdSec active bans and recent alerts (with source country)
- `GET /api/events?limit=N` - recent structured events (backlog)
- `GET /api/events/stream` - Server-Sent Events live event feed

## Install

Handled automatically at first boot (see `autoinstall/first-login-setup.sh`),
or run by hand:

```bash
sudo bash /opt/bardcastle-firewall/webui/install.sh
sudo bardcastle-fw webui set-password
```

Then browse to `https://<lan-ip>/` (accept the self-signed cert warning once).
The build machine's `build-iso.sh` compiles the SPA into the ISO, so the
appliance serves static files with no Node installed.

## Checklist (phase 1)

- [x] Backend: FastAPI + read-only data providers.
- [x] Privilege separation: dedicated `bardcastle-web` user in
      `systemd-journal`, narrow sudoers allowlist for the root reads. No root
      network service.
- [x] Auth: session login on every data endpoint.
- [x] TLS: HTTPS with a self-signed cert; HTTP redirects to HTTPS.
- [x] nftables rules for 80/443 on the LAN (`enp3s0`); over the VPN (`wg0`)
      only admin clients (`vpn admin NAME`) are allowed; never the WAN.
- [x] systemd units for the dashboard and the redirect.
- [x] React frontend (Vite) with panels for each endpoint.
- [x] SPA served by the API process; built into the ISO.
- [x] Reinstall-deployable: first-boot installs and enables the service.
- [x] SSE live event feed; per-client VPN liveness; DNS-query, bandwidth,
      and IDS/attacks panels.

## Non-goals (phase 1)

No mutations, no cloud, no WAN exposure. Management stays in the CLI. See
`docs/web-ui-design.md` sections 5, 6, and 16.
