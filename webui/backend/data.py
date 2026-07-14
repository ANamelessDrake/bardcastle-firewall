"""Read-only data providers for the bardcastle web UI (phase 1).

Each function returns JSON-serializable data gathered from the same sources the
CLI uses. This module is strictly read-only: it never mutates system state.

Some sources (nftables, wg, cscli, the journal, the root-only config) require
privilege. Phase 1 runs the API behind a narrow allowlist (see webui/README);
functions here degrade to an "available: false" / empty result when a source
cannot be read, so the dashboard never hard-fails on one panel.
"""

import json
import re
import subprocess
import time
from pathlib import Path

LEASES_FILE = "/var/lib/misc/dnsmasq.leases"
VPN_HOSTS_FILE = "/var/lib/bardcastle/vpn-hosts"
EVENTS_FILE = "/var/log/bardcastle/events.jsonl"

# Full paths for the privileged reads, matched exactly by the sudoers
# allowlist (webui/sudoers/bardcastle-web). The service user may run only
# these specific, read-only commands as root.
NFT = "/usr/sbin/nft"
WG = "/usr/bin/wg"
CSCLI = "/usr/bin/cscli"

# "query[A] www.example.com from 10.0.1.129"
_QUERY_RE = re.compile(r"query\[(\w+)\]\s+(\S+)\s+from\s+(\S+)")


def _run(cmd: list) -> subprocess.CompletedProcess | None:
    """Run a command, returning the result or None if the binary is missing."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=False)
    except (FileNotFoundError, OSError):
        return None


def _sudo(cmd: list) -> subprocess.CompletedProcess | None:
    """Run a whitelisted privileged read via sudo (non-interactive)."""
    return _run(["sudo", "-n"] + cmd)


def get_interfaces() -> list:
    """Physical/virtual interfaces with state and IPv4 addresses."""
    r = _run(["ip", "-j", "addr", "show"])
    if not r or r.returncode != 0:
        return []
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        return []
    out = []
    for iface in data:
        if iface.get("ifname") == "lo":
            continue
        addrs = [
            f"{a['local']}/{a['prefixlen']}"
            for a in iface.get("addr_info", [])
            if a.get("family") == "inet"
        ]
        out.append({
            "name": iface.get("ifname"),
            "state": iface.get("operstate", "unknown"),
            "mac": iface.get("address"),
            "addresses": addrs,
        })
    return out


def get_resources() -> dict:
    """RAM, load average, and uptime from /proc."""
    res: dict = {}
    mem = Path("/proc/meminfo")
    if mem.exists():
        info = {}
        for line in mem.read_text().splitlines():
            key, _, val = line.partition(":")
            fields = val.strip().split()
            if fields:
                try:
                    info[key.strip()] = int(fields[0])
                except ValueError:
                    pass
        total = info.get("MemTotal", 0)
        avail = info.get("MemAvailable", 0)
        res["mem_total_mb"] = total // 1024
        res["mem_used_mb"] = (total - avail) // 1024
        res["mem_pct"] = round((total - avail) / total * 100, 1) if total else 0
    load = Path("/proc/loadavg")
    if load.exists():
        res["load"] = load.read_text().split()[:3]
    up = Path("/proc/uptime")
    if up.exists():
        res["uptime_sec"] = int(float(up.read_text().split()[0]))
    return res


def _vpn_hostmap() -> dict:
    """IP -> short VPN label, from the vpn-hosts file."""
    hostmap = {}
    path = Path(VPN_HOSTS_FILE)
    if path.exists():
        for line in path.read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                hostmap[parts[0]] = ".".join(parts[1].split(".")[:2])
    return hostmap


def get_leases() -> list:
    """Active DHCP leases."""
    path = Path(LEASES_FILE)
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        p = line.split()
        if len(p) >= 4:
            out.append({
                "expires": int(p[0]) if p[0].isdigit() else None,
                "mac": p[1],
                "ip": p[2],
                "hostname": None if p[3] == "*" else p[3],
            })
    return out


def get_firewall() -> dict:
    """Blocklist set sizes and labelled drop counters from nftables."""
    r = _sudo([NFT, "-j", "list", "ruleset"])
    if not r or r.returncode != 0:
        return {"available": False}
    try:
        ruleset = json.loads(r.stdout or "{}").get("nftables", [])
    except json.JSONDecodeError:
        return {"available": False}
    v4 = v6 = 0
    counters = []
    for item in ruleset:
        if "set" in item:
            s = item["set"]
            if s.get("name") == "blocklist_v4":
                v4 = len(s.get("elem", []))
            elif s.get("name") == "blocklist_v6":
                v6 = len(s.get("elem", []))
        elif "rule" in item:
            rule = item["rule"]
            if (rule.get("family") != "inet" or rule.get("table") != "filter"
                    or not rule.get("comment")):
                continue
            for expr in rule.get("expr", []):
                if "counter" in expr:
                    c = expr["counter"]
                    counters.append({
                        "label": rule["comment"],
                        "chain": rule.get("chain"),
                        "packets": c.get("packets", 0),
                        "bytes": c.get("bytes", 0),
                    })
                    break
    return {"available": True, "blocklist_v4": v4, "blocklist_v6": v6,
            "counters": counters}


def get_vpn_clients() -> dict:
    """VPN clients with per-client liveness.

    wg dump is keyed by public key, but its allowed-ips field is the client's
    /32 VPN IP, which the vpn-hosts file maps to a name, so we can correlate
    liveness per client without reading the (root-only) config.
    """
    by_ip = {}
    r = _sudo([WG, "show", "wg0", "dump"])
    if r and r.returncode == 0:
        for line in r.stdout.strip().splitlines()[1:]:  # skip interface line
            f = line.split("\t")
            if len(f) >= 7:
                ip = f[3].split("/")[0].split(",")[0]  # first allowed-ip
                by_ip[ip] = {"handshake": int(f[4]), "rx": int(f[5]),
                             "tx": int(f[6])}
    now = int(time.time())
    clients = []
    for ip, name in sorted(_vpn_hostmap().items(), key=lambda kv: kv[1]):
        p = by_ip.get(ip, {})
        hs = p.get("handshake", 0)
        clients.append({
            "name": name, "ip": ip,
            "online": bool(hs and now - hs < 180),
            "handshake": hs, "rx": p.get("rx", 0), "tx": p.get("tx", 0),
        })
    return {
        "clients": clients,
        "active_peers": sum(1 for c in clients if c["online"]),
        "total_peers": len(by_ip),
    }


def _wan_iface() -> str | None:
    """The interface carrying the default route (the WAN)."""
    r = _run(["ip", "-j", "route", "show", "default"])
    if not r or r.returncode != 0:
        return None
    try:
        return json.loads(r.stdout)[0].get("dev")
    except (json.JSONDecodeError, IndexError, KeyError):
        return None


def get_bandwidth() -> dict:
    """Daily WAN bandwidth history from vnstat."""
    wan = _wan_iface()
    if not wan:
        return {"available": False}
    r = _run(["vnstat", "--json", "-i", wan])
    if not r or r.returncode != 0:
        return {"available": False}
    try:
        traffic = json.loads(r.stdout)["interfaces"][0]["traffic"]
    except (json.JSONDecodeError, KeyError, IndexError):
        return {"available": False}
    days = []
    for day in traffic.get("day", [])[-14:]:
        dt = day.get("date", {})
        try:
            label = f"{dt['year']:04d}-{dt['month']:02d}-{dt['day']:02d}"
        except (KeyError, TypeError):
            label = "?"
        days.append({"date": label, "rx": day.get("rx", 0), "tx": day.get("tx", 0)})
    return {"available": True, "interface": wan, "days": days}


def get_dns_top(limit: int = 10, window: str = "-2h") -> dict:
    """Top domains and clients from the DNS query log (needs log-queries)."""
    r = _run(["journalctl", "-u", "dnsmasq", "--no-pager", "-o", "cat",
              "--since", window])
    if not r or r.returncode != 0:
        return {"available": False}
    hostmap = _vpn_hostmap()
    leasemap = {l["ip"]: l["hostname"] for l in get_leases() if l["hostname"]}
    domains: dict = {}
    clients: dict = {}  # keyed by source IP so the UI can drill into one host
    for line in r.stdout.splitlines():
        m = _QUERY_RE.search(line)
        if not m:
            continue
        name, src = m.group(2), m.group(3)
        domains[name] = domains.get(name, 0) + 1
        label = hostmap.get(src) or leasemap.get(src) or src
        c = clients.setdefault(src, {"name": label, "ip": src, "count": 0})
        c["count"] += 1
    top_domains = [{"name": k, "count": v}
                   for k, v in sorted(domains.items(), key=lambda x: -x[1])[:limit]]
    top_clients = sorted(clients.values(), key=lambda c: -c["count"])[:limit]
    return {"available": True, "top_domains": top_domains, "top_clients": top_clients}


def get_host_dns(ip: str, limit: int = 20, window: str = "-6h") -> dict:
    """Per-host DNS detail: totals, top domains, query types, recent queries."""
    if not ip:
        return {"available": False}
    r = _run(["journalctl", "-u", "dnsmasq", "--no-pager", "-o", "short-iso",
              "--since", window])
    if not r or r.returncode != 0:
        return {"available": False}
    name = _vpn_hostmap().get(ip)
    if not name:
        name = {l["ip"]: l["hostname"] for l in get_leases()
                if l["hostname"]}.get(ip, ip)
    domains: dict = {}
    types: dict = {}
    recent = []
    total = 0
    for line in r.stdout.splitlines():
        m = _QUERY_RE.search(line)
        if not m or m.group(3) != ip:
            continue
        qtype, qname = m.group(1), m.group(2)
        total += 1
        domains[qname] = domains.get(qname, 0) + 1
        types[qtype] = types.get(qtype, 0) + 1
        # short-iso prefixes each line with an ISO timestamp; keep HH:MM:SS.
        stamp = line.split(" ", 1)[0]
        recent.append({"time": stamp[11:19] if len(stamp) >= 19 else "",
                       "type": qtype, "name": qname})
    top_domains = [{"name": k, "count": v}
                   for k, v in sorted(domains.items(), key=lambda x: -x[1])[:limit]]
    type_list = [{"name": k, "count": v}
                 for k, v in sorted(types.items(), key=lambda x: -x[1])]
    return {"available": True, "ip": ip, "name": name, "total": total,
            "window": window, "top_domains": top_domains, "types": type_list,
            "recent": recent[-limit:][::-1]}


def get_ids() -> dict:
    """Attack/intrusion view from CrowdSec: active bans and recent alerts."""
    dec = _sudo([CSCLI, "decisions", "list", "-o", "json"])
    if not dec:
        return {"available": False}
    if dec.returncode != 0:
        return {"available": False}
    decisions = []
    try:
        for alert in json.loads(dec.stdout or "null") or []:
            src = alert.get("source", {}) or {}
            for d in alert.get("decisions", []) or []:
                decisions.append({
                    "ip": d.get("value"), "scenario": d.get("scenario"),
                    "expires": d.get("duration"), "origin": d.get("origin"),
                    "country": src.get("cn", "") or "",
                })
    except (json.JSONDecodeError, TypeError):
        pass
    alerts = []
    alr = _sudo([CSCLI, "alerts", "list", "-o", "json"])
    if alr and alr.returncode == 0:
        try:
            for a in (json.loads(alr.stdout or "null") or [])[:15]:
                src = a.get("source", {}) or {}
                alerts.append({
                    "id": a.get("id"), "ip": src.get("value"),
                    "scenario": a.get("scenario"),
                    "country": src.get("cn", "") or "",
                    "as": (src.get("as_name", "") or "")[:28],
                    "events": a.get("events_count"),
                    "when": (a.get("created_at", "") or "")[:19].replace("T", " "),
                })
        except (json.JSONDecodeError, TypeError):
            pass
    return {"available": True, "active_bans": len(decisions),
            "decisions": decisions[:25], "alerts": alerts}


def get_events(limit: int = 50) -> list:
    """Most recent structured events."""
    path = Path(EVENTS_FILE)
    if not path.exists():
        return []
    events = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events[-limit:][::-1]
