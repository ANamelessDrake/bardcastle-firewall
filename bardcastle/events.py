"""Structured JSON event emitter for bardcastle-firewall.

Appends events to /var/log/bardcastle/events.jsonl for future
notification system integration (AWS SNS, webhooks, etc.).
"""

import json
from datetime import datetime, timezone
from pathlib import Path

EVENT_LOG = Path("/var/log/bardcastle/events.jsonl")

# Valid event types
EVENT_TYPES = {
    "new_device",
    "blocked_ip",
    "vpn_connect",
    "vpn_disconnect",
    "ids_alert",
    "dhcp_lease",
    "service_restart",
    "config_change",
    "blocklist_update",
    "login_attempt",
}


def emit_event(event_type: str, data: dict) -> None:
    """Append a structured event to the event log.

    Args:
        event_type: One of the defined EVENT_TYPES.
        data: Arbitrary dict of event-specific data.
    """
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": event_type,
        "data": data,
    }

    EVENT_LOG.parent.mkdir(parents=True, exist_ok=True)

    with open(EVENT_LOG, "a") as f:
        f.write(json.dumps(event) + "\n")


def read_events(event_type: str | None = None, limit: int = 100) -> list[dict]:
    """Read recent events from the log, optionally filtered by type."""
    if not EVENT_LOG.exists():
        return []

    events = []
    with open(EVENT_LOG) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                if event_type is None or event.get("type") == event_type:
                    events.append(event)
            except json.JSONDecodeError:
                continue

    return events[-limit:]


def rotate_log(max_size_mb: int = 50) -> None:
    """Rotate the event log if it exceeds max_size_mb."""
    if not EVENT_LOG.exists():
        return

    size_mb = EVENT_LOG.stat().st_size / (1024 * 1024)
    if size_mb <= max_size_mb:
        return

    rotated = EVENT_LOG.with_suffix(".jsonl.1")
    if rotated.exists():
        rotated.unlink()
    EVENT_LOG.rename(rotated)
