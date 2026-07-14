"""Bardcastle Firewall dashboard API (phase 1, read-only, authenticated).

A small FastAPI service that exposes read-only firewall state as JSON for the
web dashboard. Read-only: there are no mutating endpoints. Data endpoints
require a logged-in session. See webui/README.md for the design.
"""

import asyncio
import os

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

import auth
import data

app = FastAPI(
    title="Bardcastle Firewall Dashboard",
    description="Read-only firewall state for the LAN dashboard (phase 1).",
    version="0.1.0",
)

# Signed session cookie; https_only so it is never sent over plain HTTP.
app.add_middleware(
    SessionMiddleware,
    secret_key=auth.load_session_secret(),
    https_only=True,
    same_site="lax",
)

_SPA_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")


def require_auth(request: Request) -> None:
    if not request.session.get("auth"):
        raise HTTPException(status_code=401, detail="login required")


# --- auth endpoints (unauthenticated) ---

@app.get("/api/authstate")
def authstate(request: Request) -> dict:
    return {
        "authenticated": bool(request.session.get("auth")),
        "password_set": auth.password_is_set(),
    }


@app.post("/api/login")
async def login(request: Request) -> dict:
    body = await request.json()
    if auth.verify_password(body.get("password", "")):
        request.session["auth"] = True
        return {"ok": True}
    raise HTTPException(status_code=401, detail="invalid password")


@app.post("/api/logout")
def logout(request: Request) -> dict:
    request.session.clear()
    return {"ok": True}


@app.get("/api/health")
def health() -> dict:
    return {"ok": True}


# --- data endpoints (require a session) ---

_auth = [Depends(require_auth)]


@app.get("/api/status", dependencies=_auth)
def status() -> dict:
    return {
        "interfaces": data.get_interfaces(),
        "resources": data.get_resources(),
    }


@app.get("/api/leases", dependencies=_auth)
def leases() -> dict:
    return {"leases": data.get_leases()}


@app.get("/api/firewall", dependencies=_auth)
def firewall() -> dict:
    return data.get_firewall()


@app.get("/api/vpn", dependencies=_auth)
def vpn() -> dict:
    return data.get_vpn_clients()


@app.get("/api/events", dependencies=_auth)
def events(limit: int = 50) -> dict:
    return {"events": data.get_events(limit=limit)}


@app.get("/api/bandwidth", dependencies=_auth)
def bandwidth() -> dict:
    return data.get_bandwidth()


@app.get("/api/dns", dependencies=_auth)
def dns() -> dict:
    return data.get_dns_top()


@app.get("/api/dns/host", dependencies=_auth)
def dns_host(ip: str) -> dict:
    return data.get_host_dns(ip)


@app.get("/api/ids", dependencies=_auth)
def ids() -> dict:
    return data.get_ids()


@app.get("/api/events/stream", dependencies=_auth)
async def events_stream() -> StreamingResponse:
    """Server-Sent Events: push new event-log lines as they are written."""
    async def gen():
        try:
            f = open(data.EVENTS_FILE)
        except OSError:
            yield ": no event log\n\n"
            return
        f.seek(0, 2)  # start at end; only stream new lines
        try:
            while True:
                line = f.readline()
                if line.strip():
                    yield f"data: {line.strip()}\n\n"
                else:
                    yield ": ping\n\n"  # heartbeat keeps the connection open
                    await asyncio.sleep(3)
        finally:
            f.close()

    return StreamingResponse(gen(), media_type="text/event-stream")


# Serve the built SPA at the site root. Mounted last so the /api routes above
# take precedence. html=True serves index.html for client-side routes.
if os.path.isdir(_SPA_DIR):
    app.mount("/", StaticFiles(directory=_SPA_DIR, html=True), name="spa")
