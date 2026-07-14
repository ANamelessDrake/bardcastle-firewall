"""Authentication for the dashboard.

Password-based login backed by a PBKDF2 hash and a signed session cookie.
Secrets live in /etc/bardcastle-web (owned by the bardcastle-web service user),
never in the repo. Run `python auth.py set-password` (reads the password from
stdin) to set or change the password.
"""

import hashlib
import hmac
import json
import secrets
import sys
from pathlib import Path

WEB_DIR = Path("/etc/bardcastle-web")
AUTH_FILE = WEB_DIR / "auth.json"
SECRET_FILE = WEB_DIR / "secret.key"

_ITERATIONS = 200_000


def load_session_secret() -> str:
    """Signing key for the session cookie; ephemeral fallback for dev."""
    if SECRET_FILE.exists():
        return SECRET_FILE.read_text().strip()
    return secrets.token_hex(32)


def password_is_set() -> bool:
    return AUTH_FILE.exists()


def set_password(password: str) -> None:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt), _ITERATIONS
    ).hex()
    WEB_DIR.mkdir(parents=True, exist_ok=True)
    AUTH_FILE.write_text(json.dumps({"salt": salt, "hash": digest}))
    AUTH_FILE.chmod(0o600)


def verify_password(password: str) -> bool:
    if not AUTH_FILE.exists():
        return False
    try:
        data = json.loads(AUTH_FILE.read_text())
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(data["salt"]), _ITERATIONS
        ).hex()
    except (ValueError, KeyError, OSError):
        return False
    return hmac.compare_digest(digest, data["hash"])


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "set-password":
        pw = sys.stdin.readline().rstrip("\n")
        if not pw:
            print("empty password; aborting", file=sys.stderr)
            sys.exit(1)
        set_password(pw)
        print(f"password set in {AUTH_FILE}")
    else:
        print("usage: python auth.py set-password  (password on stdin)",
              file=sys.stderr)
        sys.exit(2)
