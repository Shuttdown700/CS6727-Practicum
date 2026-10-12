"""
core/identity.py -- operators, and attributing actions to one.

The architecture's claim is that attribution should resolve to a person rather
than a device. That only means something if every state-changing action in the
portal carries an operator name into the event log, so this module exists to
make the operator name available and the event log is where it lands.

Passwords are scrypt-hashed with a per-user salt, using hashlib from the
standard library -- no bcrypt/argon2 dependency on the Pi. Prototype-grade:
there is no password policy, no lockout, no MFA, and sessions are ordinary
signed cookies. Say so in the write-up rather than implying otherwise.

Standalone:
    python3 -m fabguard.core.identity       # list users
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from .. import config
from . import db, eventlog


def _hash(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt,
                          n=config.SCRYPT_N, r=config.SCRYPT_R,
                          p=config.SCRYPT_P, dklen=32,
                          maxmem=96 * 1024 * 1024)


def create_user(username: str, password: str, display_name: str = "",
                actor: str = "system") -> None:
    username = username.strip().lower()
    if not username:
        raise ValueError("username required")
    if len(password) < 6:
        raise ValueError("password must be at least 6 characters")
    salt = secrets.token_bytes(16)
    with db.tx() as c:
        c.execute(
            "INSERT INTO users(username, display_name, pw_salt, pw_hash, created_ts)"
            " VALUES (?,?,?,?,?)",
            (username, display_name or username, salt, _hash(password, salt), db.now()))
    eventlog.emit("user.created", actor=actor, feature="identity",
                  subject=username, data={"display_name": display_name})


def set_password(username: str, password: str, actor: str) -> None:
    username = username.strip().lower()
    if len(password) < 6:
        raise ValueError("password must be at least 6 characters")
    salt = secrets.token_bytes(16)
    with db.tx() as c:
        n = c.execute("UPDATE users SET pw_salt=?, pw_hash=? WHERE username=?",
                      (salt, _hash(password, salt), username)).rowcount
    if not n:
        raise ValueError(f"no such user: {username}")
    # The new password is never logged -- only the fact of the change, and who
    # made it.
    eventlog.emit("user.password_changed", actor=actor, feature="identity",
                  subject=username)


def set_disabled(username: str, disabled: bool, actor: str) -> None:
    with db.tx() as c:
        c.execute("UPDATE users SET disabled=? WHERE username=?",
                  (1 if disabled else 0, username))
    eventlog.emit("user.disabled" if disabled else "user.enabled",
                  actor=actor, feature="identity", subject=username)


def describe_device(remote_addr: str | None, user_agent: str = "") -> str:
    """
    Identify the device an action came from -- Operator Attribution [M].

    The feature's claim is specifically "a claimed operator identity ON TOP OF
    a device identity". Neither half is attribution on its own: a device
    identity alone is what the makerspace already has and cannot resolve to a
    person, and an operator name alone cannot say which machine the action
    came from.

    Device identity is the client address, with a reverse-resolved hostname
    when one is available. On a flat lab segment that is enough to tell one
    workstation from another. It is NOT trustworthy against someone who wants
    to lie about it -- addresses are forgeable -- and should be described as
    context rather than as proof.

    X-Forwarded-For is ignored unless config.ATTRIBUTION_TRUST_FORWARDED_FOR
    is set, because with no reverse proxy in front it is a client-supplied
    header and trusting it would let a client choose its own device identity.
    """
    addr = (remote_addr or "unknown").strip()
    host = ""
    try:
        import socket
        host = socket.gethostbyaddr(addr)[0]
    except Exception:
        host = ""
    label = f"{host} ({addr})" if host and host != addr else addr
    if user_agent:
        # Only enough of the agent string to tell a browser from a script.
        label += f" [{user_agent[:40]}]"
    return label


def authenticate(username: str, password: str, device: str = "") -> dict | None:
    """Return the user record on success, None otherwise. Logs both outcomes."""
    username = (username or "").strip().lower()
    ctx = {"device": device} if device else {}
    row = db.q1("SELECT * FROM users WHERE username=?", (username,))
    if row is None:
        # Hash anyway so a missing user and a wrong password take about the
        # same time; the portal is on a lab LAN but the habit is cheap.
        _hash(password or "", b"\x00" * 16)
        eventlog.emit("auth.failed", actor=username or "?", feature="identity",
                      subject=username or "?",
                      data={"reason": "no such user", **ctx})
        return None
    if row["disabled"]:
        eventlog.emit("auth.failed", actor=username, feature="identity",
                      subject=username, data={"reason": "account disabled", **ctx})
        return None
    if not hmac.compare_digest(_hash(password or "", row["pw_salt"]), row["pw_hash"]):
        eventlog.emit("auth.failed", actor=username, feature="identity",
                      subject=username, data={"reason": "bad password", **ctx})
        return None
    with db.tx() as c:
        c.execute("UPDATE users SET last_login_ts=? WHERE username=?",
                  (db.now(), username))
    eventlog.emit("auth.success", actor=username, feature="identity",
                  subject=username, data=ctx)
    return dict(row)


def list_users() -> list[dict]:
    return [dict(r) for r in db.q(
        "SELECT username, display_name, created_ts, last_login_ts, disabled"
        " FROM users ORDER BY username")]


def ensure_bootstrap_user() -> bool:
    """
    Seed one account on an empty database so the portal is reachable.
    Returns True if it created one. The seeding is logged, and the portal
    nags until the password is changed.
    """
    if db.q1("SELECT COUNT(*) AS n FROM users")["n"]:
        return False
    create_user(config.BOOTSTRAP_USER, config.BOOTSTRAP_PASSWORD,
                config.BOOTSTRAP_DISPLAY_NAME, actor="system:bootstrap")
    eventlog.emit("user.bootstrap_seeded", actor="system:bootstrap",
                  feature="identity", subject=config.BOOTSTRAP_USER,
                  data={"note": "default credentials from config.py -- change them"})
    return True


def using_default_password() -> bool:
    """True while the seeded account still has the config.py password."""
    row = db.q1("SELECT * FROM users WHERE username=?", (config.BOOTSTRAP_USER,))
    if row is None:
        return False
    return hmac.compare_digest(
        _hash(config.BOOTSTRAP_PASSWORD, row["pw_salt"]), row["pw_hash"])


if __name__ == "__main__":
    db.connect()
    if ensure_bootstrap_user():
        print(f"seeded bootstrap user '{config.BOOTSTRAP_USER}'")
    users = list_users()
    print(f"{len(users)} user(s)")
    for u in users:
        flag = " [disabled]" if u["disabled"] else ""
        print(f"  {u['username']:<16} {u['display_name']:<24} "
              f"last login {u['last_login_ts'] or 'never'}{flag}")
    if using_default_password():
        print("\nWARNING: the bootstrap account still has the config.py password.")
