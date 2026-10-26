"""Analyst accounts and session login for the dashboard.

Sessions use Flask's signed cookie. Requests that change data must also send the
session's CSRF token in the X-CSRF-Token header. Every login attempt is recorded as
an event, so the SIEM's own detection rules watch its login page.
"""

import functools
import hmac
import logging
import secrets
import threading
import time
from datetime import timedelta
from pathlib import Path

from flask import Blueprint, current_app, jsonify, request, session
from werkzeug.security import check_password_hash, generate_password_hash

from .db import get_db
from .events import format_ts, utc_now
from .pipeline import ingest_items

log = logging.getLogger("siem.auth")

bp = Blueprint("auth", __name__, url_prefix="/api/auth")

SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
MIN_PASSWORD_LENGTH = 10
LOCKOUT_FAILURES = 10
LOCKOUT_SECONDS = 300
# Compared against when the username does not exist, so both paths take the same time.
_DUMMY_HASH = generate_password_hash(secrets.token_hex(16))


# --- Accounts -------------------------------------------------------------------------------

def create_user(conn, username, password):
    username = (username or "").strip()
    if not username or len(username) > 64:
        raise ValueError("Username must be 1 to 64 characters")
    if len(password or "") < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    with conn:
        conn.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), format_ts(utc_now())),
        )


def set_password(conn, username, password):
    if len(password or "") < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    with conn:
        cur = conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?", (generate_password_hash(password), username)
        )
    if cur.rowcount == 0:
        raise KeyError(username)


def list_usernames(conn):
    return [row["username"] for row in conn.execute("SELECT username FROM users ORDER BY username")]


def ensure_admin(conn, config):
    """Create the first analyst account if there are none. Returns a generated password, or None."""
    if conn.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        return None
    password = config.ADMIN_PASSWORD or secrets.token_urlsafe(12)
    create_user(conn, config.ADMIN_USER, password)
    return None if config.ADMIN_PASSWORD else password


def load_secret_key(config):
    if config.SECRET_KEY:
        return config.SECRET_KEY
    path = Path(config.DB_PATH).with_name("secret_key")
    if path.exists():
        return path.read_text().strip()
    key = secrets.token_hex(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(key)
    return key


# --- Throttling -----------------------------------------------------------------------------

class LoginThrottle:
    """Refuse logins from an address after too many recent failures."""

    def __init__(self, limit=LOCKOUT_FAILURES, seconds=LOCKOUT_SECONDS):
        self.limit, self.seconds = limit, seconds
        self.failures = {}
        self.lock = threading.Lock()

    def _recent(self, key, now):
        return [t for t in self.failures.get(key, []) if now - t < self.seconds]

    def blocked(self, key):
        with self.lock:
            return len(self._recent(key, time.monotonic())) >= self.limit

    def fail(self, key):
        now = time.monotonic()
        with self.lock:
            self.failures[key] = self._recent(key, now) + [now]

    def reset(self, key):
        with self.lock:
            self.failures.pop(key, None)


# --- Request guards -------------------------------------------------------------------------

def check_session():
    """Return an error response if the request lacks a valid session (and CSRF token when needed)."""
    if request.method == "OPTIONS":
        return None
    if not session.get("user"):
        return jsonify({"error": "Sign in to continue"}), 401
    if request.method not in SAFE_METHODS:
        supplied = request.headers.get("X-CSRF-Token", "")
        if not hmac.compare_digest(supplied, session.get("csrf", "")):
            return jsonify({"error": "Missing or invalid X-CSRF-Token header"}), 403
    return None


def login_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        return check_session() or view(*args, **kwargs)
    return wrapper


def current_user():
    return session.get("user")


# --- Routes ---------------------------------------------------------------------------------

def _record(user, success, reason=None):
    message = f"Dashboard login {'succeeded' if success else 'failed'} for {user or 'unknown user'}"
    if reason:
        message += f" ({reason})"
    ingest_items(get_db(), [{
        "source": "siem", "host": "siem", "category": "authentication", "action": "login",
        "outcome": "success" if success else "failure", "severity": "info" if success else "low",
        "user": user or None, "src_ip": request.remote_addr, "message": message,
    }])


@bp.post("/login")
def login():
    throttle = current_app.extensions["siem_throttle"]
    address = request.remote_addr or "unknown"
    body = request.get_json(silent=True)
    body = body if isinstance(body, dict) else {}
    username = str(body.get("username") or "").strip()[:64]
    password = str(body.get("password") or "")

    if throttle.blocked(address):
        _record(username, False, "too many attempts")
        return jsonify({"error": "Too many failed sign-ins. Wait 5 minutes and try again."}), 429

    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    valid = check_password_hash(row["password_hash"] if row else _DUMMY_HASH, password)
    if not (row and valid):
        throttle.fail(address)
        _record(username, False)
        return jsonify({"error": "Username or password is incorrect"}), 401

    throttle.reset(address)
    with conn:
        conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (format_ts(utc_now()), row["id"]))
    session.clear()
    session.permanent = True
    session["user"] = row["username"]
    session["csrf"] = secrets.token_urlsafe(24)
    _record(row["username"], True)
    return jsonify({"user": row["username"], "csrf_token": session["csrf"]})


@bp.post("/logout")
@login_required
def logout():
    session.clear()
    return jsonify({"status": "signed out"})


@bp.get("/me")
@login_required
def me():
    return jsonify({"user": session["user"], "csrf_token": session["csrf"]})


@bp.get("/users")
@login_required
def users():
    return jsonify({"users": list_usernames(get_db())})


def init_app(app, config, conn):
    app.secret_key = load_secret_key(config)
    app.config.update(
        SESSION_COOKIE_NAME="siem_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=config.COOKIE_SECURE,
        SESSION_COOKIE_PATH=config.COOKIE_PATH,
        PERMANENT_SESSION_LIFETIME=timedelta(hours=config.SESSION_HOURS),
    )
    app.extensions["siem_throttle"] = LoginThrottle()
    app.register_blueprint(bp)

    generated = ensure_admin(conn, config)
    if generated:
        log.warning(
            "Created analyst account %r with password %s . Change it with: python manage.py set-password %s",
            config.ADMIN_USER, generated, config.ADMIN_USER,
        )
