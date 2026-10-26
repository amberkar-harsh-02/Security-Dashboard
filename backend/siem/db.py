import functools
import re
import sqlite3
from pathlib import Path

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,          -- event time, ISO 8601 UTC
    ingested_at TEXT NOT NULL,          -- time the SIEM received it, ISO 8601 UTC
    source      TEXT NOT NULL,          -- collector or log type, e.g. "sshd", "nginx", "api"
    host        TEXT,
    category    TEXT NOT NULL,          -- e.g. "authentication", "network", "web", "process"
    action      TEXT,                   -- e.g. "login", "connection", "http_request"
    outcome     TEXT,                   -- "success", "failure" or "unknown"
    severity    TEXT NOT NULL,          -- "info", "low", "medium", "high", "critical"
    user        TEXT,
    src_ip      TEXT,
    src_port    INTEGER,
    dst_ip      TEXT,
    dst_port    INTEGER,
    process     TEXT,
    message     TEXT NOT NULL,
    raw         TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_ts       ON events (ts);
CREATE INDEX IF NOT EXISTS idx_events_src_ip   ON events (src_ip, ts);
CREATE INDEX IF NOT EXISTS idx_events_user     ON events (user, ts);
CREATE INDEX IF NOT EXISTS idx_events_category ON events (category, ts);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events (severity, ts);

-- Full-text index over message and raw, kept in sync by triggers.
CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5 (
    message, raw, content='events', content_rowid='id'
);

CREATE TRIGGER IF NOT EXISTS events_ai AFTER INSERT ON events BEGIN
    INSERT INTO events_fts (rowid, message, raw) VALUES (new.id, new.message, new.raw);
END;

CREATE TRIGGER IF NOT EXISTS events_ad AFTER DELETE ON events BEGIN
    INSERT INTO events_fts (events_fts, rowid, message, raw)
    VALUES ('delete', old.id, old.message, old.raw);
END;

CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id         TEXT NOT NULL,
    rule_name       TEXT NOT NULL,
    severity        TEXT NOT NULL,
    title           TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'open',   -- "open", "acknowledged", "closed"
    assignee        TEXT,
    group_key       TEXT NOT NULL,                  -- e.g. "src_ip=203.0.113.9", used for deduplication
    group_fields    TEXT NOT NULL,                  -- the same values as a JSON object
    mitre_tactic    TEXT,
    mitre_technique TEXT,
    mitre_name      TEXT,
    event_count     INTEGER NOT NULL DEFAULT 0,
    first_seen      TEXT NOT NULL,                  -- time of the earliest linked event
    last_seen       TEXT NOT NULL,                  -- time of the latest linked event
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_dedupe  ON alerts (rule_id, group_key, last_seen);
CREATE INDEX IF NOT EXISTS idx_alerts_status  ON alerts (status, created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts (created_at);

CREATE TABLE IF NOT EXISTS alert_events (
    alert_id INTEGER NOT NULL REFERENCES alerts (id) ON DELETE CASCADE,
    event_id INTEGER NOT NULL,
    PRIMARY KEY (alert_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_alert_events_event ON alert_events (event_id);

-- Alerts outlive their events; drop links to events removed by retention.
CREATE TRIGGER IF NOT EXISTS events_ad_alert_links AFTER DELETE ON events BEGIN
    DELETE FROM alert_events WHERE event_id = old.id;
END;

CREATE TABLE IF NOT EXISTS alert_notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id   INTEGER NOT NULL REFERENCES alerts (id) ON DELETE CASCADE,
    author     TEXT,
    body       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    kind       TEXT NOT NULL DEFAULT 'comment'      -- "comment" by an analyst, "change" for status/assignee history
);

CREATE INDEX IF NOT EXISTS idx_alert_notes_alert ON alert_notes (alert_id, created_at);

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    last_login_at TEXT
);

-- Addresses blocked by analysts or by rule auto-block. expires_at NULL means permanent.
CREATE TABLE IF NOT EXISTS blocks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT NOT NULL,
    reason     TEXT,
    created_by TEXT NOT NULL,                       -- analyst name, or "rule:<rule id>"
    alert_id   INTEGER,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    removed_at TEXT,
    removed_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_blocks_ip ON blocks (ip, removed_at, expires_at);

-- Analyst overrides for rules defined in YAML: enable/disable and auto-block.
CREATE TABLE IF NOT EXISTS rule_settings (
    rule_id    TEXT PRIMARY KEY,
    enabled    INTEGER NOT NULL,
    updated_at TEXT NOT NULL
);
"""


@functools.lru_cache(maxsize=256)
def _compiled(pattern):
    return re.compile(pattern)


def _regexp(pattern, value):
    """SQLite REGEXP operator, used by detection rules."""
    if value is None:
        return False
    return _compiled(pattern).search(str(value)) is not None


def connect(db_path):
    """Open a connection outside the request cycle (background threads, scripts)."""
    if db_path != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.create_function("REGEXP", 2, _regexp, deterministic=True)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# Columns added after a table was first released: (table, column, definition).
# CREATE TABLE IF NOT EXISTS does not change existing tables, so add them here.
MIGRATIONS = [
    ("alert_notes", "kind", "TEXT NOT NULL DEFAULT 'comment'"),
    ("rule_settings", "auto_block_minutes", "INTEGER"),
]


def _migrate(conn):
    """Add missing columns to tables that exist. New tables get them from SCHEMA."""
    for table, column, definition in MIGRATIONS:
        existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        if existing and column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_schema(db_path):
    conn = connect(db_path)
    try:
        # Bring older tables up to date before the schema creates indexes on new columns.
        _migrate(conn)
        conn.executescript(SCHEMA)
        _migrate(conn)
        conn.commit()
    finally:
        conn.close()


def get_db():
    """Connection for the current request, closed on teardown."""
    if "db" not in g:
        g.db = connect(current_app.config["SIEM"].DB_PATH)
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()
