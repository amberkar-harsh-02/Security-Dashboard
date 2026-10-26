"""Normalized event model: validation, storage and search."""

import ipaddress
import json
from datetime import datetime, timedelta, timezone

SEVERITIES = ("info", "low", "medium", "high", "critical")
OUTCOMES = ("success", "failure", "unknown")

TEXT_FIELDS = ("source", "host", "category", "action", "user", "process")
COLUMNS = (
    "ts", "ingested_at", "source", "host", "category", "action", "outcome", "severity",
    "user", "src_ip", "src_port", "dst_ip", "dst_port", "process", "message", "raw",
)

MAX_TEXT = 256
MAX_MESSAGE = 8 * 1024
MAX_RAW = 32 * 1024


class ValidationError(ValueError):
    pass


def utc_now():
    return datetime.now(timezone.utc)


def format_ts(dt):
    """Fixed-width ISO 8601 UTC string, so text order equals time order."""
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_ts(value, field="ts"):
    """Accept ISO 8601 strings or Unix epoch seconds/milliseconds. Naive times are UTC."""
    if isinstance(value, bool):
        raise ValidationError(f"{field}: expected a timestamp")
    if isinstance(value, (int, float)):
        seconds = value / 1000 if value > 1e11 else value
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            raise ValidationError(f"{field}: epoch value out of range")
    if isinstance(value, str):
        text = value.strip()
        if text.replace(".", "", 1).isdigit():
            return parse_ts(float(text), field)
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            raise ValidationError(f"{field}: not an ISO 8601 timestamp or epoch number")
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    raise ValidationError(f"{field}: expected a timestamp")


def _text(value, field, limit=MAX_TEXT):
    if value is None:
        return None
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        raise ValidationError(f"{field}: expected a string")
    text = str(value).strip()
    return text[:limit] or None


def _ip(value, field):
    if value in (None, ""):
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        raise ValidationError(f"{field}: not a valid IP address")


def _port(value, field):
    if value in (None, ""):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValidationError(f"{field}: expected an integer")
    if not 0 <= port <= 65535:
        raise ValidationError(f"{field}: must be between 0 and 65535")
    return port


def normalize(data, now=None):
    """Turn an incoming JSON object into a row dict for the events table."""
    if not isinstance(data, dict):
        raise ValidationError("event must be a JSON object")

    now = now or utc_now()
    event = {name: _text(data.get(name), name) for name in TEXT_FIELDS}

    event["ts"] = format_ts(parse_ts(data["ts"]) if data.get("ts") is not None else now)
    event["ingested_at"] = format_ts(now)

    severity = (data.get("severity") or "info").lower()
    if severity not in SEVERITIES:
        raise ValidationError(f"severity: must be one of {', '.join(SEVERITIES)}")
    event["severity"] = severity

    outcome = (data.get("outcome") or "unknown").lower()
    if outcome not in OUTCOMES:
        raise ValidationError(f"outcome: must be one of {', '.join(OUTCOMES)}")
    event["outcome"] = outcome

    event["src_ip"] = _ip(data.get("src_ip"), "src_ip")
    event["dst_ip"] = _ip(data.get("dst_ip"), "dst_ip")
    event["src_port"] = _port(data.get("src_port"), "src_port")
    event["dst_port"] = _port(data.get("dst_port"), "dst_port")

    raw = data.get("raw")
    if raw is not None and not isinstance(raw, str):
        raw = json.dumps(raw, default=str)
    event["raw"] = raw[:MAX_RAW] if raw else None

    message = _text(data.get("message"), "message", MAX_MESSAGE) or (
        event["raw"][:MAX_MESSAGE] if event["raw"] else None
    )
    if not message:
        raise ValidationError("message: required (or provide raw)")
    event["message"] = message

    event["source"] = event["source"] or "unknown"
    event["category"] = (event["category"] or "unknown").lower()
    return event


def insert_events(conn, events):
    """Insert normalized events in one transaction. Returns the new row ids."""
    sql = f"INSERT INTO events ({', '.join(COLUMNS)}) VALUES ({', '.join('?' * len(COLUMNS))})"
    ids = []
    with conn:
        for event in events:
            cur = conn.execute(sql, [event[c] for c in COLUMNS])
            ids.append(cur.lastrowid)
    return ids


def _fts_query(text):
    """Turn free text into a safe FTS5 query: every word must appear, as a prefix."""
    terms = [t.replace('"', "") for t in text.split()]
    return " ".join(f'"{t}"*' for t in terms if t)


EXACT_FILTERS = ("source", "host", "category", "outcome", "user", "src_ip", "dst_ip", "action")


def search_events(conn, params, default_limit=50, max_limit=500):
    """Filter, full-text search and paginate events. `params` is a dict of strings."""
    where, args = [], []

    query = (params.get("q") or "").strip()
    if query:
        fts = _fts_query(query)
        if fts:
            where.append("id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)")
            args.append(fts)

    if params.get("from"):
        where.append("ts >= ?")
        args.append(format_ts(parse_ts(params["from"], "from")))
    if params.get("to"):
        where.append("ts <= ?")
        args.append(format_ts(parse_ts(params["to"], "to")))

    if params.get("severity"):
        levels = [s.strip().lower() for s in params["severity"].split(",") if s.strip()]
        unknown = set(levels) - set(SEVERITIES)
        if unknown:
            raise ValidationError(f"severity: unknown value {sorted(unknown)[0]!r}")
        where.append(f"severity IN ({', '.join('?' * len(levels))})")
        args.extend(levels)

    for name in EXACT_FILTERS:
        if params.get(name):
            where.append(f"{name} = ?")
            args.append(params[name].strip())

    if params.get("ip"):
        where.append("(src_ip = ? OR dst_ip = ?)")
        args.extend([params["ip"].strip()] * 2)

    try:
        limit = int(params.get("limit") or default_limit)
        page = int(params.get("page") or 1)
    except ValueError:
        raise ValidationError("limit and page must be integers")
    limit = max(1, min(limit, max_limit))
    page = max(1, page)

    clause = f"WHERE {' AND '.join(where)}" if where else ""
    total = conn.execute(f"SELECT COUNT(*) FROM events {clause}", args).fetchone()[0]
    rows = conn.execute(
        f"SELECT * FROM events {clause} ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?",
        [*args, limit, (page - 1) * limit],
    ).fetchall()

    return {
        "events": [dict(row) for row in rows],
        "total": total,
        "page": page,
        "limit": limit,
    }


def get_event(conn, event_id):
    row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    return dict(row) if row else None


def purge_older_than(conn, days, now=None):
    """Delete events older than the retention window. Returns the number removed."""
    cutoff = format_ts((now or utc_now()) - timedelta(days=days))
    with conn:
        cur = conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
    return cur.rowcount
