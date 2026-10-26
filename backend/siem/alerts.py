"""Reading alerts for the API. Alerts are created by the detection engine."""

import json
from datetime import timedelta

from .events import SEVERITIES, ValidationError, format_ts, parse_ts, utc_now

STATUSES = ("open", "acknowledged", "closed")
_SEVERITY_RANK = "CASE severity " + " ".join(f"WHEN '{s}' THEN {i}" for i, s in enumerate(SEVERITIES)) + " END"
SORTS = {
    "recent": "last_seen DESC, id DESC",
    "severity": f"{_SEVERITY_RANK} DESC, last_seen DESC, id DESC",
    "oldest": "first_seen ASC, id ASC",
}
LINKED_EVENT_LIMIT = 200


def like_escape(text):
    """Escape LIKE wildcards; use with ESCAPE '\\'."""
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _alert(row):
    alert = dict(row)
    alert["group_fields"] = json.loads(alert["group_fields"])
    return alert


def _csv(params, name, allowed):
    values = [v.strip().lower() for v in (params.get(name) or "").split(",") if v.strip()]
    unknown = set(values) - set(allowed)
    if unknown:
        raise ValidationError(f"{name}: unknown value {sorted(unknown)[0]!r}")
    return values


def list_alerts(conn, params, default_limit=50, max_limit=500):
    where, args = [], []

    for name in ("status", "severity"):
        values = _csv(params, name, STATUSES if name == "status" else SEVERITIES)
        if values:
            where.append(f"{name} IN ({', '.join('?' * len(values))})")
            args.extend(values)

    if params.get("rule_id"):
        where.append("rule_id = ?")
        args.append(params["rule_id"])
    if "assignee" in params:
        if params["assignee"]:
            where.append("assignee = ?")
            args.append(params["assignee"])
        else:
            where.append("assignee IS NULL")
    if params.get("q"):
        where.append("(title LIKE ? ESCAPE '\\' OR group_key LIKE ? ESCAPE '\\')")
        pattern = f"%{like_escape(params['q'].strip())}%"
        args.extend([pattern, pattern])
    if params.get("from"):
        where.append("last_seen >= ?")
        args.append(format_ts(parse_ts(params["from"], "from")))
    if params.get("to"):
        where.append("first_seen <= ?")
        args.append(format_ts(parse_ts(params["to"], "to")))

    try:
        limit = max(1, min(int(params.get("limit") or default_limit), max_limit))
        page = max(1, int(params.get("page") or 1))
    except ValueError:
        raise ValidationError("limit and page must be integers")

    sort = params.get("sort") or "recent"
    if sort not in SORTS:
        raise ValidationError(f"sort: must be one of {', '.join(SORTS)}")

    clause = f"WHERE {' AND '.join(where)}" if where else ""
    total = conn.execute(f"SELECT COUNT(*) FROM alerts {clause}", args).fetchone()[0]
    rows = conn.execute(
        f"SELECT * FROM alerts {clause} ORDER BY {SORTS[sort]} LIMIT ? OFFSET ?",
        [*args, limit, (page - 1) * limit],
    ).fetchall()
    return {"alerts": [_alert(r) for r in rows], "total": total, "page": page, "limit": limit}


def get_alert(conn, alert_id):
    row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if row is None:
        return None
    alert = _alert(row)
    alert["events"] = [dict(r) for r in conn.execute(
        "SELECT e.* FROM events e JOIN alert_events ae ON ae.event_id = e.id WHERE ae.alert_id = ? "
        "ORDER BY e.ts, e.id LIMIT ?",
        (alert_id, LINKED_EVENT_LIMIT),
    )]
    alert["notes"] = [dict(r) for r in conn.execute(
        "SELECT * FROM alert_notes WHERE alert_id = ? ORDER BY created_at, id", (alert_id,)
    )]
    return alert


def rule_hit_counts(conn, hours=24):
    since = format_ts(utc_now() - timedelta(hours=hours))
    return {
        row["rule_id"]: row["n"]
        for row in conn.execute(
            "SELECT rule_id, COUNT(*) AS n FROM alerts WHERE last_seen >= ? GROUP BY rule_id", (since,)
        )
    }


# --- Changes by analysts ----------------------------------------------------------------------

MAX_NOTE = 4000


def _note(conn, alert_id, author, body, kind, now):
    conn.execute(
        "INSERT INTO alert_notes (alert_id, author, body, created_at, kind) VALUES (?, ?, ?, ?, ?)",
        (alert_id, author, body, now, kind),
    )


def update_alert(conn, alert_id, changes, actor, known_users):
    """Apply status and/or assignee changes. Records each change in the alert's history.

    Returns the updated alert, or None if it does not exist.
    """
    allowed = {"status", "assignee"}
    unknown = set(changes) - allowed
    if unknown:
        raise ValidationError(f"{sorted(unknown)[0]}: cannot be changed; use status or assignee")
    if not changes:
        raise ValidationError("Send status and/or assignee")

    if "status" in changes and changes["status"] not in STATUSES:
        raise ValidationError(f"status: must be one of {', '.join(STATUSES)}")
    if "assignee" in changes:
        assignee = changes["assignee"] or None
        if assignee is not None and assignee not in known_users:
            raise ValidationError(f"assignee: no analyst named {assignee!r}")
        changes = {**changes, "assignee": assignee}

    row = conn.execute("SELECT status, assignee FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if row is None:
        return None

    now = format_ts(utc_now())
    with conn:
        for name, value in changes.items():
            if row[name] == value:
                continue
            conn.execute(f"UPDATE alerts SET {name} = ?, updated_at = ? WHERE id = ?", (value, now, alert_id))
            if name == "status":
                body = f"Changed status from {row['status']} to {value}"
            elif value is None:
                body = f"Unassigned {row['assignee']}"
            else:
                body = f"Assigned to {value}"
            _note(conn, alert_id, actor, body, "change", now)
    return get_alert(conn, alert_id)


def bulk_update_status(conn, alert_ids, status, actor):
    if status not in STATUSES:
        raise ValidationError(f"status: must be one of {', '.join(STATUSES)}")
    if not isinstance(alert_ids, list) or not alert_ids or not all(isinstance(i, int) for i in alert_ids):
        raise ValidationError("ids: send a list of alert ids")
    if len(alert_ids) > 500:
        raise ValidationError("ids: at most 500 alerts at a time")

    now = format_ts(utc_now())
    changed = []
    with conn:
        rows = conn.execute(
            "SELECT id, status FROM alerts WHERE id IN (SELECT value FROM json_each(?))", (json.dumps(alert_ids),)
        ).fetchall()
        for row in rows:
            if row["status"] == status:
                continue
            conn.execute("UPDATE alerts SET status = ?, updated_at = ? WHERE id = ?", (status, now, row["id"]))
            _note(conn, row["id"], actor, f"Changed status from {row['status']} to {status}", "change", now)
            changed.append(row["id"])
    return changed


def add_note(conn, alert_id, author, body):
    body = (body or "").strip() if isinstance(body, str) else ""
    if not body:
        raise ValidationError("body: write a note")
    if len(body) > MAX_NOTE:
        raise ValidationError(f"body: at most {MAX_NOTE} characters")
    if conn.execute("SELECT 1 FROM alerts WHERE id = ?", (alert_id,)).fetchone() is None:
        return None
    now = format_ts(utc_now())
    with conn:
        _note(conn, alert_id, author, body, "comment", now)
        conn.execute("UPDATE alerts SET updated_at = ? WHERE id = ?", (now, alert_id))
    return conn.execute(
        "SELECT * FROM alert_notes WHERE alert_id = ? ORDER BY id DESC LIMIT 1", (alert_id,)
    ).fetchone()
