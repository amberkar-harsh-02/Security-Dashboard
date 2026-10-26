"""Aggregates for the overview page and the sources page."""

from datetime import timedelta

from .events import SEVERITIES, ValidationError, format_ts, utc_now

# range name: (length, bucket size)
RANGES = {
    "1h": (timedelta(hours=1), timedelta(minutes=2)),
    "24h": (timedelta(hours=24), timedelta(hours=1)),
    "7d": (timedelta(days=7), timedelta(hours=6)),
}
TOP_N = 8

# Seconds since the Unix epoch for a stored ISO timestamp.
EPOCH = "CAST(strftime('%s', substr({col}, 1, 19)) AS INTEGER)"


def _buckets(start, end, size):
    """Bucket start times (epoch seconds) covering [start, end], aligned to the bucket size."""
    step = int(size.total_seconds())
    first = int(start.timestamp()) // step * step
    last = int(end.timestamp()) // step * step
    return list(range(first, last + step, step)), step


def overview(conn, range_name="24h", window_from=None, window_to=None, now=None):
    """Series for the whole range; totals and top lists for the selected window.

    The window (`window_from`/`window_to`, datetimes) defaults to the whole range. The
    dashboard sets it when an analyst drags across the alert band.
    """
    if range_name not in RANGES:
        raise ValidationError(f"range: must be one of {', '.join(RANGES)}")
    length, size = RANGES[range_name]
    now = now or utc_now()
    start = now - length
    since = format_ts(start)
    buckets, step = _buckets(start, now, size)

    scope_from = format_ts(window_from) if window_from else since
    scope_to = format_ts(window_to) if window_to else format_ts(now)
    if scope_from > scope_to:
        raise ValidationError("from: must be before to")

    alert_rows = conn.execute(
        f"SELECT ({EPOCH.format(col='first_seen')} / ?) * ? AS bucket, severity, COUNT(*) AS n "
        "FROM alerts WHERE first_seen >= ? GROUP BY bucket, severity",
        (step, step, since),
    ).fetchall()
    alert_series = {b: dict.fromkeys(SEVERITIES, 0) for b in buckets}
    for row in alert_rows:
        if row["bucket"] in alert_series:
            alert_series[row["bucket"]][row["severity"]] = row["n"]

    event_rows = conn.execute(
        f"SELECT ({EPOCH.format(col='ts')} / ?) * ? AS bucket, COUNT(*) AS n "
        "FROM events WHERE ts >= ? GROUP BY bucket",
        (step, step, since),
    ).fetchall()
    event_series = dict.fromkeys(buckets, 0)
    for row in event_rows:
        if row["bucket"] in event_series:
            event_series[row["bucket"]] = row["n"]

    # Open alerts with activity in the window: the triage queue for this period.
    active = "last_seen >= ? AND first_seen <= ?"
    open_by_severity = dict.fromkeys(SEVERITIES, 0)
    for row in conn.execute(
        f"SELECT severity, COUNT(*) AS n FROM alerts WHERE status = 'open' AND {active} GROUP BY severity",
        (scope_from, scope_to),
    ):
        open_by_severity[row["severity"]] = row["n"]

    top_sources = [dict(r) for r in conn.execute(
        "SELECT src_ip, COUNT(*) AS events, SUM(outcome = 'failure') AS failures, "
        "(SELECT COUNT(*) FROM alerts a WHERE json_extract(a.group_fields, '$.src_ip') = e.src_ip "
        " AND a.last_seen >= ? AND a.first_seen <= ?) AS alerts "
        "FROM events e WHERE ts BETWEEN ? AND ? AND src_ip IS NOT NULL "
        "GROUP BY src_ip ORDER BY alerts DESC, failures DESC, events DESC LIMIT ?",
        (scope_from, scope_to, scope_from, scope_to, TOP_N),
    )]
    top_rules = [dict(r) for r in conn.execute(
        # A rule always raises alerts at its own severity, so any row's value is the rule's.
        f"SELECT rule_id, rule_name, severity, COUNT(*) AS alerts FROM alerts WHERE {active} "
        "GROUP BY rule_id ORDER BY alerts DESC LIMIT ?",
        (scope_from, scope_to, TOP_N),
    )]
    top_failed_users = [dict(r) for r in conn.execute(
        "SELECT user, COUNT(*) AS failures, COUNT(DISTINCT src_ip) AS addresses FROM events "
        "WHERE ts BETWEEN ? AND ? AND category = 'authentication' AND outcome = 'failure' AND user IS NOT NULL "
        "GROUP BY user ORDER BY failures DESC LIMIT ?",
        (scope_from, scope_to, TOP_N),
    )]

    return {
        "range": range_name,
        "from": since,
        "to": format_ts(now),
        "window": {"from": scope_from, "to": scope_to},
        "bucket_seconds": step,
        "totals": {
            "events": conn.execute(
                "SELECT COUNT(*) FROM events WHERE ts BETWEEN ? AND ?", (scope_from, scope_to)
            ).fetchone()[0],
            "alerts": conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE first_seen BETWEEN ? AND ?", (scope_from, scope_to)
            ).fetchone()[0],
            "open_alerts": sum(open_by_severity.values()),
            "events_last_minute": conn.execute(
                "SELECT COUNT(*) FROM events WHERE ts >= ?", (format_ts(now - timedelta(minutes=1)),)
            ).fetchone()[0],
        },
        "open_by_severity": open_by_severity,
        "alert_series": [{"start": b, **alert_series[b]} for b in buckets],
        "event_series": [{"start": b, "events": event_series[b]} for b in buckets],
        "top_sources": top_sources,
        "top_rules": top_rules,
        "top_failed_users": top_failed_users,
    }


def sources(conn, now=None):
    """Each (source, host) seen in the last 24 hours, with volume and last event time."""
    now = now or utc_now()
    since = format_ts(now - timedelta(hours=24))
    hour_ago = format_ts(now - timedelta(hours=1))
    rows = conn.execute(
        "SELECT source, host, COUNT(*) AS events_24h, SUM(ts >= ?) AS events_1h, MAX(ts) AS last_seen "
        "FROM events WHERE ts >= ? GROUP BY source, host ORDER BY last_seen DESC",
        (hour_ago, since),
    ).fetchall()
    return [dict(r) for r in rows]
