import json
import time
from datetime import timedelta

from flask import Blueprint, Response, current_app, jsonify, request

from .. import db
from ..auth import check_session
from ..config import DEFAULT_INGEST_KEY
from ..db import get_db
from ..events import ValidationError, format_ts, parse_ts, utc_now
from ..stats import overview, sources

bp = Blueprint("stats", __name__, url_prefix="/api")
bp.before_request(check_session)

STATS_EVERY_SECONDS = 5


@bp.get("/stats/overview")
def stats_overview():
    args = request.args
    window_from = parse_ts(args["from"], "from") if args.get("from") else None
    window_to = parse_ts(args["to"], "to") if args.get("to") else None
    return jsonify(overview(get_db(), args.get("range", "24h"), window_from, window_to))


@bp.get("/performance")
def performance():
    since = request.args.get("since")
    try:
        since = int(since) if since else None
    except ValueError:
        raise ValidationError("since: expected epoch milliseconds")
    return jsonify(current_app.extensions["siem_performance"].snapshot(since))


@bp.get("/sources")
def list_sources():
    config = current_app.config["SIEM"]
    return jsonify({
        "sources": sources(get_db()),
        # How logs reach this SIEM, so the sources page can tell analysts where to send them.
        "collectors": {
            "syslog": {"enabled": bool(config.SYSLOG_PORT), "host": config.SYSLOG_HOST, "port": config.SYSLOG_PORT},
            "host_agent": {"enabled": config.HOST_AGENT_ENABLED, "interval_seconds": config.HOST_AGENT_INTERVAL},
            "simulator": {"enabled": config.SIMULATOR_ENABLED, "noise_per_second": config.NOISE_RATE},
            "ingest_api": {"path": "/api/ingest", "raw_path": "/api/ingest/raw", "default_key": config.INGEST_API_KEY == DEFAULT_INGEST_KEY},
        },
    })


def _sse(event, data):
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"


@bp.get("/stream")
def stream():
    """Server-sent events: `alert` when an alert is created or changes, `stats` every few seconds.

    The stream closes after STREAM_MAX_SECONDS; browsers reconnect on their own.
    """
    config = current_app.config["SIEM"]

    def generate():
        conn = db.connect(config.DB_PATH)
        try:
            last_id = conn.execute("SELECT COALESCE(MAX(id), 0) FROM alerts").fetchone()[0]
            cursor = format_ts(utc_now())
            started = time.monotonic()
            next_stats = started
            yield "retry: 3000\n\n"
            while time.monotonic() - started < config.STREAM_MAX_SECONDS:
                rows = conn.execute(
                    "SELECT * FROM alerts WHERE id > ? OR updated_at > ? ORDER BY id", (last_id, cursor)
                ).fetchall()
                for row in rows:
                    alert = dict(row)
                    alert["group_fields"] = json.loads(alert["group_fields"])
                    yield _sse("alert", {"created": row["id"] > last_id, "alert": alert})
                if rows:
                    last_id = max(last_id, max(r["id"] for r in rows))
                    cursor = max(cursor, max(r["updated_at"] for r in rows))

                if time.monotonic() >= next_stats:
                    minute_ago = format_ts(utc_now() - timedelta(minutes=1))
                    yield _sse("stats", {
                        "events_last_minute": conn.execute(
                            "SELECT COUNT(*) FROM events WHERE ts >= ?", (minute_ago,)
                        ).fetchone()[0],
                        "open_alerts": conn.execute(
                            "SELECT COUNT(*) FROM alerts WHERE status = 'open'"
                        ).fetchone()[0],
                    })
                    next_stats = time.monotonic() + STATS_EVERY_SECONDS
                time.sleep(config.STREAM_POLL_SECONDS)
        finally:
            conn.close()

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@bp.errorhandler(ValidationError)
def handle_validation(exc):
    return jsonify({"error": str(exc)}), 400
