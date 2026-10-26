import hmac

from flask import Blueprint, current_app, jsonify, request

from ..auth import login_required
from ..db import get_db
from ..events import ValidationError, get_event, search_events
from ..parsers import FORMATS
from ..pipeline import ingest_items, ingest_lines

bp = Blueprint("events", __name__, url_prefix="/api")


def _authorized():
    expected = current_app.config["SIEM"].INGEST_API_KEY
    supplied = request.headers.get("X-API-Key", "")
    return hmac.compare_digest(supplied.encode(), expected.encode())


def _too_many(count):
    max_batch = current_app.config["SIEM"].MAX_BATCH_SIZE
    if count > max_batch:
        return jsonify({"error": f"Batch too large: send at most {max_batch} events"}), 413
    return None


def _result(ids, rejected):
    return jsonify({"accepted": len(ids), "ids": ids, "rejected": rejected}), 202 if ids else 400


@bp.post("/ingest")
def ingest():
    """Accept one event object or a list of them. Valid events are stored even if others fail."""
    if not _authorized():
        return jsonify({"error": "Missing or invalid X-API-Key header"}), 401

    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"error": "Request body must be JSON"}), 400

    items = payload if isinstance(payload, list) else [payload]
    if not items:
        return jsonify({"error": "No events in request"}), 400
    return _too_many(len(items)) or _result(*ingest_items(get_db(), items))


@bp.post("/ingest/raw")
def ingest_raw():
    """Accept plain-text log lines, one per line. `?format=` picks a parser; `?host=` is the fallback host."""
    if not _authorized():
        return jsonify({"error": "Missing or invalid X-API-Key header"}), 401

    fmt = request.args.get("format", "auto")
    if fmt not in FORMATS:
        return jsonify({"error": f"Unknown format {fmt!r}. Use one of: {', '.join(FORMATS)}"}), 400

    lines = [line for line in request.get_data(as_text=True).splitlines() if line.strip()]
    if not lines:
        return jsonify({"error": "No log lines in request body"}), 400
    return _too_many(len(lines)) or _result(*ingest_lines(get_db(), lines, fmt, request.args.get("host")))


@bp.get("/events")
@login_required
def list_events():
    return jsonify(search_events(get_db(), request.args.to_dict()))


@bp.get("/events/<int:event_id>")
@login_required
def event_detail(event_id):
    event = get_event(get_db(), event_id)
    if event is None:
        return jsonify({"error": f"Event {event_id} not found"}), 404
    return jsonify(event)


@bp.errorhandler(ValidationError)
def handle_validation(exc):
    return jsonify({"error": str(exc)}), 400
