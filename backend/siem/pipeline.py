"""One path into storage for every event source: API, syslog, host agent and simulator."""

import logging

from . import db, detection
from .events import ValidationError, insert_events, normalize
from .parsers import ParseError, parse_line, windows

log = logging.getLogger("siem.pipeline")


def prepare(item):
    """Turn one JSON item into a normalized event.

    Items can be already-structured events, Windows events (with an EventID), or
    `{"format": "...", "raw": "<log line>"}` to run a raw line through a parser.
    """
    if not isinstance(item, dict):
        raise ValidationError("event must be a JSON object")
    if "EventID" in item:
        fields = windows.parse(item)
        if fields is None:
            raise ValidationError("EventID: expected an integer")
    elif item.get("format"):
        if not isinstance(item.get("raw"), str):
            raise ValidationError("raw: required as a string when format is given")
        fields = parse_line(item["raw"], item["format"], item.get("host"))
    else:
        fields = item
    return normalize(fields)


def ingest_items(conn, items):
    """Store JSON items. Returns (new ids, list of {index, error})."""
    accepted, rejected = [], []
    for index, item in enumerate(items):
        try:
            accepted.append(prepare(item))
        except (ValidationError, ParseError) as exc:
            rejected.append({"index": index, "error": str(exc)})
    ids = insert_events(conn, accepted) if accepted else []
    detection.evaluate(conn, ids)
    return ids, rejected


def ingest_lines(conn, lines, fmt="auto", default_host=None):
    """Store raw log lines. Blank lines are skipped. Returns (new ids, list of {line, error})."""
    accepted, rejected = [], []
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            accepted.append(normalize(parse_line(line, fmt, default_host)))
        except (ValidationError, ParseError) as exc:
            rejected.append({"line": number, "error": str(exc)})
    ids = insert_events(conn, accepted) if accepted else []
    detection.evaluate(conn, ids)
    return ids, rejected


def store(db_path, items=(), lines=(), fmt="auto", default_host=None):
    """Convenience for background collectors: open a connection, ingest, close."""
    conn = db.connect(db_path)
    try:
        ids, rejected = ingest_items(conn, items) if items else ([], [])
        if lines:
            line_ids, line_rejected = ingest_lines(conn, lines, fmt, default_host)
            ids += line_ids
            rejected += line_rejected
    finally:
        conn.close()
    for problem in rejected[:5]:
        log.warning("Dropped event: %s", problem["error"])
    return ids
