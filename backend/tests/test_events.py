from datetime import datetime, timezone

import pytest

from siem import db
from siem.events import ValidationError, insert_events, normalize, purge_older_than

NOW = datetime(2026, 10, 19, 12, 0, 0, tzinfo=timezone.utc)


def test_normalize_fills_defaults():
    event = normalize({"message": "hello"}, now=NOW)
    assert event["ts"] == "2026-10-19T12:00:00.000Z"
    assert event["severity"] == "info"
    assert event["outcome"] == "unknown"
    assert event["category"] == "unknown"
    assert event["source"] == "unknown"


@pytest.mark.parametrize(
    "ts, expected",
    [
        ("2026-10-19T10:15:00Z", "2026-10-19T10:15:00.000Z"),
        ("2026-10-19T03:15:00-07:00", "2026-10-19T10:15:00.000Z"),
        ("2026-10-19 10:15:00", "2026-10-19T10:15:00.000Z"),
        (1792404900, "2026-10-19T10:15:00.000Z"),
        (1792404900000, "2026-10-19T10:15:00.000Z"),
        ("1792404900", "2026-10-19T10:15:00.000Z"),
    ],
)
def test_normalize_timestamps(ts, expected):
    assert normalize({"message": "x", "ts": ts})["ts"] == expected


def test_normalize_uses_raw_when_message_missing():
    event = normalize({"raw": {"EventID": 4625}})
    assert event["message"] == '{"EventID": 4625}'
    assert event["raw"] == '{"EventID": 4625}'


@pytest.mark.parametrize(
    "data, field",
    [
        ({}, "message"),
        ({"message": "x", "severity": "urgent"}, "severity"),
        ({"message": "x", "outcome": "maybe"}, "outcome"),
        ({"message": "x", "src_ip": "999.1.1.1"}, "src_ip"),
        ({"message": "x", "dst_port": 70000}, "dst_port"),
        ({"message": "x", "ts": "yesterday"}, "ts"),
        ({"message": "x", "user": {"name": "a"}}, "user"),
    ],
)
def test_normalize_rejects_bad_fields(data, field):
    with pytest.raises(ValidationError, match=field):
        normalize(data)


def test_purge_removes_only_old_events(tmp_path):
    path = str(tmp_path / "p.db")
    db.init_schema(path)
    conn = db.connect(path)
    insert_events(conn, [
        normalize({"message": "old", "ts": "2026-10-01T00:00:00Z"}, now=NOW),
        normalize({"message": "new", "ts": "2026-10-18T00:00:00Z"}, now=NOW),
    ])
    assert purge_older_than(conn, days=7, now=NOW) == 1
    remaining = [r["message"] for r in conn.execute("SELECT message FROM events")]
    assert remaining == ["new"]
    # The full-text index must drop the deleted row too.
    hits = conn.execute("SELECT rowid FROM events_fts WHERE events_fts MATCH 'old'").fetchall()
    assert hits == []
    conn.close()
