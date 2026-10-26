import textwrap
from datetime import datetime, timedelta, timezone

import pytest

from siem import db, detection, simulator
from siem.config import BACKEND_DIR
from siem.detection.rules import RuleError, build_rule, compile_where, load_rules
from siem.pipeline import ingest_items, ingest_lines

T0 = datetime(2026, 10, 19, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def setup(tmp_path):
    """A database plus an engine loading rules written by the test."""
    db_path = str(tmp_path / "d.db")
    db.init_schema(db_path)
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    intel_dir = tmp_path / "intel"
    intel_dir.mkdir()
    (intel_dir / "bad_ips.txt").write_text("# test list\n192.0.2.66\n")
    conn = db.connect(db_path)

    def use_rules(text):
        (rules_dir / "rules.yml").write_text(textwrap.dedent(text))
        engine = detection.Engine(str(rules_dir), str(intel_dir))
        detection.configure(engine)
        return engine

    yield conn, use_rules
    detection.configure(None)
    conn.close()


def send(conn, *events):
    ids, rejected = ingest_items(conn, list(events))
    assert not rejected
    return ids


def alerts(conn):
    return [dict(r) for r in conn.execute("SELECT * FROM alerts ORDER BY id")]


def at(seconds):
    return (T0 + timedelta(seconds=seconds)).isoformat()


def fail(ip, seconds, user="root", **extra):
    return {"ts": at(seconds), "source": "sshd", "category": "authentication", "action": "login",
            "outcome": "failure", "user": user, "src_ip": ip, "message": "Failed password", **extra}


# --- Rule types --------------------------------------------------------------------------------

def test_match_rule_groups_and_dedupes(setup):
    conn, use_rules = setup
    use_rules("""
        id: m
        name: Match
        severity: high
        type: match
        where: {category: web, message|contains: "(possible "}
        group_by: [src_ip]
        title: "Attack from {src_ip}"
    """)
    send(conn, {"ts": at(0), "category": "web", "src_ip": "203.0.113.1", "message": "GET /x (possible sql injection)"})
    send(conn, {"ts": at(30), "category": "web", "src_ip": "203.0.113.1", "message": "GET /y (POSSIBLE path traversal)"})
    send(conn, {"ts": at(40), "category": "web", "src_ip": "203.0.113.2", "message": "GET / 200"})
    found = alerts(conn)
    assert len(found) == 1
    assert found[0]["title"] == "Attack from 203.0.113.1"
    assert found[0]["event_count"] == 2


def test_threshold_rule(setup):
    conn, use_rules = setup
    use_rules("""
        id: t
        name: Threshold
        severity: high
        type: threshold
        where: {outcome: failure}
        group_by: [src_ip]
        window: 1m
        threshold: 5
    """)
    # Four failures, then a fifth outside the window: no alert.
    for i in range(4):
        send(conn, fail("203.0.113.5", i))
    send(conn, fail("203.0.113.5", 120))
    assert alerts(conn) == []

    # Four more inside the window of the last one: alert with all five.
    send(conn, *[fail("203.0.113.5", 121 + i) for i in range(4)])
    found = alerts(conn)
    assert len(found) == 1
    assert found[0]["event_count"] == 5
    assert found[0]["group_key"] == "src_ip=203.0.113.5"

    # More failures extend the same alert instead of creating a new one.
    send(conn, fail("203.0.113.5", 130))
    found = alerts(conn)
    assert len(found) == 1
    assert found[0]["event_count"] == 6


def test_distinct_rule(setup):
    conn, use_rules = setup
    use_rules("""
        id: d
        name: Distinct
        severity: high
        type: distinct
        where: {outcome: failure}
        field: user
        group_by: [src_ip]
        window: 5m
        threshold: 3
    """)
    send(conn, *[fail("203.0.113.7", i, user="root") for i in range(10)])
    assert alerts(conn) == []
    send(conn, fail("203.0.113.7", 20, user="alice"), fail("203.0.113.7", 21, user="bob"))
    assert len(alerts(conn)) == 1


def test_sequence_rule(setup):
    conn, use_rules = setup
    use_rules("""
        id: s
        name: Sequence
        severity: critical
        type: sequence
        steps:
          - where: {outcome: failure}
            count: 3
          - where: {outcome: success}
        group_by: [src_ip]
        window: 5m
        title: "{user} in from {src_ip}"
    """)
    ok = {"ts": at(60), "category": "authentication", "outcome": "success", "user": "admin",
          "src_ip": "203.0.113.9", "message": "Accepted password"}
    send(conn, fail("203.0.113.9", 0), fail("203.0.113.9", 1))
    send(conn, ok)
    assert alerts(conn) == []  # only two failures before the success

    send(conn, fail("203.0.113.9", 70), fail("203.0.113.9", 71), fail("203.0.113.9", 72))
    send(conn, {**ok, "ts": at(80)})
    found = alerts(conn)
    assert len(found) == 1
    assert found[0]["title"] == "admin in from 203.0.113.9"
    assert found[0]["event_count"] == 6  # five failures in the window plus the success


def test_ioc_rule(setup):
    conn, use_rules = setup
    use_rules("""
        id: i
        name: IOC
        severity: high
        type: ioc
        field: src_ip
        list: bad_ips
        group_by: [src_ip]
    """)
    send(conn, {"src_ip": "192.0.2.1", "message": "fine"})
    send(conn, {"src_ip": "192.0.2.66", "message": "bad"})
    found = alerts(conn)
    assert [a["group_key"] for a in found] == ["src_ip=192.0.2.66"]


def test_closed_alert_is_not_reused(setup):
    conn, use_rules = setup
    use_rules("""
        id: m
        name: Match
        severity: low
        type: match
        where: {outcome: failure}
        group_by: [src_ip]
    """)
    send(conn, fail("203.0.113.3", 0))
    conn.execute("UPDATE alerts SET status = 'closed'")
    conn.commit()
    send(conn, fail("203.0.113.3", 10))
    assert len(alerts(conn)) == 2


def test_dedupe_window_expires(setup):
    conn, use_rules = setup
    use_rules("""
        id: m
        name: Match
        severity: low
        type: match
        where: {outcome: failure}
        group_by: [src_ip]
        dedupe: 10m
    """)
    send(conn, fail("203.0.113.3", 0))
    send(conn, fail("203.0.113.3", 300))
    send(conn, fail("203.0.113.3", 2000))
    assert [a["event_count"] for a in alerts(conn)] == [2, 1]


def test_disabled_rule_does_not_fire(setup):
    conn, use_rules = setup
    engine = use_rules("""
        id: m
        name: Match
        severity: low
        type: match
        where: {outcome: failure}
        group_by: [src_ip]
    """)
    engine.set_enabled(conn, "m", False)
    send(conn, fail("203.0.113.3", 0))
    assert alerts(conn) == []
    engine.set_enabled(conn, "m", True)
    send(conn, fail("203.0.113.3", 1))
    assert len(alerts(conn)) == 1


def test_events_missing_group_field_are_skipped(setup):
    conn, use_rules = setup
    use_rules("""
        id: m
        name: Match
        severity: low
        type: match
        where: {outcome: failure}
        group_by: [src_ip]
    """)
    send(conn, {"outcome": "failure", "message": "no address"})
    assert alerts(conn) == []


def test_broken_rule_does_not_block_ingest(setup, monkeypatch):
    conn, use_rules = setup
    engine = use_rules("""
        id: m
        name: Match
        severity: low
        type: match
        where: {outcome: failure}
        group_by: [src_ip]
    """)
    monkeypatch.setattr(engine, "_run_match", lambda *a: 1 / 0)
    assert len(send(conn, fail("203.0.113.3", 0))) == 1


# --- Rule validation ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "data, message",
    [
        ({"name": "x", "type": "match", "severity": "low"}, "id"),
        ({"id": "Bad_ID", "name": "x", "type": "match", "severity": "low"}, "lowercase"),
        ({"id": "x", "name": "x", "type": "fuzzy", "severity": "low"}, "type"),
        ({"id": "x", "name": "x", "type": "match", "severity": "urgent"}, "severity"),
        ({"id": "x", "name": "x", "type": "match", "severity": "low", "where": {"colour": "red"}}, "unknown field"),
        ({"id": "x", "name": "x", "type": "match", "severity": "low", "where": {"user|fuzzy": "a"}}, "operator"),
        ({"id": "x", "name": "x", "type": "match", "severity": "low", "where": {"raw|regex": "("}}, "regex"),
        ({"id": "x", "name": "x", "type": "threshold", "severity": "low", "threshold": 5}, "group_by"),
        ({"id": "x", "name": "x", "type": "threshold", "severity": "low", "group_by": "src_ip"}, "threshold"),
        ({"id": "x", "name": "x", "type": "match", "severity": "low", "window": "five minutes"}, "duration"),
        ({"id": "x", "name": "x", "type": "sequence", "severity": "low", "group_by": "user", "steps": [{}]}, "two steps"),
        ({"id": "x", "name": "x", "type": "ioc", "severity": "low", "field": "src_ip", "list": "nope"}, "intel list"),
    ],
)
def test_invalid_rules_are_rejected(data, message):
    with pytest.raises(RuleError, match=message):
        build_rule(data, intel={"bad_ips": set()})


def test_compile_where_escapes_like_wildcards():
    sql, params = compile_where({"message|contains": "100%_done"})
    assert params == ["%100\\%\\_done%"]
    assert "ESCAPE" in sql


def test_bundled_rules_load():
    rules = load_rules(BACKEND_DIR / "rules")
    assert len(rules) >= 10
    assert all(rule.description for rule in rules.values())


# --- End to end: every scenario raises the alerts it should ------------------------------------

EXPECTED = {
    "brute_force": {"ssh-brute-force", "brute-force-success"},
    "password_spray": {"password-spray"},
    "port_scan": {"port-scan"},
    "web_attack": {"web-attack", "web-scanner"},
    "privilege_escalation": {"new-local-account", "privileged-group-change", "audit-log-cleared", "encoded-powershell"},
    "known_bad_ip": {"known-bad-source"},
}


@pytest.mark.parametrize("scenario", list(EXPECTED))
def test_scenarios_raise_expected_alerts(tmp_path, scenario):
    db_path = str(tmp_path / "e.db")
    db.init_schema(db_path)
    detection.configure(detection.Engine(str(BACKEND_DIR / "rules"), str(BACKEND_DIR / "intel")))
    try:
        simulator.run_scenario(db_path, scenario)
    finally:
        detection.configure(None)
    conn = db.connect(db_path)
    fired = {row["rule_id"] for row in conn.execute("SELECT rule_id FROM alerts")}
    conn.close()
    assert fired == EXPECTED[scenario]


def test_noise_raises_no_alerts(tmp_path):
    db_path = str(tmp_path / "n.db")
    db.init_schema(db_path)
    detection.configure(detection.Engine(str(BACKEND_DIR / "rules"), str(BACKEND_DIR / "intel")))
    conn = db.connect(db_path)
    try:
        start = datetime.now(timezone.utc) - timedelta(minutes=10)
        lines = []
        for i in range(1200):  # about 10 minutes of noise at 2 events per second
            line, host = simulator.noise_line(start + timedelta(milliseconds=500 * i))
            lines.append((line, host))
        for line, host in lines:
            ingest_lines(conn, [line], default_host=host)
        fired = [row["rule_id"] for row in conn.execute("SELECT rule_id FROM alerts")]
    finally:
        detection.configure(None)
        conn.close()
    assert fired == []

