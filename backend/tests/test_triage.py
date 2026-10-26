import json

from siem import db
from siem.auth import create_user


def run(client, scenario):
    assert client.post(f"/api/simulate/{scenario}").status_code == 201


def first_alert(client, rule_id):
    alerts = client.get(f"/api/alerts?rule_id={rule_id}").get_json()["alerts"]
    assert alerts, f"no alert for {rule_id}"
    return alerts[0]


def test_alert_list_filters(client):
    run(client, "brute_force")
    run(client, "port_scan")
    body = client.get("/api/alerts").get_json()
    assert body["total"] == 3
    assert client.get("/api/alerts?severity=critical").get_json()["total"] == 1
    assert client.get("/api/alerts?q=port scan").get_json()["total"] == 1
    assert client.get("/api/alerts?q=100%25").get_json()["total"] == 0  # % is literal, not a wildcard
    assert client.get("/api/alerts?assignee=").get_json()["total"] == 3
    assert client.get("/api/alerts?status=closed").get_json()["total"] == 0
    assert client.get("/api/alerts?status=done").status_code == 400


def test_change_status_and_assignee(client):
    run(client, "port_scan")
    alert = first_alert(client, "port-scan")

    res = client.patch(f"/api/alerts/{alert['id']}", json={"status": "acknowledged", "assignee": "admin"})
    assert res.status_code == 200
    updated = res.get_json()
    assert (updated["status"], updated["assignee"]) == ("acknowledged", "admin")
    history = [n["body"] for n in updated["notes"] if n["kind"] == "change"]
    assert history == ["Changed status from open to acknowledged", "Assigned to admin"]

    # Same values again: no new history entries.
    again = client.patch(f"/api/alerts/{alert['id']}", json={"status": "acknowledged"}).get_json()
    assert len(again["notes"]) == 2

    unassigned = client.patch(f"/api/alerts/{alert['id']}", json={"assignee": None}).get_json()
    assert unassigned["assignee"] is None
    assert unassigned["notes"][-1]["body"] == "Unassigned admin"
    assert client.get("/api/alerts?assignee=admin").get_json()["total"] == 0


def test_change_alert_validation(client):
    run(client, "port_scan")
    alert_id = first_alert(client, "port-scan")["id"]
    assert client.patch(f"/api/alerts/{alert_id}", json={"status": "done"}).status_code == 400
    assert client.patch(f"/api/alerts/{alert_id}", json={"assignee": "ghost"}).status_code == 400
    assert client.patch(f"/api/alerts/{alert_id}", json={"severity": "low"}).status_code == 400
    assert client.patch(f"/api/alerts/{alert_id}", json={}).status_code == 400
    assert client.patch(f"/api/alerts/{alert_id}", data="x").status_code == 400
    assert client.patch("/api/alerts/999", json={"status": "closed"}).status_code == 404


def test_assign_to_other_analyst(client, app):
    conn = db.connect(app.config["SIEM"].DB_PATH)
    create_user(conn, "bob", "another-long-password")
    conn.close()
    run(client, "port_scan")
    alert_id = first_alert(client, "port-scan")["id"]
    res = client.patch(f"/api/alerts/{alert_id}", json={"assignee": "bob"})
    assert res.get_json()["assignee"] == "bob"
    assert res.get_json()["notes"][0]["author"] == "admin"


def test_bulk_status(client):
    run(client, "brute_force")
    ids = [a["id"] for a in client.get("/api/alerts").get_json()["alerts"]]
    res = client.post("/api/alerts/bulk", json={"ids": ids + [999], "status": "closed"})
    assert sorted(res.get_json()["changed"]) == sorted(ids)
    assert client.get("/api/alerts?status=open").get_json()["total"] == 0
    assert client.post("/api/alerts/bulk", json={"ids": "1", "status": "closed"}).status_code == 400
    assert client.post("/api/alerts/bulk", json={"ids": ids, "status": "gone"}).status_code == 400


def test_notes(client):
    run(client, "port_scan")
    alert_id = first_alert(client, "port-scan")["id"]
    res = client.post(f"/api/alerts/{alert_id}/notes", json={"body": "  Blocked at the edge firewall.  "})
    assert res.status_code == 201
    assert res.get_json()["body"] == "Blocked at the edge firewall."
    assert res.get_json()["author"] == "admin"
    notes = client.get(f"/api/alerts/{alert_id}").get_json()["notes"]
    assert [n["kind"] for n in notes] == ["comment"]
    assert client.post(f"/api/alerts/{alert_id}/notes", json={"body": "   "}).status_code == 400
    assert client.post("/api/alerts/999/notes", json={"body": "x"}).status_code == 404


def test_closed_alert_starts_a_new_one(client):
    run(client, "port_scan")
    alert_id = first_alert(client, "port-scan")["id"]
    client.patch(f"/api/alerts/{alert_id}", json={"status": "closed"})
    run(client, "port_scan")  # a new attacker address, so a new alert regardless
    assert client.get("/api/alerts?rule_id=port-scan").get_json()["total"] == 2


def test_toggle_rule(client):
    res = client.patch("/api/rules/port-scan", json={"enabled": False})
    assert res.status_code == 200
    assert res.get_json()["enabled"] is False
    run(client, "port_scan")
    assert client.get("/api/alerts?rule_id=port-scan").get_json()["total"] == 0

    client.patch("/api/rules/port-scan", json={"enabled": True})
    run(client, "port_scan")
    assert client.get("/api/alerts?rule_id=port-scan").get_json()["total"] == 1
    rules = {r["id"]: r for r in client.get("/api/rules").get_json()["rules"]}
    assert rules["port-scan"]["alerts_24h"] == 1

    assert client.patch("/api/rules/port-scan", json={"enabled": "no"}).status_code == 400
    assert client.patch("/api/rules/nope", json={"enabled": True}).status_code == 404


def test_reload_rules_keeps_old_rules_on_error(client, app, tmp_path):
    engine = app.extensions["siem_engine"]
    count = len(engine.rules)
    assert client.post("/api/rules/reload").status_code == 200

    broken = tmp_path / "rules"
    broken.mkdir()
    (broken / "bad.yml").write_text("id: bad\nname: Bad\ntype: nope\nseverity: low\n")
    engine.rules_dir = str(broken)
    res = client.post("/api/rules/reload")
    assert res.status_code == 400
    assert "bad.yml" in res.get_json()["error"]
    assert len(engine.rules) == count


def test_overview(client):
    run(client, "brute_force")
    run(client, "password_spray")
    body = client.get("/api/stats/overview?range=24h").get_json()
    assert body["bucket_seconds"] == 3600
    assert len(body["alert_series"]) in (24, 25)
    assert body["totals"]["alerts"] == 3
    assert body["totals"]["open_alerts"] == 3
    assert body["open_by_severity"]["critical"] == 1
    assert sum(b["critical"] + b["high"] for b in body["alert_series"]) == 3
    assert body["totals"]["events"] == sum(b["events"] for b in body["event_series"])
    assert body["top_sources"][0]["alerts"] >= 1
    assert {r["rule_id"] for r in body["top_rules"]} == {"ssh-brute-force", "brute-force-success", "password-spray"}
    assert body["top_failed_users"]

    assert client.get("/api/stats/overview?range=1h").get_json()["bucket_seconds"] == 120
    assert client.get("/api/stats/overview?range=2y").status_code == 400


def test_sources(client):
    run(client, "port_scan")
    sources = client.get("/api/sources").get_json()["sources"]
    firewall = next(s for s in sources if s["source"] == "firewall")
    assert firewall["host"] == "fw-01"
    assert firewall["events_24h"] == 60
    collectors = client.get("/api/sources").get_json()["collectors"]
    assert collectors["syslog"]["port"] == 5514
    assert collectors["ingest_api"]["default_key"] is False  # tests set their own key
    assert "test-key" not in str(collectors)


def test_stream_sends_alerts_and_stats(client, ingest):
    # Start the stream, then create an alert while it is open.
    res = client.get("/api/stream", buffered=False)
    assert res.mimetype == "text/event-stream"
    chunks = res.response
    first = next(chunks)
    assert b"retry:" in (first if isinstance(first, bytes) else first.encode())

    ingest({"src_ip": "192.0.2.66", "message": "hello from a bad address"})
    body = b"".join(c if isinstance(c, bytes) else c.encode() for c in chunks).decode()
    events = [block for block in body.split("\n\n") if block.startswith("event:")]
    kinds = [block.split("\n")[0] for block in events]
    assert "event: stats" in kinds
    alert_blocks = [b for b in events if b.startswith("event: alert")]
    assert alert_blocks
    payload = json.loads(alert_blocks[0].split("data: ", 1)[1])
    assert payload["created"] is True
    assert payload["alert"]["rule_id"] == "known-bad-source"


def test_overview_window_scopes_totals_not_series(client, ingest):
    run(client, "port_scan")
    full = client.get("/api/stats/overview?range=24h").get_json()
    assert full["totals"]["alerts"] == 1

    # A window long before the scan: series still cover the range, totals are empty.
    early = client.get(
        "/api/stats/overview?range=24h&from=2000-01-01T00:00:00Z&to=2000-01-01T01:00:00Z"
    ).get_json()
    assert early["totals"]["alerts"] == 0
    assert early["totals"]["open_alerts"] == 0
    assert early["top_sources"] == []
    assert early["alert_series"] == full["alert_series"]
    assert early["window"] == {"from": "2000-01-01T00:00:00.000Z", "to": "2000-01-01T01:00:00.000Z"}

    backwards = client.get("/api/stats/overview?from=2026-01-02T00:00:00Z&to=2026-01-01T00:00:00Z")
    assert backwards.status_code == 400


def test_alert_sort_by_severity(client):
    run(client, "port_scan")       # medium
    run(client, "brute_force")     # high + critical
    titles = [a["severity"] for a in client.get("/api/alerts?sort=severity").get_json()["alerts"]]
    assert titles == ["critical", "high", "medium"]
    assert client.get("/api/alerts?sort=random").status_code == 400


def test_alert_detail_includes_rule(client):
    run(client, "port_scan")
    alert_id = first_alert(client, "port-scan")["id"]
    detail = client.get(f"/api/alerts/{alert_id}").get_json()
    assert detail["rule"]["id"] == "port-scan"
    assert detail["rule"]["description"]
    assert "definition" not in detail["rule"]
    patched = client.patch(f"/api/alerts/{alert_id}", json={"status": "closed"}).get_json()
    assert patched["rule"]["name"] == "Port scan"
