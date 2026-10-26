import json
from datetime import timedelta

import pytest

from siem import blocks, create_app, db
from siem.config import Config
from siem.events import ValidationError, format_ts, utc_now

from .conftest import ADMIN_PASSWORD

ATTACKER = "203.0.113.50"


def run(client, scenario):
    assert client.post(f"/api/simulate/{scenario}").status_code == 201


def conn_for(app):
    return db.connect(app.config["SIEM"].DB_PATH)


# --- Safety -------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "ip, words",
    [
        ("not-an-ip", "valid"),
        ("127.0.0.1", "Loopback"),
        ("10.1.2.3", "Internal"),
        ("192.168.0.5", "Internal"),
        ("fe80::1", "Internal"),
        ("224.0.0.1", "Multicast"),
    ],
)
def test_protected_addresses(ip, words):
    assert words in blocks.protected_reason(ip)


def test_documentation_addresses_are_blockable_for_demos():
    assert blocks.protected_reason("203.0.113.9") is None
    assert blocks.protected_reason("198.51.100.23") is None


def test_own_address_and_allowlist_are_protected(tmp_path):
    assert "your own address" in blocks.protected_reason("198.51.100.7", analyst_ip="198.51.100.7")
    blocks.configure(Config(BLOCK_ALLOWLIST="198.51.100.0/24, not-a-network", BLOCKLIST_FILE=""))
    try:
        assert "never-block" in blocks.protected_reason("198.51.100.99")
    finally:
        blocks.configure(Config(BLOCK_ALLOWLIST="", BLOCKLIST_FILE=""))


# --- Records ------------------------------------------------------------------------------

def test_block_extend_and_unblock(app):
    conn = conn_for(app)
    first = blocks.block(conn, ATTACKER, 15, "guessing passwords", "admin")
    assert first["active"] and first["created_by"] == "admin"

    again = blocks.block(conn, ATTACKER, 60, None, "admin")
    assert again["id"] == first["id"]  # extended, not duplicated
    assert again["expires_at"] > first["expires_at"]
    assert again["reason"] == "guessing passwords"
    assert [b["ip"] for b in blocks.active(conn)] == [ATTACKER]

    ended = blocks.unblock(conn, first["id"], "admin")
    assert not ended["active"] and ended["removed_by"] == "admin"
    assert blocks.active(conn) == []
    assert blocks.unblock(conn, first["id"], "admin") is None

    actions = [r[0] for r in conn.execute("SELECT action FROM events WHERE category = 'response' ORDER BY id")]
    assert actions == ["block", "block", "unblock"]
    conn.close()


def test_permanent_block_and_bad_duration(app):
    conn = conn_for(app)
    assert blocks.block(conn, ATTACKER, None, None, "admin")["expires_at"] is None
    with pytest.raises(ValidationError, match="minutes"):
        blocks.block(conn, "203.0.113.51", 7, None, "admin")
    conn.close()


def test_expiry_is_recorded_once(app):
    conn = conn_for(app)
    record = blocks.block(conn, ATTACKER, 15, None, "admin")
    past = format_ts(utc_now() - timedelta(minutes=1))
    with conn:
        conn.execute("UPDATE blocks SET expires_at = ? WHERE id = ?", (past, record["id"]))
    assert blocks.active(conn) == []
    assert [b["ip"] for b in blocks.history(conn)] == [ATTACKER]
    assert blocks.expire(conn) == 1
    assert blocks.expire(conn) == 0
    conn.close()


def test_blocklist_file(tmp_path, app):
    path = tmp_path / "state" / "blocklist.json"
    conn = conn_for(app)
    blocks.block(conn, ATTACKER, 60, None, "admin")
    blocks.block(conn, "198.51.100.23", None, None, "admin")
    assert blocks.write_blocklist(conn, str(path))
    data = json.loads(path.read_text())
    assert {b["ip"]: b["expires_at"] is None for b in data["blocks"]} == {ATTACKER: False, "198.51.100.23": True}
    assert not list(path.parent.glob(".blocklist-*"))  # the temporary file was renamed into place
    assert blocks.write_blocklist(conn) is False  # no file configured: record only
    conn.close()


def test_enforcement_status(tmp_path):
    assert blocks.enforcement_status("") == {"mode": "record-only"}
    path = tmp_path / "blocklist.json"
    assert blocks.enforcement_status(str(path))["error"]
    (tmp_path / "blocklist.applied.json").write_text(json.dumps({"last_applied_at": "2026-10-20T00:00:00Z", "applied": 2, "skipped": 0, "error": None}))
    status = blocks.enforcement_status(str(path))
    assert status["mode"] == "firewall" and status["applied"] == 2


# --- API ----------------------------------------------------------------------------------

def test_api_requires_sign_in_and_csrf(anon, app):
    assert anon.get("/api/blocks").status_code == 401
    plain = app.test_client()
    plain.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})
    assert plain.post("/api/blocks", json={"ip": ATTACKER, "minutes": 15}).status_code == 403


def test_api_block_flow(client):
    res = client.post("/api/blocks", json={"ip": ATTACKER, "minutes": 60, "reason": "scanner"})
    assert res.status_code == 201
    block_id = res.get_json()["id"]

    listing = client.get("/api/blocks").get_json()
    assert listing["enforcement"] == {"mode": "record-only"}
    assert [b["ip"] for b in listing["active"]] == [ATTACKER]
    assert listing["durations"] == [15, 60, 1440, 10080, None]

    assert client.post(f"/api/blocks/{block_id}/unblock").status_code == 200
    assert client.post(f"/api/blocks/{block_id}/unblock").status_code == 404
    assert client.get("/api/blocks").get_json()["history"][0]["ip"] == ATTACKER
    assert client.get(f"/api/events?ip={ATTACKER}&category=response").get_json()["total"] == 2


def test_api_refuses_protected_and_own_address(client):
    res = client.post("/api/blocks", json={"ip": "10.0.0.5", "minutes": 15})
    assert res.status_code == 400 and "Internal" in res.get_json()["error"]
    # The test client's own address is 127.0.0.1; a different own address comes from the proxy.
    res = client.post("/api/blocks", json={"ip": "127.0.0.1", "minutes": 15})
    assert res.status_code == 400


def test_block_from_alert_adds_note_and_shows_on_alert(client):
    run(client, "port_scan")
    alert = client.get("/api/alerts?rule_id=port-scan").get_json()["alerts"][0]
    ip = alert["group_fields"]["src_ip"]
    assert client.get(f"/api/alerts/{alert['id']}").get_json()["blocked"] is None

    client.post("/api/blocks", json={"ip": ip, "minutes": 15, "alert_id": alert["id"]})
    detail = client.get(f"/api/alerts/{alert['id']}").get_json()
    assert detail["blocked"]["ip"] == ip
    assert detail["notes"][-1]["body"] == f"Blocked {ip} for 15 minutes"


def test_block_events_do_not_raise_alerts(client):
    before = client.get("/api/alerts").get_json()["total"]
    client.post("/api/blocks", json={"ip": "198.51.100.23", "minutes": 15})  # on the threat intel list
    assert client.get("/api/alerts").get_json()["total"] == before


# --- Auto-block ---------------------------------------------------------------------------

def test_auto_block_is_off_by_default(client):
    run(client, "brute_force")
    assert client.get("/api/blocks").get_json()["active"] == []
    rules = {r["id"]: r for r in client.get("/api/rules").get_json()["rules"]}
    assert rules["ssh-brute-force"]["auto_block_minutes"] is None
    assert rules["ssh-brute-force"]["can_auto_block"] is True
    assert rules["new-local-account"]["can_auto_block"] is False


def test_auto_block_blocks_new_alert_source(client):
    res = client.patch("/api/rules/ssh-brute-force", json={"auto_block_minutes": 60})
    assert res.status_code == 200 and res.get_json()["auto_block_minutes"] == 60
    assert res.get_json()["enabled"] is True  # setting auto-block leaves the rule on

    run(client, "brute_force")
    active = client.get("/api/blocks").get_json()["active"]
    assert len(active) == 1
    assert active[0]["created_by"] == "rule:ssh-brute-force"
    alert = client.get("/api/alerts?rule_id=ssh-brute-force").get_json()["alerts"][0]
    assert active[0]["ip"] == alert["group_fields"]["src_ip"]

    client.patch("/api/rules/ssh-brute-force", json={"auto_block_minutes": None})
    assert client.get("/api/rules").get_json()["rules"][0]  # still loads


def test_auto_block_skips_recent_analyst_address(client, app):
    client.patch("/api/rules/known-bad-source", json={"auto_block_minutes": 15})
    conn = conn_for(app)
    from siem.pipeline import ingest_items

    # An analyst signed in from 198.51.100.77, which is also on the threat intel list.
    ingest_items(conn, [{"source": "siem", "category": "authentication", "action": "login", "outcome": "success",
                         "src_ip": "198.51.100.77", "user": "admin", "message": "Dashboard login succeeded"}])
    conn.close()
    assert client.get("/api/blocks").get_json()["active"] == []


def test_auto_block_setting_validation(client):
    assert client.patch("/api/rules/new-local-account", json={"auto_block_minutes": 60}).status_code == 400
    assert client.patch("/api/rules/ssh-brute-force", json={"auto_block_minutes": 7}).status_code == 400
    assert client.patch("/api/rules/ssh-brute-force", json={"auto_block_minutes": "1h"}).status_code == 400
    assert client.patch("/api/rules/ssh-brute-force", json={}).status_code == 400
    assert client.patch("/api/rules/nope", json={"auto_block_minutes": 60}).status_code == 404


def test_writes_file_when_configured(tmp_path):
    path = tmp_path / "blocklist.json"
    config = Config(DB_PATH=str(tmp_path / "f.db"), START_BACKGROUND_JOBS=False, SECRET_KEY="s",
                    ADMIN_PASSWORD=ADMIN_PASSWORD, BLOCKLIST_FILE=str(path))
    app = create_app(config)
    try:
        client = app.test_client()
        token = client.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}).get_json()["csrf_token"]
        client.post("/api/blocks", json={"ip": ATTACKER, "minutes": 15}, headers={"X-CSRF-Token": token})
        assert json.loads(path.read_text())["blocks"][0]["ip"] == ATTACKER
        assert client.get("/api/blocks").get_json()["enforcement"]["mode"] == "firewall"
    finally:
        blocks.configure(Config(BLOCKLIST_FILE="", BLOCK_ALLOWLIST=""))
