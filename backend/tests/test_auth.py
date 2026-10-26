import pytest

from siem import db
from siem.auth import LoginThrottle, create_user

from .conftest import ADMIN_PASSWORD

PROTECTED = [
    ("get", "/api/events"),
    ("get", "/api/events/1"),
    ("get", "/api/alerts"),
    ("get", "/api/rules"),
    ("get", "/api/stats/overview"),
    ("get", "/api/sources"),
    ("get", "/api/stream"),
    ("get", "/api/simulate"),
    ("post", "/api/simulate/brute_force"),
    ("get", "/api/auth/me"),
    ("get", "/api/system-health"),
    ("get", "/api/performance"),
]


@pytest.mark.parametrize("method, path", PROTECTED)
def test_protected_routes_need_sign_in(anon, method, path):
    res = getattr(anon, method)(path)
    assert res.status_code == 401
    assert res.get_json()["error"] == "Sign in to continue"


@pytest.mark.parametrize("path", ["/api/health"])
def test_public_routes(anon, path):
    assert anon.get(path).status_code == 200


def test_login_flow(anon):
    res = anon.post("/api/auth/login", json={"username": "ADMIN", "password": ADMIN_PASSWORD})
    assert res.status_code == 200  # usernames are case-insensitive
    token = res.get_json()["csrf_token"]
    assert res.get_json()["user"] == "admin"
    assert "HttpOnly" in res.headers["Set-Cookie"]

    me = anon.get("/api/auth/me").get_json()
    assert me == {"user": "admin", "csrf_token": token}

    assert anon.post("/api/auth/logout").status_code == 403  # no CSRF header
    assert anon.post("/api/auth/logout", headers={"X-CSRF-Token": token}).status_code == 200
    assert anon.get("/api/auth/me").status_code == 401


def test_wrong_password_and_unknown_user(anon):
    for username in ("admin", "nobody"):
        res = anon.post("/api/auth/login", json={"username": username, "password": "wrong-password"})
        assert res.status_code == 401
        assert res.get_json()["error"] == "Username or password is incorrect"


def test_logins_are_recorded_as_events(anon, client):
    anon.post("/api/auth/login", json={"username": "admin", "password": "nope-nope-nope"})
    events = client.get("/api/events?source=siem").get_json()["events"]
    outcomes = sorted(e["outcome"] for e in events)
    assert outcomes == ["failure", "success"]


def test_writes_need_csrf_token(app, client):
    plain = app.test_client()
    plain.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})
    assert plain.post("/api/simulate/port_scan").status_code == 403
    assert plain.post("/api/simulate/port_scan", headers={"X-CSRF-Token": "guess"}).status_code == 403
    assert client.post("/api/simulate/port_scan").status_code == 201


def test_lockout_after_repeated_failures(anon):
    for _ in range(10):
        anon.post("/api/auth/login", json={"username": "admin", "password": "wrong-password"})
    res = anon.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})
    assert res.status_code == 429


def test_throttle_window_expires():
    throttle = LoginThrottle(limit=2, seconds=0)
    throttle.fail("x")
    throttle.fail("x")
    assert not throttle.blocked("x")


def test_list_users(client, app):
    conn = db.connect(app.config["SIEM"].DB_PATH)
    create_user(conn, "bob", "another-long-password")
    conn.close()
    assert client.get("/api/auth/users").get_json() == {"users": ["admin", "bob"]}


def test_password_rules(app):
    conn = db.connect(app.config["SIEM"].DB_PATH)
    with pytest.raises(ValueError, match="at least"):
        create_user(conn, "carol", "short")
    conn.close()


def test_generated_admin_password(tmp_path, caplog):
    from siem import create_app
    from siem.config import Config

    config = Config(DB_PATH=str(tmp_path / "g.db"), START_BACKGROUND_JOBS=False, ADMIN_PASSWORD=None)
    with caplog.at_level("WARNING"):
        create_app(config)
    assert "Created analyst account 'admin' with password" in caplog.text
    assert (tmp_path / "secret_key").exists()


def test_repeated_dashboard_sign_in_failures_raise_an_alert(anon, client):
    for _ in range(10):
        anon.post("/api/auth/login", json={"username": "admin", "password": "wrong-password"})
    alerts = client.get("/api/alerts?rule_id=siem-login-guessing").get_json()["alerts"]
    assert len(alerts) == 1
    assert alerts[0]["event_count"] == 10
    rules = {r["id"]: r for r in client.get("/api/rules").get_json()["rules"]}
    assert rules["siem-login-guessing"]["can_auto_block"] is True
