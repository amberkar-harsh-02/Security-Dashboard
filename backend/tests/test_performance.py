from types import SimpleNamespace

from siem import create_app, db
from siem.config import Config
from siem.performance import PerformanceMonitor, _rate

from .conftest import ADMIN_PASSWORD


def test_sample_has_every_field():
    monitor = PerformanceMonitor(interval=2)
    point = monitor.sample(now=1000)
    assert point["t"] == 1_000_000
    for key in ("cpu", "cores", "mem_used", "mem_percent", "swap_percent", "disk_read", "disk_write", "net_recv", "net_sent"):
        assert key in point, key
    assert 0 <= point["cpu"] <= 100
    assert len(point["cores"]) >= 1
    assert point["disk_read"] == 0 and point["net_recv"] == 0  # no previous reading yet

    snapshot = monitor.snapshot()
    assert snapshot["info"]["cores_logical"] >= 1
    assert snapshot["info"]["memory_total"] > 0
    assert snapshot["processes"]["count"] > 0
    assert snapshot["processes"]["top"]
    assert all({"pid", "name", "cpu", "memory"} <= set(row) for row in snapshot["processes"]["top"])
    assert snapshot["disks"]


def test_rates_are_never_negative():
    assert _rate(100, 400, 2) == 0.0  # counter reset or wrap
    assert _rate(400, 100, 2) == 150.0
    assert _rate(400, None, 2) == 0.0
    assert _rate(400, 100, 0) == 0.0


def test_rates_use_the_time_between_samples(monkeypatch):
    monitor = PerformanceMonitor(interval=2)
    readings = iter([
        (10.0, SimpleNamespace(read_bytes=0, write_bytes=0), SimpleNamespace(bytes_recv=0, bytes_sent=0)),
        (12.0, SimpleNamespace(read_bytes=4000, write_bytes=2000), SimpleNamespace(bytes_recv=1000, bytes_sent=500)),
    ])
    monkeypatch.setattr(monitor, "_read_counters", lambda: next(readings))
    monitor.sample()
    point = monitor.sample()
    assert (point["disk_read"], point["disk_write"], point["net_recv"], point["net_sent"]) == (2000, 1000, 500, 250)


def test_history_is_bounded_and_filtered_by_since():
    monitor = PerformanceMonitor(interval=1800)  # two samples per hour of history
    for second in (1, 2, 3):
        monitor.sample(now=second)
    assert [p["t"] for p in monitor.history] == [2000, 3000]
    assert [p["t"] for p in monitor.snapshot(since=2000)["history"]] == [3000]


def test_endpoint_requires_sign_in(anon, client):
    assert anon.get("/api/performance").status_code == 401
    body = client.get("/api/performance").get_json()
    assert body["history"]  # the first request takes a sample when none exist yet
    assert body["info"]["hostname"]
    assert client.get("/api/performance?since=abc").status_code == 400


def test_monitor_thread_not_started_without_background_jobs(app):
    assert "siem_jobs" not in app.extensions
    assert not app.extensions["siem_performance"].history


def test_proxy_settings(tmp_path):
    config = Config(
        DB_PATH=str(tmp_path / "p.db"),
        START_BACKGROUND_JOBS=False,
        SECRET_KEY="test-secret",
        ADMIN_PASSWORD=ADMIN_PASSWORD,
        TRUST_PROXY=True,
        COOKIE_PATH="/siem",
        COOKIE_SECURE=True,
    )
    client = create_app(config).test_client()
    res = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": ADMIN_PASSWORD},
        headers={"X-Forwarded-For": "198.51.100.200", "X-Forwarded-Proto": "https"},
    )
    assert res.status_code == 200
    # Browsers send this cookie to /siem/... only; Caddy strips /siem before Flask sees the path.
    cookie = res.headers["Set-Cookie"]
    assert "Path=/siem" in cookie and "Secure" in cookie

    conn = db.connect(config.DB_PATH)
    stored = conn.execute("SELECT src_ip FROM events WHERE source = 'siem'").fetchone()[0]
    conn.close()
    assert stored == "198.51.100.200"


def test_forwarded_for_ignored_without_trust_proxy(anon, client):
    anon.post(
        "/api/auth/login",
        json={"username": "admin", "password": "wrong-password"},
        headers={"X-Forwarded-For": "198.51.100.200"},
    )
    addresses = {e["src_ip"] for e in client.get("/api/events?source=siem").get_json()["events"]}
    assert "198.51.100.200" not in addresses
