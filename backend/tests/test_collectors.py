import socket
import threading
import time
from datetime import datetime, timezone

import pytest

from siem import db, simulator
from siem.collectors.host_agent import HostAgent
from siem.collectors.syslog_listener import SyslogListener
from siem.events import normalize
from siem.parsers import parse_line


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "c.db")
    db.init_schema(path)
    return path


def count(db_path, where="1=1"):
    conn = db.connect(db_path)
    try:
        return conn.execute(f"SELECT COUNT(*) FROM events WHERE {where}").fetchone()[0]
    finally:
        conn.close()


@pytest.mark.parametrize("name", list(simulator.SCENARIOS))
def test_every_scenario_line_parses_cleanly(name):
    lines, host = simulator.SCENARIOS[name][0](datetime.now(timezone.utc))
    events = [normalize(parse_line(line, default_host=host)) for line in lines]
    assert events
    assert all(e["category"] not in ("unknown", "system") for e in events), [e["message"] for e in events]


def test_scenarios_store_events(db_path):
    stored = simulator.run_scenario(db_path, "brute_force")
    assert len(stored) == 26
    assert count(db_path, "outcome = 'success' AND source = 'sshd'") == 1


def test_known_bad_ip_uses_intel_list(db_path):
    simulator.run_scenario(db_path, "known_bad_ip")
    bad = set(simulator.load_bad_ips())
    conn = db.connect(db_path)
    ips = {r[0] for r in conn.execute("SELECT src_ip FROM events WHERE source = 'sshd'")}
    conn.close()
    assert ips and ips <= bad


def test_noise_lines_parse_cleanly():
    now = datetime.now(timezone.utc)
    for _ in range(300):
        line, host = simulator.noise_line(now)
        event = normalize(parse_line(line, default_host=host))
        assert event["category"] not in ("unknown", "system"), line


def test_syslog_listener_stores_datagrams(db_path):
    listener = SyslogListener(db_path, "127.0.0.1", 0)
    stop = threading.Event()
    thread = threading.Thread(target=listener.run, args=(stop,), daemon=True)
    thread.start()

    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.sendto(b"<38>Oct 19 10:15:02 web-01 sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2",
                  listener.address)
    sender.sendto(b"plain line without header", listener.address)
    sender.close()

    deadline = time.time() + 5
    while time.time() < deadline and count(db_path) < 2:
        time.sleep(0.1)
    stop.set()
    thread.join(timeout=3)

    assert count(db_path, "source = 'sshd' AND host = 'web-01'") == 1
    assert count(db_path, "category = 'unknown' AND host = '127.0.0.1'") == 1


def test_host_agent_baseline_then_events():
    agent = HostAgent(hostname="test-host")
    assert agent.poll() == []  # first poll only records a baseline
    events = agent.poll()
    for event in events:
        normalize(event)  # every agent event must be valid
        assert event["host"] == "test-host"


def test_host_agent_ignores_its_own_ports(monkeypatch):
    agent = HostAgent(hostname="test-host")
    snapshots = iter([{}, {("0.0.0.0", 5000): agent.own_pid, ("0.0.0.0", 8080): 4242}])
    monkeypatch.setattr(agent, "_snapshot_processes", lambda: {})
    monkeypatch.setattr(agent, "_snapshot_connections", lambda: ([], next(snapshots)))
    agent.poll()
    events = agent.poll()
    assert [e["dst_port"] for e in events if e["action"] == "port_opened"] == [8080]
