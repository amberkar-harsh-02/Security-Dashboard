import json
from datetime import datetime, timezone

import pytest

from siem.events import normalize
from siem.parsers import ParseError, parse_line, syslog

SSH_FAIL = "<38>Oct 19 10:15:02 web-01 sshd[2211]: Failed password for invalid user oracle from 203.0.113.9 port 51022 ssh2"
SSH_OK = "Oct  5 09:01:02 db-01 sshd[1]: Accepted publickey for carol from 198.51.100.23 port 40000 ssh2"
UFW = "<4>Oct 19 10:15:02 fw-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.9 DST=10.0.1.10 PROTO=TCP SPT=40112 DPT=3389"
ACCESS = ('203.0.113.9 - - [19/Oct/2026:10:15:02 +0000] "GET /download?file=../../etc/passwd HTTP/1.1" '
          '400 312 "-" "curl/8.5"')
RFC5424 = "<165>1 2026-10-19T10:15:02.003Z app-01 billing 4211 ID47 - Invoice batch finished"


def test_sshd_failed_login_over_syslog():
    event = parse_line(SSH_FAIL)
    assert event["source"] == "sshd"
    assert event["outcome"] == "failure"
    assert event["user"] == "oracle"
    assert event["src_ip"] == "203.0.113.9"
    assert event["host"] == "web-01"
    assert event["raw"] == SSH_FAIL


def test_sshd_accepted_with_padded_day():
    event = normalize(parse_line(SSH_OK))
    assert event["outcome"] == "success"
    assert event["user"] == "carol"
    assert event["ts"][5:10] == "10-05"


def test_firewall_block():
    event = parse_line(UFW)
    assert (event["source"], event["outcome"], event["dst_port"], event["host"]) == ("firewall", "failure", "3389", "fw-01")


def test_web_access_log_flags_attack():
    event = normalize(parse_line(ACCESS, default_host="web-01"))
    assert event["category"] == "web"
    assert event["severity"] == "medium"
    assert "path traversal" in event["message"]
    assert event["host"] == "web-01"
    assert event["ts"] == "2026-10-19T10:15:02.000Z"


def test_web_access_log_normal_request():
    line = '10.0.2.5 - bob [19/Oct/2026:10:15:02 +0000] "GET /dashboard HTTP/1.1" 200 5120 "-" "Firefox"'
    event = parse_line(line, "web")
    assert event["severity"] == "info"
    assert event["user"] == "bob"


def test_rfc5424_unknown_program():
    event = normalize(parse_line(RFC5424))
    assert event["source"] == "billing"
    assert event["category"] == "system"
    assert event["severity"] == "low"  # syslog severity 5 (notice)
    assert event["message"] == "Invoice batch finished"
    assert event["ts"] == "2026-10-19T10:15:02.003Z"


@pytest.mark.parametrize(
    "event_id, action, severity",
    [(4625, "login", "low"), (4720, "user_created", "medium"), (4732, "group_member_added", "high"), (1102, "log_cleared", "high")],
)
def test_windows_events(event_id, action, severity):
    line = json.dumps({"EventID": event_id, "Computer": "dc-01", "TargetUserName": "Administrators",
                       "MemberName": "support_1", "SubjectUserName": "bob", "IpAddress": "10.0.2.4"})
    event = normalize(parse_line(line))
    assert (event["action"], event["severity"], event["host"]) == (action, severity, "dc-01")


def test_windows_nested_event_data():
    event = parse_line(json.dumps({"EventID": "4624", "EventData": {"TargetUserName": "alice", "LogonType": "10"}}))
    assert event["user"] == "alice"
    assert "remote desktop" in event["message"]


def test_unknown_line_is_kept():
    event = normalize(parse_line("something odd happened", default_host="10.0.0.9"))
    assert event["category"] == "unknown"
    assert event["host"] == "10.0.0.9"


def test_forced_format_mismatch_is_an_error():
    with pytest.raises(ParseError):
        parse_line("hello", "sshd")
    with pytest.raises(ParseError):
        parse_line("hello", "nope")


def test_bsd_timestamp_in_future_rolls_back_a_year():
    now = datetime(2026, 1, 1, 0, 30, tzinfo=timezone.utc)
    header = syslog.parse("Dec 31 23:59:00 h app: x", now=now)
    assert header["ts"].startswith("2025-12-31")
