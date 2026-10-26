"""Syslog framing: RFC 3164 (BSD) and RFC 5424 headers.

Returns the header fields and the message body. The caller passes the body to the
parser for the sending program (sshd, kernel firewall, web server).
"""

import re
from datetime import datetime, timedelta, timezone

RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+) "
    r"(?P<sd>-|(?:\[(?:[^\]\\]|\\.)*\])+) ?(?P<msg>.*)$",
    re.S,
)
RFC3164 = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?P<ts>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) (?P<host>\S+) "
    r"(?P<app>[^\s:\[]+)(?:\[(?P<procid>\d+)\])?: ?(?P<msg>.*)$",
    re.S,
)

# Syslog severity number to SIEM severity.
SEVERITY = {0: "critical", 1: "critical", 2: "critical", 3: "high", 4: "medium", 5: "low", 6: "info", 7: "info"}


def _bsd_timestamp(text, now):
    """RFC 3164 has no year or zone. Assume UTC and the current year, or last year if that is in the future."""
    parsed = datetime.strptime(f"{now.year} {text}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
    if parsed > now + timedelta(days=1):
        parsed = parsed.replace(year=now.year - 1)
    return parsed.isoformat()


def parse(line, now=None):
    now = now or datetime.now(timezone.utc)

    match = RFC5424.match(line)
    if match:
        ts = None if match["ts"] == "-" else match["ts"]
    else:
        match = RFC3164.match(line)
        if not match:
            return None
        try:
            ts = _bsd_timestamp(" ".join(match["ts"].split()), now)
        except ValueError:
            ts = None

    pri = int(match["pri"]) if match["pri"] else None
    host = match["host"]
    app = match["app"]
    return {
        "ts": ts,
        "host": None if host == "-" else host,
        "app": None if app == "-" else app,
        "severity": SEVERITY[pri % 8] if pri is not None and pri < 192 else "info",
        "message": match["msg"].strip(),
    }
