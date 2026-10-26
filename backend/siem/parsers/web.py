"""Apache / Nginx access logs in common or combined format."""

import re
from datetime import datetime
from urllib.parse import unquote_plus

LINE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)(?: (?P<proto>[^"]*))?" (?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?'
)

# Request patterns that are almost never legitimate. Detection rules decide what is an alert;
# the parser only raises the event's severity so it stands out in search.
SUSPICIOUS = [
    ("path traversal", re.compile(r"\.\./|\.\.\\|/etc/passwd|win\.ini", re.I)),
    ("sql injection", re.compile(r"union\s+select|'\s*or\s+'?1'?\s*=\s*'?1|sleep\(\d+\)|information_schema", re.I)),
    ("cross-site scripting", re.compile(r"<script|javascript:|onerror\s*=", re.I)),
    ("command injection", re.compile(r";\s*(cat|wget|curl|bash|sh)\b|\|\s*(nc|bash)\b|cmd\.exe", re.I)),
]


def detect_attack(path):
    decoded = unquote_plus(path)
    for name, pattern in SUSPICIOUS:
        if pattern.search(decoded):
            return name
    return None


def parse(line):
    match = LINE.match(line)
    if not match:
        return None

    status = int(match["status"])
    attack = detect_attack(match["path"])
    if attack:
        severity = "medium"
    elif status >= 500:
        severity = "low"
    else:
        severity = "info"

    try:
        ts = datetime.strptime(match["time"], "%d/%b/%Y:%H:%M:%S %z").isoformat()
    except ValueError:
        ts = None

    summary = f'{match["method"]} {match["path"]} {status}'
    if attack:
        summary += f" (possible {attack})"

    return {
        "ts": ts,
        "source": "web",
        "category": "web",
        "action": "http_request",
        "outcome": "failure" if status >= 400 else "success",
        "severity": severity,
        "user": None if match["user"] == "-" else match["user"],
        "src_ip": match["ip"],
        "message": summary,
        "raw": line,
    }
