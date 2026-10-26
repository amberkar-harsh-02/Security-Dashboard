"""Synthetic but realistic log traffic for demos and testing.

Scenarios produce raw log lines (syslog, access log, Windows JSON) that go through the
same parsers as real data. Background noise produces normal activity so detections have
to find attacks among ordinary events.

All addresses come from documentation ranges (RFC 5737) or private ranges.
"""

import json
import logging
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import pipeline
from .config import BACKEND_DIR

log = logging.getLogger("siem.simulator")

USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "svc_backup"]
LINUX_HOSTS = {"web-01": "10.0.1.10", "db-01": "10.0.1.20"}
WINDOWS_HOST = "dc-01"
FIREWALL_HOST = "fw-01"
PUBLIC_SERVER = "10.0.1.10"
WEB_PATHS = ["/", "/login", "/dashboard", "/api/orders", "/api/orders/1042", "/static/app.js",
             "/static/style.css", "/favicon.ico", "/account/settings", "/search?q=invoice"]
AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:139.0) Gecko/20100101 Firefox/139.0",
]
SPRAY_USERS = ["administrator", "admin", "jsmith", "mjones", "helpdesk", "backup", "sqlsvc", "test",
               "guest", "scanner", "operator", "alice", "bob", "carol", "dave"]
INTEL_FILE = BACKEND_DIR / "intel" / "bad_ips.txt"


def load_bad_ips(path=INTEL_FILE):
    try:
        lines = Path(path).read_text().splitlines()
    except OSError:
        return []
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


def _attacker_ip():
    return f"203.0.113.{random.randint(2, 254)}"


def _internal_ip():
    return f"10.0.2.{random.randint(10, 200)}"


# --- Line builders -------------------------------------------------------------------------

def _bsd_time(ts):
    """RFC 3164 timestamp: day of month is space-padded ("Oct  5 09:01:02")."""
    return f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S}"


def _syslog(ts, host, app, pid, message, pri=38):
    return f"<{pri}>{_bsd_time(ts)} {host} {app}[{pid}]: {message}"


def _sshd(ts, host, message):
    return _syslog(ts, host, "sshd", random.randint(1000, 65000), message)


def _ufw(ts, action, src, dst, dpt, proto="TCP"):
    msg = (f"[UFW {action}] IN=eth0 OUT= SRC={src} DST={dst} PROTO={proto} "
           f"SPT={random.randint(1024, 65535)} DPT={dpt}")
    return f"<4>{_bsd_time(ts)} {FIREWALL_HOST} kernel: {msg}"


def _access(ts, ip, method, path, status, agent=None):
    stamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    size = random.randint(200, 48000) if status < 400 else random.randint(150, 600)
    return f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "{agent or random.choice(AGENTS)}"'


def _windows(ts, event_id, **data):
    return json.dumps({"EventID": event_id, "Computer": WINDOWS_HOST, "TimeCreated": ts.isoformat(), **data})


def _spread(start, count, seconds):
    """`count` timestamps between start and start + seconds, in order, with jitter."""
    step = seconds / max(count, 1)
    return [start + timedelta(seconds=i * step + random.uniform(0, step * 0.8)) for i in range(count)]


# --- Attack scenarios ------------------------------------------------------------------------
# Each returns (lines, default_host). Lines end at roughly "now".

def brute_force(now):
    attacker = _attacker_ip()
    host = "web-01"
    times = _spread(now - timedelta(seconds=60), 26, 55)
    lines = []
    for ts in times[:-1]:
        user = random.choice(["root", "admin", "ubuntu", "oracle", "postgres"])
        if user in ("root", "admin"):
            msg = f"Failed password for {user} from {attacker} port {random.randint(30000, 65000)} ssh2"
        else:
            msg = f"Failed password for invalid user {user} from {attacker} port {random.randint(30000, 65000)} ssh2"
        lines.append(_sshd(ts, host, msg))
    lines.append(_sshd(times[-1], host, f"Accepted password for admin from {attacker} port {random.randint(30000, 65000)} ssh2"))
    return lines, host


def password_spray(now):
    attacker = _attacker_ip()
    users = random.sample(SPRAY_USERS, 12)
    times = _spread(now - timedelta(seconds=120), len(users), 115)
    lines = [
        _windows(ts, 4625, TargetUserName=user, IpAddress=attacker, IpPort=str(random.randint(30000, 65000)),
                 LogonType="3", WorkstationName="-", Status="0xC000006D")
        for ts, user in zip(times, users)
    ]
    return lines, WINDOWS_HOST


def port_scan(now):
    attacker = _attacker_ip()
    ports = random.sample(range(1, 10000), 55) + [22, 80, 443, 445, 3389]
    random.shuffle(ports)
    times = _spread(now - timedelta(seconds=20), len(ports), 18)
    lines = [
        _ufw(ts, "ALLOW" if port in (80, 443) else "BLOCK", attacker, PUBLIC_SERVER, port)
        for ts, port in zip(times, ports)
    ]
    return lines, FIREWALL_HOST


def web_attack(now):
    attacker = _attacker_ip()
    agent = "sqlmap/1.8.4#stable (https://sqlmap.org)"
    requests = [
        ("GET", "/", 200),
        ("GET", "/login", 200),
        ("GET", "/search?q=invoice%27%20OR%20%271%27%3D%271", 500),
        ("GET", "/api/orders?id=1%20UNION%20SELECT%20username,password%20FROM%20users--", 500),
        ("GET", "/api/orders?id=1%20AND%20SLEEP(5)", 200),
        ("GET", "/download?file=../../../../etc/passwd", 400),
        ("GET", "/download?file=..%2F..%2F..%2Fwindows%2Fwin.ini", 400),
        ("GET", "/search?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E", 200),
        ("POST", "/api/ping?host=127.0.0.1;cat%20/etc/shadow", 500),
        ("GET", "/wp-admin/", 404),
        ("GET", "/.env", 404),
        ("GET", "/phpmyadmin/", 404),
    ]
    times = _spread(now - timedelta(seconds=40), len(requests), 38)
    lines = [_access(ts, attacker, method, path, status, agent) for ts, (method, path, status) in zip(times, requests)]
    return lines, "web-01"


def privilege_escalation(now):
    user = random.choice(["bob", "dave", "erin"])
    client = _internal_ip()
    new_account = f"support_{random.randint(10, 99)}"
    times = _spread(now - timedelta(seconds=90), 6, 85)
    lines = [
        _windows(times[0], 4624, TargetUserName=user, IpAddress=client, LogonType="10"),
        _windows(times[1], 4672, SubjectUserName=user),
        _windows(times[2], 4688, SubjectUserName=user,
                 NewProcessName="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                 CommandLine="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="),
        _windows(times[3], 4720, SubjectUserName=user, TargetUserName=new_account),
        _windows(times[4], 4732, SubjectUserName=user, TargetUserName="Administrators", MemberName=new_account),
        _windows(times[5], 1102, SubjectUserName=user),
    ]
    return lines, WINDOWS_HOST


def known_bad_ip(now):
    bad_ips = load_bad_ips() or ["198.51.100.23"]
    ip = random.choice(bad_ips)
    user = random.choice(["carol", "svc_backup"])
    ts = now - timedelta(seconds=random.randint(1, 5))
    lines = [
        _ufw(ts - timedelta(seconds=2), "ALLOW", ip, PUBLIC_SERVER, 22),
        _sshd(ts, "db-01", f"Accepted publickey for {user} from {ip} port {random.randint(30000, 65000)} ssh2"),
    ]
    return lines, "db-01"


SCENARIOS = {
    "brute_force": (brute_force, "SSH brute force", "One address tries many passwords against SSH on web-01, then gets in."),
    "password_spray": (password_spray, "Password spray", "One address tries one password against many Windows accounts on dc-01."),
    "port_scan": (port_scan, "Port scan", "One address probes about 60 ports on the public server in under 20 seconds."),
    "web_attack": (web_attack, "Web application attack", "SQL injection, path traversal, XSS and command injection against web-01."),
    "privilege_escalation": (privilege_escalation, "Privilege escalation",
                             "A user creates an account, adds it to Administrators and clears the audit log on dc-01."),
    "known_bad_ip": (known_bad_ip, "Login from a known-bad address",
                     "A successful SSH login on db-01 from an address on the threat intelligence list."),
}


def list_scenarios():
    return [{"id": key, "name": name, "description": desc} for key, (_fn, name, desc) in SCENARIOS.items()]


def run_scenario(db_path, name, now=None):
    if name not in SCENARIOS:
        raise KeyError(name)
    lines, host = SCENARIOS[name][0](now or datetime.now(timezone.utc))
    return pipeline.store(db_path, lines=lines, default_host=host)


# --- Background noise ------------------------------------------------------------------------

def noise_line(now):
    """One line of ordinary activity, chosen by weight."""
    kind = random.choices(
        ["web", "ssh_ok", "ssh_typo", "fw_allow", "fw_block", "win_logon", "win_process", "win_typo"],
        weights=[40, 8, 2, 10, 6, 10, 10, 2],
    )[0]
    user = random.choice(USERS)
    if kind == "web":
        path = random.choice(WEB_PATHS)
        status = random.choices([200, 304, 302, 404, 500], weights=[80, 10, 5, 4, 1])[0]
        ip = random.choice([_internal_ip(), f"100.{random.randint(64, 127)}.{random.randint(0, 255)}.{random.randint(1, 254)}"])
        return _access(now, ip, "POST" if path == "/login" and random.random() < 0.5 else "GET", path, status), "web-01"
    if kind in ("ssh_ok", "ssh_typo"):
        host = random.choice(list(LINUX_HOSTS))
        ip = _internal_ip()
        port = random.randint(40000, 65000)
        if kind == "ssh_ok":
            method = random.choice(["publickey", "publickey", "password"])
            return _sshd(now, host, f"Accepted {method} for {user} from {ip} port {port} ssh2"), host
        return _sshd(now, host, f"Failed password for {user} from {ip} port {port} ssh2"), host
    if kind == "fw_allow":
        return _ufw(now, "ALLOW", _internal_ip(), PUBLIC_SERVER, random.choice([443, 443, 80, 22])), FIREWALL_HOST
    if kind == "fw_block":
        return _ufw(now, "BLOCK", _attacker_ip(), PUBLIC_SERVER, random.choice([23, 445, 1433, 3389, 5900, 8080])), FIREWALL_HOST
    if kind == "win_logon":
        return _windows(now, 4624, TargetUserName=user, IpAddress=_internal_ip(), LogonType=random.choice(["2", "3", "3", "7"])), WINDOWS_HOST
    if kind == "win_process":
        exe = random.choice(["chrome.exe", "OUTLOOK.EXE", "Teams.exe", "explorer.exe", "notepad.exe", "EXCEL.EXE"])
        return _windows(now, 4688, SubjectUserName=user, NewProcessName=f"C:\\Program Files\\{exe}"), WINDOWS_HOST
    return _windows(now, 4625, TargetUserName=user, IpAddress=_internal_ip(), LogonType="2", Status="0xC000006A"), WINDOWS_HOST


def run_noise(stop, db_path, rate):
    """Write about `rate` ordinary events per second until stopped."""
    log.info("Background noise generator running at about %s events per second", rate)
    while not stop.is_set():
        now = datetime.now(timezone.utc)
        count = int(rate) + (random.random() < rate % 1)
        by_host = {}
        for _ in range(count):
            line, host = noise_line(now - timedelta(milliseconds=random.randint(0, 999)))
            by_host.setdefault(host, []).append(line)
        try:
            for host, lines in by_host.items():
                pipeline.store(db_path, lines=lines, default_host=host)
        except Exception:
            log.exception("Noise generator failed to store events")
        stop.wait(1)
