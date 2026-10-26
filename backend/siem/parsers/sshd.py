"""OpenSSH server messages, as written to auth.log or sent over syslog."""

import re

FAILED = re.compile(
    r"Failed (?P<method>password|publickey|keyboard-interactive/pam) for (?P<invalid>invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
ACCEPTED = re.compile(
    r"Accepted (?P<method>password|publickey|keyboard-interactive/pam) for (?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)
INVALID_USER = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?")


def parse(message):
    """Return event fields for a known sshd message, or None."""
    base = {"source": "sshd", "category": "authentication", "action": "login", "process": "sshd", "dst_port": 22}

    match = FAILED.search(message)
    if match:
        return {
            **base,
            "outcome": "failure",
            "severity": "low",
            "user": match["user"],
            "src_ip": match["ip"],
            "src_port": match["port"],
            "message": message,
        }

    match = ACCEPTED.search(message)
    if match:
        return {
            **base,
            "outcome": "success",
            "severity": "info",
            "user": match["user"],
            "src_ip": match["ip"],
            "src_port": match["port"],
            "message": message,
        }

    match = INVALID_USER.search(message)
    if match:
        return {
            **base,
            "action": "invalid_user",
            "outcome": "failure",
            "severity": "low",
            "user": match["user"] or None,
            "src_ip": match["ip"],
            "src_port": match["port"],
            "message": message,
        }

    return None
