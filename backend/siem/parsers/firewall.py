"""Linux UFW / iptables kernel log lines, e.g.

[UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.9 DST=10.0.0.5 PROTO=TCP SPT=40112 DPT=3389
"""

import re

ACTION = re.compile(r"\[UFW (?P<action>BLOCK|ALLOW|AUDIT)\]")
FIELD = re.compile(r"\b(SRC|DST|PROTO|SPT|DPT|IN)=(\S*)")


def parse(message):
    match = ACTION.search(message)
    if not match:
        return None

    fields = dict(FIELD.findall(message))
    blocked = match["action"] == "BLOCK"
    return {
        "source": "firewall",
        "category": "network",
        "action": "connection",
        "outcome": "failure" if blocked else "success",
        "severity": "low" if blocked else "info",
        "src_ip": fields.get("SRC"),
        "dst_ip": fields.get("DST"),
        "src_port": fields.get("SPT"),
        "dst_port": fields.get("DPT"),
        "message": message,
    }
