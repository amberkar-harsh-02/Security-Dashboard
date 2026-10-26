#!/usr/bin/env python3
"""Apply the SIEM's blocklist to nftables. Runs as root, started by siem-firewall.path.

The SIEM (an unprivileged user) writes /var/lib/siem/blocklist.json. This script reads it,
validates every address, and replaces the contents of the `inet siem` sets in one atomic
nft transaction. Timed blocks get an nftables timeout, so they expire in the kernel even if
the SIEM is stopped. Nothing from the file is ever executed; addresses are parsed with
`ipaddress` and written back in canonical form.

Standard library only, so it runs on the system Python.
"""

import ipaddress
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

BLOCKLIST = Path(os.environ.get("SIEM_BLOCKLIST_FILE", "/var/lib/siem/blocklist.json"))
STATUS = BLOCKLIST.with_name("blocklist.applied.json")
NEVER_BLOCK_FILE = Path(os.environ.get("SIEM_NEVER_BLOCK_FILE", "/etc/siem/never-block.conf"))
TABLE_FILE = Path(os.environ.get("SIEM_NFT_TABLE_FILE", "/opt/siem/deploy/siem.nft"))
NFT = os.environ.get("SIEM_NFT", "/usr/sbin/nft")

# Always protected, whatever the files say.
BUILT_IN_NEVER_BLOCK = [
    "0.0.0.0/8", "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "100.64.0.0/10", "169.254.0.0/16", "224.0.0.0/4",
    "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
]
MAX_ENTRIES = 50000


def parse_time(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def load_never_block(text=""):
    """Built-in protected ranges plus one CIDR or address per line of the config file."""
    networks = [ipaddress.ip_network(n) for n in BUILT_IN_NEVER_BLOCK]
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            networks.append(ipaddress.ip_network(line, strict=False))
    return networks


def build_nft_script(entries, now, never_block):
    """Return (nft script, applied count, skipped count) for the given blocklist entries."""
    lines = ["flush set inet siem blocked4", "flush set inet siem blocked6"]
    applied = skipped = 0
    seen = set()
    for entry in entries[:MAX_ENTRIES]:
        try:
            address = ipaddress.ip_address(str(entry["ip"]).strip())
            expires = entry.get("expires_at")
            timeout = None
            if expires is not None:
                remaining = int((parse_time(expires) - now).total_seconds())
                if remaining <= 0:
                    skipped += 1
                    continue
                timeout = remaining
        except (KeyError, TypeError, ValueError, AttributeError):
            skipped += 1
            continue
        if address in seen or any(address in network for network in never_block):
            skipped += 1
            continue
        seen.add(address)
        set_name = "blocked4" if address.version == 4 else "blocked6"
        element = f"{address} timeout {timeout}s" if timeout else str(address)
        lines.append(f"add element inet siem {set_name} {{ {element} }}")
        applied += 1
    return "\n".join(lines) + "\n", applied, skipped


def _run(args, script=None):
    return subprocess.run(args, input=script, text=True, capture_output=True, check=False)


def ensure_table():
    if _run([NFT, "list", "table", "inet", "siem"]).returncode != 0:
        result = _run([NFT, "-f", str(TABLE_FILE)])
        if result.returncode != 0:
            raise RuntimeError(f"Could not create the nftables table: {result.stderr.strip()}")


def write_status(status):
    temp = STATUS.with_suffix(".tmp")
    temp.write_text(json.dumps(status), encoding="utf-8")
    os.chmod(temp, 0o644)
    os.replace(temp, STATUS)


def main():
    now = datetime.now(timezone.utc)
    status = {"last_applied_at": now.isoformat(timespec="seconds").replace("+00:00", "Z"), "applied": 0, "skipped": 0, "error": None}
    try:
        ensure_table()
        never_block = load_never_block(NEVER_BLOCK_FILE.read_text(encoding="utf-8") if NEVER_BLOCK_FILE.exists() else "")
        data = json.loads(BLOCKLIST.read_text(encoding="utf-8")) if BLOCKLIST.exists() else {"blocks": []}
        entries = data.get("blocks", []) if isinstance(data, dict) else []
        script, status["applied"], status["skipped"] = build_nft_script(entries, now, never_block)
        result = _run([NFT, "-f", "-"], script)
        if result.returncode != 0:
            raise RuntimeError(f"nft rejected the update: {result.stderr.strip()}")
    except Exception as exc:  # report every failure to the dashboard; the firewall keeps its previous state
        status["error"] = str(exc)
        write_status(status)
        print(f"siem-firewall-sync: {exc}", file=sys.stderr)
        return 1
    write_status(status)
    print(f"siem-firewall-sync: {status['applied']} blocked, {status['skipped']} skipped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
