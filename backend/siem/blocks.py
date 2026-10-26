"""Blocking addresses: records, safety checks and the file the server firewall follows.

The SIEM never touches the firewall itself. It writes the active blocks to
SIEM_BLOCKLIST_FILE; on the server a root-run sync (deploy/siem_firewall_sync.py) turns that
file into an nftables set whose elements expire on their own. Without the file setting,
blocks are recorded but not enforced (the laptop and test setup).
"""

import ipaddress
import json
import logging
import os
import tempfile
import threading
from datetime import timedelta
from pathlib import Path

import psutil

from .events import ValidationError, format_ts, insert_events, normalize, utc_now

log = logging.getLogger("siem.blocks")

# Durations offered in the dashboard, in minutes. None means permanent.
DURATIONS = (15, 60, 1440, 10080, None)
AUTO_BLOCK_DURATIONS = (15, 60, 1440)
KNOWN_ANALYST_HOURS = 24

# Internal networks: blocking them from a public server is pointless and can cut off
# the server's own services. Documentation ranges (RFC 5737) stay blockable so the
# attack simulator's addresses can be used to try blocking out.
INTERNAL_NETWORKS = [
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")
]

_settings = {"file": None, "allowlist": []}
_file_lock = threading.Lock()


def configure(config):
    """Called by create_app: where to write the blocklist, and extra never-block ranges."""
    allowlist = []
    for item in (config.BLOCK_ALLOWLIST or "").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            allowlist.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            log.error("Ignoring invalid SIEM_BLOCK_ALLOWLIST entry %r", item)
    _settings["file"] = config.BLOCKLIST_FILE or None
    _settings["allowlist"] = allowlist


def _own_addresses():
    addresses = set()
    for entries in psutil.net_if_addrs().values():
        for entry in entries:
            try:
                addresses.add(ipaddress.ip_address(entry.address.split("%")[0]))
            except ValueError:
                continue
    return addresses


def protected_reason(ip, analyst_ip=None):
    """Why this address must never be blocked, or None if it may be."""
    try:
        address = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return "Not a valid IP address."
    if analyst_ip and address == _parse(analyst_ip):
        return "This is your own address. Blocking it would lock you out."
    if address.is_loopback or address.is_unspecified:
        return "Loopback and unspecified addresses cannot be blocked."
    if address.is_link_local or any(address in network for network in INTERNAL_NETWORKS):
        return "Internal network addresses cannot be blocked from here."
    if address.is_multicast or address.is_reserved:
        return "Multicast and reserved addresses cannot be blocked."
    if address in _own_addresses():
        return "This is one of the SIEM server's own addresses."
    for network in _settings["allowlist"]:
        if address in network:
            return f"This address is on the never-block list ({network})."
    return None


def _parse(ip):
    try:
        return ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return None


def recently_signed_in(conn, ip, hours=KNOWN_ANALYST_HOURS):
    """True if someone signed in to the SIEM from this address recently (an analyst's address)."""
    since = format_ts(utc_now() - timedelta(hours=hours))
    row = conn.execute(
        "SELECT 1 FROM events WHERE source = 'siem' AND action = 'login' AND outcome = 'success' "
        "AND src_ip = ? AND ts >= ? LIMIT 1",
        (str(ip), since),
    ).fetchone()
    return row is not None


# --- Records ------------------------------------------------------------------------------

def _row(row, now):
    block = dict(row)
    block["active"] = block["removed_at"] is None and (block["expires_at"] is None or block["expires_at"] > now)
    return block


def active(conn):
    now = format_ts(utc_now())
    rows = conn.execute(
        "SELECT * FROM blocks WHERE removed_at IS NULL AND (expires_at IS NULL OR expires_at > ?) "
        "ORDER BY created_at DESC, id DESC",
        (now,),
    ).fetchall()
    return [_row(r, now) for r in rows]


def history(conn, limit=50):
    now = format_ts(utc_now())
    rows = conn.execute(
        "SELECT * FROM blocks WHERE removed_at IS NOT NULL OR (expires_at IS NOT NULL AND expires_at <= ?) "
        "ORDER BY COALESCE(removed_at, expires_at) DESC, id DESC LIMIT ?",
        (now, limit),
    ).fetchall()
    return [_row(r, now) for r in rows]


def active_for(conn, ip):
    now = format_ts(utc_now())
    row = conn.execute(
        "SELECT * FROM blocks WHERE ip = ? AND removed_at IS NULL AND (expires_at IS NULL OR expires_at > ?) "
        "ORDER BY id DESC LIMIT 1",
        (str(ip), now),
    ).fetchone()
    return _row(row, now) if row else None


def _record_event(conn, action, ip, actor, message):
    """Audit event. Stored directly, without detection: a block must not trigger new alerts."""
    event = normalize({
        "source": "siem", "host": "siem", "category": "response", "action": action,
        "outcome": "success", "severity": "info", "user": actor, "src_ip": ip, "message": message,
    })
    insert_events(conn, [event])


def _describe(minutes):
    if minutes is None:
        return "permanently"
    if minutes % 1440 == 0:
        days = minutes // 1440
        return f"for {days} {'day' if days == 1 else 'days'}"
    if minutes % 60 == 0:
        hours = minutes // 60
        return f"for {hours} {'hour' if hours == 1 else 'hours'}"
    return f"for {minutes} minutes"


def block(conn, ip, minutes, reason, actor, alert_id=None, analyst_ip=None):
    """Block an address, or extend its current block. Returns the block record.

    Raises ValidationError with a reader-facing reason when the address may not be blocked.
    """
    if minutes is not None and (not isinstance(minutes, int) or isinstance(minutes, bool) or minutes not in DURATIONS):
        raise ValidationError("minutes: choose 15, 60, 1440 or 10080, or null for permanent")
    reason = (reason or "").strip()[:500] or None
    refusal = protected_reason(ip, analyst_ip)
    if refusal:
        raise ValidationError(refusal)
    address = str(ipaddress.ip_address(str(ip).strip()))

    now = utc_now()
    expires_at = format_ts(now + timedelta(minutes=minutes)) if minutes is not None else None
    existing = active_for(conn, address)
    with conn:
        if existing:
            conn.execute(
                "UPDATE blocks SET expires_at = ?, reason = COALESCE(?, reason) WHERE id = ?",
                (expires_at, reason, existing["id"]),
            )
            block_id = existing["id"]
            verb = "Extended block of"
        else:
            cur = conn.execute(
                "INSERT INTO blocks (ip, reason, created_by, alert_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
                (address, reason, actor, alert_id, format_ts(now), expires_at),
            )
            block_id = cur.lastrowid
            verb = "Blocked"
        message = f"{verb} {address} {_describe(minutes)}" + (f": {reason}" if reason else "")
        _record_event(conn, "block", address, actor, message)
        if alert_id is not None:
            conn.execute(
                "INSERT INTO alert_notes (alert_id, author, body, created_at, kind) VALUES (?, ?, ?, ?, 'change')",
                (alert_id, actor, f"{verb} {address} {_describe(minutes)}", format_ts(now)),
            )
    write_blocklist(conn)
    log.info("%s by %s", message, actor)
    return _row(conn.execute("SELECT * FROM blocks WHERE id = ?", (block_id,)).fetchone(), format_ts(utc_now()))


def unblock(conn, block_id, actor):
    """End a block early. Returns the record, or None if there is no such active block."""
    row = conn.execute("SELECT * FROM blocks WHERE id = ?", (block_id,)).fetchone()
    now = format_ts(utc_now())
    if row is None or not _row(row, now)["active"]:
        return None
    with conn:
        conn.execute("UPDATE blocks SET removed_at = ?, removed_by = ? WHERE id = ?", (now, actor, block_id))
        _record_event(conn, "unblock", row["ip"], actor, f"Unblocked {row['ip']}")
        if row["alert_id"] is not None:
            conn.execute(
                "INSERT INTO alert_notes (alert_id, author, body, created_at, kind) VALUES (?, ?, ?, ?, 'change')",
                (row["alert_id"], actor, f"Unblocked {row['ip']}", now),
            )
    write_blocklist(conn)
    return _row(conn.execute("SELECT * FROM blocks WHERE id = ?", (block_id,)).fetchone(), format_ts(utc_now()))


def expire(conn):
    """Record the end of blocks whose time ran out. Returns how many ended."""
    now = format_ts(utc_now())
    rows = conn.execute(
        "SELECT b.id, b.ip FROM blocks b WHERE b.removed_at IS NULL AND b.expires_at IS NOT NULL AND b.expires_at <= ? "
        "AND NOT EXISTS (SELECT 1 FROM events e WHERE e.source = 'siem' AND e.action = 'unblock' "
        "AND e.src_ip = b.ip AND e.ts >= b.expires_at)",
        (now,),
    ).fetchall()
    if rows:
        with conn:
            for row in rows:
                _record_event(conn, "unblock", row["ip"], "expired", f"Block of {row['ip']} expired")
        write_blocklist(conn)
    return len(rows)


# --- Enforcement file -----------------------------------------------------------------------

def write_blocklist(conn, path=None):
    """Write the active blocks for the firewall sync. Atomic: readers see the old or the new file."""
    path = path or _settings["file"]
    if not path:
        return False
    entries = [{"ip": b["ip"], "expires_at": b["expires_at"]} for b in active(conn)]
    target = Path(path)
    with _file_lock:
        target.parent.mkdir(parents=True, exist_ok=True)
        handle, temp = tempfile.mkstemp(dir=target.parent, prefix=".blocklist-", suffix=".json")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as out:
                json.dump({"generated_at": format_ts(utc_now()), "blocks": entries}, out)
            os.chmod(temp, 0o644)
            os.replace(temp, target)
        except BaseException:
            Path(temp).unlink(missing_ok=True)
            raise
    return True


def enforcement_status(path=None):
    """What the server firewall last applied, from the status file the root sync writes."""
    path = path or _settings["file"]
    if not path:
        return {"mode": "record-only"}
    status_file = Path(path).with_name("blocklist.applied.json")
    try:
        status = json.loads(status_file.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"mode": "firewall", "last_applied_at": None, "error": "The firewall has not applied the blocklist yet."}
    except (OSError, ValueError) as exc:
        return {"mode": "firewall", "last_applied_at": None, "error": f"Cannot read the firewall status: {exc}"}
    return {"mode": "firewall", **status}


def auto_block(conn, rule, fields, alert_id, minutes):
    """Block the alert's source address for a rule with auto-block on. Never raises."""
    ip = fields.get("src_ip")
    if not ip or minutes is None:
        return None
    try:
        if protected_reason(ip):
            return None
        if recently_signed_in(conn, ip):
            log.info("Auto-block skipped %s: an analyst signed in from it recently", ip)
            return None
        if active_for(conn, ip):
            return None
        return block(conn, ip, minutes, f"Auto-block: {rule.name}", f"rule:{rule.id}", alert_id=alert_id)
    except Exception:
        log.exception("Auto-block of %s failed", ip)
        return None

