"""Evaluate detection rules against newly stored events and raise alerts.

Every evaluation is scoped to the new batch: a rule only fires for groups (for example a
source IP) that appear in the batch, and looks back over the rule's window in SQL. State
lives in the database, so restarts lose nothing.
"""

import json
import logging
import threading

from .. import blocks
from ..events import format_ts, parse_ts, utc_now
from .rules import load_intel, load_rules

log = logging.getLogger("siem.detection")

MAX_LINKED_EVENTS = 1000


class _Blank(dict):
    def __missing__(self, key):
        return "unknown"


def _ids_param(ids):
    return json.dumps(list(ids))


def _key(event, group_by):
    values = tuple(event[name] for name in group_by)
    return None if any(v is None for v in values) else values


def _shift(ts, delta):
    return format_ts(parse_ts(ts) + delta)


class Engine:
    def __init__(self, rules_dir, intel_dir):
        self.rules_dir = rules_dir
        self.intel_dir = intel_dir
        self.lock = threading.RLock()
        self._auto_block = {}  # rule id -> minutes, refreshed on each evaluation
        self.reload()

    def reload(self):
        intel = load_intel(self.intel_dir)
        rules = load_rules(self.rules_dir, intel)
        with self.lock:
            self.intel, self.rules = intel, rules
        log.info("Loaded %d detection rules and %d intel lists", len(rules), len(intel))

    # --- Rule settings -----------------------------------------------------------------------

    def enabled_map(self, conn):
        overrides = {row["rule_id"]: bool(row["enabled"]) for row in conn.execute("SELECT * FROM rule_settings")}
        return {rule_id: overrides.get(rule_id, rule.enabled) for rule_id, rule in self.rules.items()}

    def auto_block_map(self, conn):
        """Minutes to block a new alert's source for, per rule (None: auto-block off)."""
        stored = {
            row["rule_id"]: row["auto_block_minutes"]
            for row in conn.execute("SELECT rule_id, auto_block_minutes FROM rule_settings")
        }
        return {rule_id: stored.get(rule_id) for rule_id in self.rules}

    def set_auto_block(self, conn, rule_id, minutes):
        rule = self.rules.get(rule_id)
        if rule is None:
            raise KeyError(rule_id)
        if "src_ip" not in rule.group_by:
            raise ValueError(f"{rule.name} does not group by source address, so it cannot auto-block")
        if minutes is not None and minutes not in blocks.AUTO_BLOCK_DURATIONS:
            raise ValueError("auto_block_minutes: choose 15, 60 or 1440, or null to turn it off")
        enabled = self.enabled_map(conn)[rule_id]
        with conn:
            conn.execute(
                "INSERT INTO rule_settings (rule_id, enabled, auto_block_minutes, updated_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT (rule_id) DO UPDATE SET auto_block_minutes = excluded.auto_block_minutes, "
                "updated_at = excluded.updated_at",
                (rule_id, int(enabled), minutes, format_ts(utc_now())),
            )

    def set_enabled(self, conn, rule_id, enabled):
        if rule_id not in self.rules:
            raise KeyError(rule_id)
        with conn:
            conn.execute(
                "INSERT INTO rule_settings (rule_id, enabled, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT (rule_id) DO UPDATE SET enabled = excluded.enabled, updated_at = excluded.updated_at",
                (rule_id, int(bool(enabled)), format_ts(utc_now())),
            )

    # --- Evaluation --------------------------------------------------------------------------

    def evaluate(self, conn, event_ids):
        """Run every enabled rule over the new events. Returns [{id, created}] for touched alerts."""
        if not event_ids:
            return []
        ids = _ids_param(event_ids)
        results = []
        with self.lock:
            enabled = self.enabled_map(conn)
            self._auto_block = self.auto_block_map(conn)
            for rule in self.rules.values():
                if not enabled[rule.id]:
                    continue
                try:
                    results.extend(getattr(self, f"_run_{rule.type}")(conn, rule, ids))
                except Exception:
                    log.exception("Rule %s failed", rule.id)
            conn.commit()
        return results

    def _new(self, conn, ids, sql, params):
        return conn.execute(
            f"SELECT * FROM events WHERE id IN (SELECT value FROM json_each(?)) AND ({sql}) ORDER BY ts, id",
            [ids, *params],
        ).fetchall()

    def _history(self, conn, sql, params, group_by, key, start, end, columns="*"):
        key_sql = " AND ".join(f"{name} = ?" for name in group_by)
        return conn.execute(
            f"SELECT {columns} FROM events WHERE ({sql}) AND {key_sql} AND ts BETWEEN ? AND ? "
            f"ORDER BY ts DESC, id DESC LIMIT {MAX_LINKED_EVENTS}",
            [*params, *key, start, end],
        ).fetchall()

    @staticmethod
    def _group(events, group_by):
        groups = {}
        for event in events:
            key = _key(event, group_by) if group_by else (event["id"],)
            if key is not None:
                groups.setdefault(key, []).append(event)
        return groups

    def _run_match(self, conn, rule, ids, extra_sql="", extra_params=()):
        events = self._new(conn, ids, rule.where_sql + extra_sql, [*rule.where_params, *extra_params])
        return [self._raise(conn, rule, key, group) for key, group in self._group(events, rule.group_by).items()]

    def _run_ioc(self, conn, rule, ids):
        values = sorted(self.intel.get(rule.ioc_list, ()))
        if not values:
            return []
        return self._run_match(conn, rule, ids, f" AND {rule.field} IN (SELECT value FROM json_each(?))", [json.dumps(values)])

    def _run_threshold(self, conn, rule, ids):
        return self._run_counting(conn, rule, ids, distinct=False)

    def _run_distinct(self, conn, rule, ids):
        return self._run_counting(conn, rule, ids, distinct=True)

    def _run_counting(self, conn, rule, ids, distinct):
        results = []
        events = self._new(conn, ids, rule.where_sql, rule.where_params)
        for key, group in self._group(events, rule.group_by).items():
            end = max(e["ts"] for e in group)
            start = _shift(end, -rule.window)
            window = self._history(conn, rule.where_sql, rule.where_params, rule.group_by, key, start, end)
            size = len({e[rule.field] for e in window if e[rule.field] is not None}) if distinct else len(window)
            if size >= rule.threshold:
                results.append(self._raise(conn, rule, key, window))
        return results

    def _run_sequence(self, conn, rule, ids):
        (first_sql, first_params, first_count), (last_sql, last_params, _) = rule.steps
        results = []
        triggers = self._new(conn, ids, last_sql, last_params)
        for key, group in self._group(triggers, rule.group_by).items():
            trigger = group[-1]
            start = _shift(trigger["ts"], -rule.window)
            earlier = [
                e for e in self._history(conn, first_sql, first_params, rule.group_by, key, start, trigger["ts"])
                if e["id"] != trigger["id"]
            ]
            if len(earlier) >= first_count:
                results.append(self._raise(conn, rule, key, [*earlier, trigger]))
        return results

    # --- Alerts ------------------------------------------------------------------------------

    def _raise(self, conn, rule, key, events):
        """Create an alert, or add events to a recent open alert for the same rule and group."""
        fields = dict(zip(rule.group_by, key)) if rule.group_by else {}
        group_key = "&".join(f"{k}={v}" for k, v in fields.items()) or f"event={key[0]}"
        first = min(e["ts"] for e in events)
        last = max(e["ts"] for e in events)
        now = format_ts(utc_now())

        existing = conn.execute(
            "SELECT id, first_seen, last_seen FROM alerts WHERE rule_id = ? AND group_key = ? "
            "AND status != 'closed' AND last_seen >= ? ORDER BY id DESC LIMIT 1",
            (rule.id, group_key, _shift(first, -rule.dedupe)),
        ).fetchone()

        if existing:
            alert_id, created = existing["id"], False
            conn.execute(
                "UPDATE alerts SET first_seen = MIN(first_seen, ?), last_seen = MAX(last_seen, ?), updated_at = ? "
                "WHERE id = ?",
                (first, last, now, alert_id),
            )
        else:
            latest = dict(max(events, key=lambda e: (e["ts"], e["id"])))
            title = rule.title.format_map(_Blank({**latest, **fields}))
            cur = conn.execute(
                "INSERT INTO alerts (rule_id, rule_name, severity, title, status, group_key, group_fields, "
                "mitre_tactic, mitre_technique, mitre_name, first_seen, last_seen, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (rule.id, rule.name, rule.severity, title, group_key, json.dumps(fields),
                 rule.mitre.get("tactic"), rule.mitre.get("technique"), rule.mitre.get("name"),
                 first, last, now, now),
            )
            alert_id, created = cur.lastrowid, True

        conn.executemany(
            "INSERT OR IGNORE INTO alert_events (alert_id, event_id) VALUES (?, ?)",
            [(alert_id, e["id"]) for e in events],
        )
        conn.execute(
            "UPDATE alerts SET event_count = (SELECT COUNT(*) FROM alert_events WHERE alert_id = ?) WHERE id = ?",
            (alert_id, alert_id),
        )
        if created:
            log.info("Alert %d: [%s] %s", alert_id, rule.severity, rule.title.format_map(_Blank(fields)))
            minutes = self._auto_block.get(rule.id)
            if minutes:
                blocks.auto_block(conn, rule, fields, alert_id, minutes)
        return {"id": alert_id, "created": created, "rule_id": rule.id}
