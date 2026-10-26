from flask import Blueprint, current_app, jsonify, request

from .. import blocks
from ..alerts import add_note, bulk_update_status, get_alert, list_alerts, rule_hit_counts, update_alert
from ..auth import check_session, current_user, list_usernames
from ..db import get_db
from ..detection import RuleError
from ..events import ValidationError

bp = Blueprint("alerts", __name__, url_prefix="/api")
bp.before_request(check_session)


def _body():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise ValidationError("Request body must be a JSON object")
    return body


@bp.get("/alerts")
def alerts():
    return jsonify(list_alerts(get_db(), request.args.to_dict()))


def _with_rule(alert):
    """Attach the rule's current description and settings, and any active block of the source address."""
    rule = current_app.extensions["siem_engine"].rules.get(alert["rule_id"])
    if rule is not None:
        summary = rule.summary()
        summary.pop("definition", None)
        alert["rule"] = summary
    else:
        alert["rule"] = None
    src_ip = alert["group_fields"].get("src_ip")
    alert["blocked"] = blocks.active_for(get_db(), src_ip) if src_ip else None
    return alert


@bp.get("/alerts/<int:alert_id>")
def alert_detail(alert_id):
    alert = get_alert(get_db(), alert_id)
    if alert is None:
        return jsonify({"error": f"Alert {alert_id} not found"}), 404
    return jsonify(_with_rule(alert))


@bp.patch("/alerts/<int:alert_id>")
def change_alert(alert_id):
    conn = get_db()
    alert = update_alert(conn, alert_id, _body(), current_user(), list_usernames(conn))
    if alert is None:
        return jsonify({"error": f"Alert {alert_id} not found"}), 404
    return jsonify(_with_rule(alert))


@bp.post("/alerts/bulk")
def change_alerts():
    body = _body()
    changed = bulk_update_status(get_db(), body.get("ids"), body.get("status"), current_user())
    return jsonify({"changed": changed})


@bp.post("/alerts/<int:alert_id>/notes")
def create_note(alert_id):
    note = add_note(get_db(), alert_id, current_user(), _body().get("body"))
    if note is None:
        return jsonify({"error": f"Alert {alert_id} not found"}), 404
    return jsonify(dict(note)), 201


def _rule_summaries(engine, conn):
    enabled = engine.enabled_map(conn)
    auto_block = engine.auto_block_map(conn)
    hits = rule_hit_counts(conn)
    result = []
    for rule in engine.rules.values():
        summary = rule.summary()
        summary["enabled"] = enabled[rule.id]
        summary["alerts_24h"] = hits.get(rule.id, 0)
        summary["can_auto_block"] = "src_ip" in rule.group_by
        summary["auto_block_minutes"] = auto_block[rule.id]
        result.append(summary)
    return result


@bp.get("/rules")
def rules():
    engine = current_app.extensions["siem_engine"]
    return jsonify({"rules": _rule_summaries(engine, get_db())})


@bp.patch("/rules/<rule_id>")
def change_rule(rule_id):
    """Turn a rule on or off ({"enabled": bool}) and/or set its auto-block ({"auto_block_minutes": ...})."""
    body = _body()
    if "enabled" not in body and "auto_block_minutes" not in body:
        raise ValidationError("Send enabled and/or auto_block_minutes")
    if "enabled" in body and not isinstance(body["enabled"], bool):
        raise ValidationError("enabled: send true or false")
    minutes = body.get("auto_block_minutes")
    if "auto_block_minutes" in body and minutes is not None and (not isinstance(minutes, int) or isinstance(minutes, bool)):
        raise ValidationError("auto_block_minutes: send 15, 60, 1440 or null")

    engine = current_app.extensions["siem_engine"]
    conn = get_db()
    try:
        if "enabled" in body:
            engine.set_enabled(conn, rule_id, body["enabled"])
        if "auto_block_minutes" in body:
            engine.set_auto_block(conn, rule_id, minutes)
    except KeyError:
        return jsonify({"error": f"Rule {rule_id!r} not found"}), 404
    except ValueError as exc:
        raise ValidationError(str(exc))
    return jsonify(next(r for r in _rule_summaries(engine, conn) if r["id"] == rule_id))


@bp.post("/rules/reload")
def reload_rules():
    """Re-read rule and intel files. On an error the previous rules stay active."""
    engine = current_app.extensions["siem_engine"]
    try:
        engine.reload()
    except RuleError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"rules": _rule_summaries(engine, get_db())})


@bp.get("/blocks")
def list_blocks():
    conn = get_db()
    return jsonify({
        "enforcement": blocks.enforcement_status(),
        "durations": list(blocks.DURATIONS),
        "active": blocks.active(conn),
        "history": blocks.history(conn),
    })


@bp.post("/blocks")
def create_block():
    body = _body()
    alert_id = body.get("alert_id")
    if alert_id is not None and (not isinstance(alert_id, int) or isinstance(alert_id, bool)):
        raise ValidationError("alert_id: expected an alert id")
    record = blocks.block(
        get_db(),
        body.get("ip"),
        body.get("minutes"),
        body.get("reason"),
        current_user(),
        alert_id=alert_id,
        analyst_ip=request.remote_addr,
    )
    return jsonify(record), 201


@bp.post("/blocks/<int:block_id>/unblock")
def end_block(block_id):
    record = blocks.unblock(get_db(), block_id, current_user())
    if record is None:
        return jsonify({"error": f"Block {block_id} is not active"}), 404
    return jsonify(record)


@bp.errorhandler(ValidationError)
def handle_validation(exc):
    return jsonify({"error": str(exc)}), 400
