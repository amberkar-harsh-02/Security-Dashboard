"""Windows Security log events exported as JSON (for example by Winlogbeat or NXLog).

Accepts both flat objects and objects with an "EventData" sub-object.
"""

import json

LOGON_TYPES = {"2": "interactive", "3": "network", "7": "unlock", "10": "remote desktop", "11": "cached"}

# EventID: (action, outcome, severity, description)
EVENTS = {
    4624: ("login", "success", "info", "An account logged on"),
    4625: ("login", "failure", "low", "An account failed to log on"),
    4634: ("logout", "success", "info", "An account logged off"),
    4648: ("login_explicit", "success", "low", "A logon was attempted using explicit credentials"),
    4672: ("special_privileges", "success", "medium", "Special privileges assigned to new logon"),
    4688: ("process_started", "success", "info", "A new process has been created"),
    4720: ("user_created", "success", "medium", "A user account was created"),
    4726: ("user_deleted", "success", "medium", "A user account was deleted"),
    4732: ("group_member_added", "success", "high", "A member was added to a security-enabled local group"),
    4740: ("account_locked", "failure", "medium", "A user account was locked out"),
    1102: ("log_cleared", "success", "high", "The audit log was cleared"),
}

CATEGORIES = {
    "login": "authentication", "logout": "authentication", "login_explicit": "authentication",
    "account_locked": "authentication", "special_privileges": "privilege",
    "process_started": "process", "user_created": "iam", "user_deleted": "iam",
    "group_member_added": "iam", "log_cleared": "audit",
}


def _clean(value):
    return None if value in (None, "", "-", "::1", "127.0.0.1") else value


def parse(data):
    """`data` is a dict with an EventID. Returns event fields, or None if not a Windows event."""
    if not isinstance(data, dict) or "EventID" not in data:
        return None
    try:
        event_id = int(data["EventID"])
    except (TypeError, ValueError):
        return None

    fields = {**data, **(data.get("EventData") or {})}
    action, outcome, severity, description = EVENTS.get(
        event_id, ("windows_event", "unknown", "info", f"Windows event {event_id}")
    )

    user = _clean(fields.get("TargetUserName")) or _clean(fields.get("SubjectUserName"))
    message = f"{description}: {user}" if user else description

    logon_type = str(fields.get("LogonType", ""))
    if action in ("login", "login_explicit") and logon_type in LOGON_TYPES:
        message += f" ({LOGON_TYPES[logon_type]})"
    if action == "process_started" and fields.get("NewProcessName"):
        message += f" ran {fields['NewProcessName']}"
    if action == "group_member_added" and fields.get("TargetUserName"):
        member = fields.get("MemberName") or fields.get("MemberSid") or "unknown"
        message = f"{description}: {member} added to {fields['TargetUserName']}"
        user = _clean(fields.get("SubjectUserName")) or user

    return {
        "ts": fields.get("TimeCreated") or fields.get("ts"),
        "source": "windows",
        "host": fields.get("Computer") or fields.get("WorkstationName"),
        "category": CATEGORIES.get(action, "windows"),
        "action": action,
        "outcome": outcome,
        "severity": severity,
        "user": user,
        "src_ip": _clean(fields.get("IpAddress")),
        "src_port": _clean(fields.get("IpPort")),
        "process": fields.get("NewProcessName") or fields.get("ProcessName"),
        "message": message,
        "raw": json.dumps(data, default=str),
    }
