"""Turn raw log lines into event dicts that `events.normalize` accepts."""

import json

from . import firewall, sshd, syslog, web, windows

FORMATS = ("auto", "syslog", "sshd", "web", "firewall", "windows")

# Message parsers tried on a syslog body or a bare line, in order.
MESSAGE_PARSERS = {"sshd": sshd.parse, "firewall": firewall.parse, "web": web.parse}
APP_HINTS = {"sshd": "sshd", "kernel": "firewall", "ufw": "firewall", "nginx": "web", "apache2": "web", "httpd": "web"}


class ParseError(ValueError):
    pass


def _parse_message(text, preferred=None):
    order = [preferred] if preferred else []
    order += [name for name in MESSAGE_PARSERS if name != preferred]
    for name in order:
        result = MESSAGE_PARSERS[name](text)
        if result:
            return result
    return None


def _parse_json(line):
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    return windows.parse(data) or {**data, "raw": data.get("raw") or line}


def parse_line(line, fmt="auto", default_host=None):
    """Parse one log line. Unrecognized lines are kept as `category=unknown` events.

    `default_host` is used when the line itself names no host (for example the syslog sender).
    """
    line = line.rstrip("\r\n")
    if not line.strip():
        raise ParseError("empty line")
    fmt = fmt or "auto"
    if fmt not in FORMATS:
        raise ParseError(f"unknown format {fmt!r}; use one of {', '.join(FORMATS)}")

    if fmt == "windows":
        result = _parse_json(line)
        if not result or result.get("source") != "windows":
            raise ParseError("not a Windows event JSON object with an EventID")
        return result

    if fmt == "auto" and line.lstrip().startswith("{"):
        result = _parse_json(line)
        if result:
            return result

    if fmt in ("auto", "syslog"):
        header = syslog.parse(line)
        if header:
            hint = APP_HINTS.get((header["app"] or "").lower())
            result = _parse_message(header["message"], hint) or {
                "source": header["app"] or "syslog",
                "category": "system",
                "severity": header["severity"],
                "process": header["app"],
                "message": header["message"] or line,
            }
            result["host"] = result.get("host") or header["host"] or default_host
            result["ts"] = result.get("ts") or header["ts"]
            result["raw"] = line
            return result
        if fmt == "syslog":
            raise ParseError("not a syslog line")

    if fmt in MESSAGE_PARSERS:
        result = MESSAGE_PARSERS[fmt](line)
        if not result:
            raise ParseError(f"line does not match the {fmt} format")
    else:
        result = _parse_message(line) or {"source": "unknown", "category": "unknown", "message": line}

    result["host"] = result.get("host") or default_host
    result["raw"] = line
    return result
