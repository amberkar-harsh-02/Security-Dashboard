"""Load detection rules from YAML and compile their conditions to SQL.

A rule file looks like this:

    id: ssh-brute-force
    name: SSH brute force
    description: Many failed SSH logins from one address.
    severity: high
    type: threshold           # match | threshold | distinct | sequence | ioc
    where:
      source: sshd
      outcome: failure
      action: [login, invalid_user]     # a list matches any value
      message|contains: password        # operators: contains, startswith, endswith, regex, gt, gte, lt, lte
    group_by: [src_ip]
    window: 2m
    threshold: 10
    title: "SSH brute force from {src_ip}"
    mitre: {tactic: Credential Access, technique: T1110.001, name: Password Guessing}

Type-specific keys:
- distinct: `field` (count distinct values of it) and `threshold`.
- sequence: `steps`, a list of two {where, count} objects. The first step must happen at
  least `count` times before the second, for the same group, within `window`.
- ioc: `field` and `list` (a file name in the intel directory, without .txt).
"""

import re
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import timedelta
from pathlib import Path

import yaml

from ..events import SEVERITIES

EVENT_FIELDS = {
    "source", "host", "category", "action", "outcome", "severity", "user", "src_ip", "src_port",
    "dst_ip", "dst_port", "process", "message", "raw",
}
TYPES = ("match", "threshold", "distinct", "sequence", "ioc")
OPERATORS = ("eq", "contains", "startswith", "endswith", "regex", "gt", "gte", "lt", "lte")
COMPARISONS = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}
DURATION = re.compile(r"^(\d+)\s*([smhd])$")
UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


class RuleError(ValueError):
    pass


def parse_duration(text, where):
    match = DURATION.match(str(text).strip())
    if not match:
        raise RuleError(f"{where}: duration must look like 30s, 5m, 1h or 1d, not {text!r}")
    return timedelta(**{UNITS[match[2]]: int(match[1])})


def _like_escape(text):
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def compile_where(where, context="where"):
    """Return (sql, params) for a condition mapping. An empty mapping matches everything."""
    if where is None:
        return "1=1", []
    if not isinstance(where, dict):
        raise RuleError(f"{context}: must be a mapping of field to value")

    clauses, params = [], []
    for key, value in where.items():
        name, _, op = str(key).partition("|")
        op = op or "eq"
        if name not in EVENT_FIELDS:
            raise RuleError(f"{context}: unknown field {name!r}")
        if op not in OPERATORS:
            raise RuleError(f"{context}: unknown operator {op!r} on {name!r}")

        values = value if isinstance(value, list) else [value]
        if not values:
            raise RuleError(f"{context}: {key!r} has an empty list")

        options = []
        for item in values:
            if op == "eq":
                if item is None:
                    options.append(f"{name} IS NULL")
                else:
                    options.append(f"{name} = ?")
                    params.append(item)
            elif op in ("contains", "startswith", "endswith"):
                text = _like_escape(str(item).lower())
                pattern = {"contains": f"%{text}%", "startswith": f"{text}%", "endswith": f"%{text}"}[op]
                options.append(f"LOWER({name}) LIKE ? ESCAPE '\\'")
                params.append(pattern)
            elif op == "regex":
                try:
                    re.compile(str(item))
                except re.error as exc:
                    raise RuleError(f"{context}: invalid regex for {name!r}: {exc}")
                options.append(f"{name} REGEXP ?")
                params.append(str(item))
            else:
                options.append(f"{name} {COMPARISONS[op]} ?")
                params.append(item)
        clauses.append(options[0] if len(options) == 1 else "(" + " OR ".join(options) + ")")

    return (" AND ".join(clauses) or "1=1"), params


@dataclass
class Rule:
    id: str
    name: str
    description: str
    severity: str
    type: str
    title: str
    group_by: list
    window: timedelta
    dedupe: timedelta
    threshold: int = 1
    field: str = None
    where_sql: str = "1=1"
    where_params: list = dataclass_field(default_factory=list)
    steps: list = dataclass_field(default_factory=list)  # for sequence: [(sql, params, count), (sql, params, 1)]
    ioc_list: str = None
    mitre: dict = dataclass_field(default_factory=dict)
    enabled: bool = True
    path: str = None
    source: dict = dataclass_field(default_factory=dict)

    def summary(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "type": self.type,
            "enabled": self.enabled,
            "group_by": self.group_by,
            "window_seconds": int(self.window.total_seconds()),
            "threshold": self.threshold,
            "field": self.field,
            "mitre": self.mitre,
            "definition": self.source,
        }


def build_rule(data, path="<rule>", intel=None):
    """Validate a parsed YAML mapping and return a Rule."""
    if not isinstance(data, dict):
        raise RuleError(f"{path}: rule file must contain a mapping")

    def need(key):
        if not data.get(key):
            raise RuleError(f"{path}: missing required key {key!r}")
        return data[key]

    rule_id = str(need("id"))
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", rule_id):
        raise RuleError(f"{path}: id must use lowercase letters, digits and dashes")
    ctx = f"{path} ({rule_id})"

    rule_type = need("type")
    if rule_type not in TYPES:
        raise RuleError(f"{ctx}: type must be one of {', '.join(TYPES)}")
    severity = need("severity")
    if severity not in SEVERITIES:
        raise RuleError(f"{ctx}: severity must be one of {', '.join(SEVERITIES)}")

    group_by = data.get("group_by") or []
    if isinstance(group_by, str):
        group_by = [group_by]
    for name in group_by:
        if name not in EVENT_FIELDS:
            raise RuleError(f"{ctx}: group_by has unknown field {name!r}")
    if rule_type in ("threshold", "distinct", "sequence") and not group_by:
        raise RuleError(f"{ctx}: {rule_type} rules need group_by")

    window = parse_duration(data.get("window", "5m"), f"{ctx} window")
    dedupe = parse_duration(data["dedupe"], f"{ctx} dedupe") if data.get("dedupe") else max(window, timedelta(minutes=10))

    rule = Rule(
        id=rule_id,
        name=str(need("name")),
        description=str(data.get("description", "")).strip(),
        severity=severity,
        type=rule_type,
        title=str(data.get("title") or data["name"]),
        group_by=list(group_by),
        window=window,
        dedupe=dedupe,
        mitre=data.get("mitre") or {},
        enabled=bool(data.get("enabled", True)),
        path=str(path),
        source=data,
    )

    if rule_type != "sequence":
        rule.where_sql, rule.where_params = compile_where(data.get("where"), f"{ctx} where")

    if rule_type in ("threshold", "distinct"):
        try:
            rule.threshold = int(need("threshold"))
        except (TypeError, ValueError):
            raise RuleError(f"{ctx}: threshold must be an integer")
        if rule.threshold < 1:
            raise RuleError(f"{ctx}: threshold must be at least 1")

    if rule_type in ("distinct", "ioc"):
        rule.field = need("field")
        if rule.field not in EVENT_FIELDS:
            raise RuleError(f"{ctx}: unknown field {rule.field!r}")

    if rule_type == "sequence":
        steps = need("steps")
        if not isinstance(steps, list) or len(steps) != 2:
            raise RuleError(f"{ctx}: steps must be a list of exactly two steps")
        for index, step in enumerate(steps):
            if not isinstance(step, dict):
                raise RuleError(f"{ctx}: step {index + 1} must be a mapping")
            sql, params = compile_where(step.get("where"), f"{ctx} step {index + 1}")
            count = int(step.get("count", 1))
            rule.steps.append((sql, params, count))

    if rule_type == "ioc":
        rule.ioc_list = str(need("list"))
        if intel is not None and rule.ioc_list not in intel:
            raise RuleError(f"{ctx}: intel list {rule.ioc_list!r} not found")

    return rule


def load_intel(intel_dir):
    """Read every <name>.txt in the intel directory into {name: set of values}."""
    lists = {}
    directory = Path(intel_dir)
    if not directory.is_dir():
        return lists
    for path in sorted(directory.glob("*.txt")):
        values = set()
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                values.add(line)
        lists[path.stem] = values
    return lists


def load_rules(rules_dir, intel=None):
    """Load every *.yml / *.yaml file. A file may hold one rule or a list of rules."""
    rules = {}
    for path in sorted(Path(rules_dir).glob("*.y*ml")):
        try:
            documents = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise RuleError(f"{path.name}: invalid YAML: {exc}")
        for data in documents if isinstance(documents, list) else [documents]:
            rule = build_rule(data, path.name, intel)
            if rule.id in rules:
                raise RuleError(f"{path.name}: duplicate rule id {rule.id!r} (also in {rules[rule.id].path})")
            rules[rule.id] = rule
    return rules
