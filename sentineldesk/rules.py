"""Rule loader and detection engine.

Rules are YAML files (Sigma-inspired). Four rule types:

  match      one event matches a selection              (e.g. encoded PowerShell)
  threshold  N matching events per entity in a window   (e.g. brute force)
  distinct   N distinct values of a field in a window   (e.g. password spray)
  sequence   N "first" events then a "then" event       (e.g. failures -> success)

Selection keys look like  field|operator: value  with operators
eq (default), contains, startswith, endswith, re.  A list of values means OR;
all keys in a selection must match (AND). Matching is case-insensitive.
"""
from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Optional

import yaml

from .models import SEVERITY_ORDER, Alert, Event

RULE_TYPES = {"match", "threshold", "distinct", "sequence"}


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    tactic: str
    techniques: list[str]
    type: str
    description: str = ""
    response: list[str] = field(default_factory=list)
    selection: dict[str, Any] = field(default_factory=dict)
    exclude: dict[str, Any] = field(default_factory=dict)
    group_by: list[str] = field(default_factory=list)
    count: int = 1
    window: int = 300
    distinct_field: str = ""
    first: dict[str, Any] = field(default_factory=dict)
    then: dict[str, Any] = field(default_factory=dict)
    path: str = ""


def load_rules(path: str | Path) -> list[Rule]:
    path = Path(path)
    files = sorted(path.glob("*.y*ml")) if path.is_dir() else [path]
    rules: list[Rule] = []
    for f in files:
        data = yaml.safe_load(f.read_text(encoding="utf-8"))
        rules.append(_build_rule(data, f))
    ids = [r.id for r in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"duplicate rule ids: {sorted(dupes)}")
    return rules


def _build_rule(data: dict, path: Path) -> Rule:
    for key in ("id", "title", "severity", "tactic", "techniques", "type"):
        if key not in data:
            raise ValueError(f"{path.name}: missing required key '{key}'")
    if data["severity"] not in SEVERITY_ORDER:
        raise ValueError(f"{path.name}: severity must be one of {sorted(SEVERITY_ORDER)}")
    if data["type"] not in RULE_TYPES:
        raise ValueError(f"{path.name}: type must be one of {sorted(RULE_TYPES)}")
    for item in data.get("response") or []:
        if not isinstance(item, str):
            raise ValueError(f"{path.name}: every 'response' entry must be a plain string "
                             f"(quote it if it contains ': '), got {item!r}")
    group_by = data.get("group_by") or []
    if isinstance(group_by, str):
        group_by = [group_by]
    rule = Rule(
        id=data["id"], title=data["title"], severity=data["severity"], tactic=data["tactic"],
        techniques=list(data["techniques"]), type=data["type"],
        description=(data.get("description") or "").strip(), response=list(data.get("response") or []),
        selection=data.get("selection") or {}, exclude=data.get("exclude") or {}, group_by=group_by,
        count=int(data.get("count", 1)), window=int(data.get("window", 300)),
        distinct_field=data.get("distinct_field", ""), first=data.get("first") or {},
        then=data.get("then") or {}, path=str(path))
    if rule.type in ("threshold", "distinct", "sequence") and not rule.group_by:
        raise ValueError(f"{path.name}: {rule.type} rules need group_by")
    if rule.type == "distinct" and not rule.distinct_field:
        raise ValueError(f"{path.name}: distinct rules need distinct_field")
    if rule.type == "sequence" and not (rule.first.get("selection") and rule.then.get("selection")):
        raise ValueError(f"{path.name}: sequence rules need first.selection and then.selection")
    return rule


# --------------------------------------------------------------------- matching
@lru_cache(maxsize=256)
def _regex(pattern: str):
    return re.compile(pattern, re.IGNORECASE)


def _match_value(actual: Any, op: str, expected: Any) -> bool:
    values = expected if isinstance(expected, list) else [expected]
    a = str(actual)
    al = a.lower()
    if op == "eq":
        return any(al == str(v).lower() for v in values)
    if op == "contains":
        return any(str(v).lower() in al for v in values)
    if op == "startswith":
        return any(al.startswith(str(v).lower()) for v in values)
    if op == "endswith":
        return any(al.endswith(str(v).lower()) for v in values)
    if op == "re":
        return any(_regex(str(v)).search(a) for v in values)
    raise ValueError(f"unknown operator: {op}")


def matches(event: Event, selection: dict[str, Any]) -> bool:
    for key, expected in selection.items():
        name, _, op = key.partition("|")
        if not _match_value(event.get(name), op or "eq", expected):
            return False
    return True


def _hit(rule: Rule, ev: Event) -> bool:
    return matches(ev, rule.selection) and not (rule.exclude and matches(ev, rule.exclude))


def _key(rule: Rule, ev: Event) -> Optional[tuple]:
    vals = tuple(str(ev.get(f)) for f in rule.group_by)
    return vals if any(vals) else None


def _new_alert(rule: Rule, events: list[Event], key: Optional[tuple] = None) -> Alert:
    return Alert(rule_id=rule.id, title=rule.title, severity=rule.severity, tactic=rule.tactic,
                 techniques=rule.techniques, description=rule.description, response=rule.response,
                 events=list(events), group="|".join(key) if key else "",
                 keep_user=rule.type in ("match", "sequence") or "user" in rule.group_by)


# ------------------------------------------------------------------ evaluators
def eval_match(rule: Rule, events: list[Event]) -> list[Alert]:
    out: list[Alert] = []
    open_: dict[tuple, Alert] = {}
    for ev in events:
        if not _hit(rule, ev):
            continue
        key = _key(rule, ev) if rule.group_by else None
        cur = open_.get(key) if key else None
        if cur and (ev.ts - cur.ts_last).total_seconds() <= rule.window:
            cur.extend(ev)  # same entity, still active: merge instead of alert-spamming
        else:
            cur = _new_alert(rule, [ev], key)
            out.append(cur)
            if key:
                open_[key] = cur
    return out


def _eval_windowed(rule: Rule, events: list[Event], triggered: Callable[[deque], bool]) -> list[Alert]:
    buckets: dict[tuple, deque] = defaultdict(deque)
    open_: dict[tuple, Alert] = {}
    out: list[Alert] = []
    for ev in events:
        if not _hit(rule, ev):
            continue
        key = _key(rule, ev)
        if key is None:
            continue
        cur = open_.get(key)
        if cur and (ev.ts - cur.ts_last).total_seconds() <= rule.window:
            cur.extend(ev)
            continue
        dq = buckets[key]
        dq.append(ev)
        while (ev.ts - dq[0].ts).total_seconds() > rule.window:
            dq.popleft()
        if triggered(dq):
            alert = _new_alert(rule, list(dq), key)
            out.append(alert)
            open_[key] = alert
            dq.clear()
    return out


def eval_threshold(rule: Rule, events: list[Event]) -> list[Alert]:
    return _eval_windowed(rule, events, lambda dq: len(dq) >= rule.count)


def eval_distinct(rule: Rule, events: list[Event]) -> list[Alert]:
    return _eval_windowed(rule, events, lambda dq: len({e.get(rule.distinct_field) for e in dq}) >= rule.count)


def eval_sequence(rule: Rule, events: list[Event]) -> list[Alert]:
    first_sel, then_sel = rule.first["selection"], rule.then["selection"]
    need = int(rule.first.get("count", 1))
    buckets: dict[tuple, deque] = defaultdict(deque)
    out: list[Alert] = []
    for ev in events:
        key = _key(rule, ev)
        if key is None:
            continue
        dq = buckets[key]
        while dq and (ev.ts - dq[0].ts).total_seconds() > rule.window:
            dq.popleft()
        if matches(ev, first_sel):
            dq.append(ev)
        elif matches(ev, then_sel) and len(dq) >= need:
            out.append(_new_alert(rule, list(dq) + [ev], key))
            dq.clear()
    return out


EVALUATORS = {"match": eval_match, "threshold": eval_threshold, "distinct": eval_distinct,
              "sequence": eval_sequence}


def run_rules(rules: list[Rule], events: list[Event]) -> list[Alert]:
    events = sorted(events, key=lambda e: e.ts)
    alerts: list[Alert] = []
    for rule in rules:
        alerts.extend(EVALUATORS[rule.type](rule, events))
    alerts.sort(key=lambda a: (a.ts_first, -SEVERITY_ORDER[a.severity]))
    return alerts
