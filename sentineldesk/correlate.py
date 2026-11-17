"""Alert correlation: group related alerts into incidents.

Alerts are linked when they share a source IP, or the same user on the same host.
That is enough to turn "12 disconnected alerts" into one attack story.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime

from .models import SEVERITY_ORDER, Alert

SEV_WEIGHT = {"low": 5, "medium": 15, "high": 30, "critical": 50}
GENERIC_USERS = {"", "-", "system", "local service", "network service", "anonymous logon"}


@dataclass
class Incident:
    id: str
    title: str
    severity: str
    score: int
    alerts: list[Alert]
    ts_first: datetime
    ts_last: datetime
    ips: list[str]
    users: list[str]
    hosts: list[str]
    tactics: list[str]
    techniques: list[str]
    response: list[str]

    def to_dict(self) -> dict:
        return {"id": self.id, "title": self.title, "severity": self.severity, "risk_score": self.score,
                "first_seen": self.ts_first.isoformat(), "last_seen": self.ts_last.isoformat(),
                "source_ips": self.ips, "users": self.users, "hosts": self.hosts, "tactics": self.tactics,
                "techniques": self.techniques, "recommended_actions": self.response,
                "alerts": [a.to_dict() for a in self.alerts]}


def _link_keys(a: Alert) -> set[str]:
    keys = set()
    if a.entities.get("src_ip"):
        keys.add("ip:" + a.entities["src_ip"])
    user, host = a.entities.get("user", "").lower(), a.entities.get("host", "").lower()
    if user not in GENERIC_USERS and not user.endswith("$") and host:
        keys.add(f"uh:{host}:{user}")
    return keys


def _uniq(items):
    seen, out = set(), []
    for i in items:
        if i and i not in seen:
            seen.add(i)
            out.append(i)
    return out


def build_incidents(alerts: list[Alert]) -> list[Incident]:
    parent = list(range(len(alerts)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    owner: dict[str, int] = {}
    for idx, alert in enumerate(alerts):
        for key in _link_keys(alert):
            if key in owner:
                parent[find(idx)] = find(owner[key])
            else:
                owner[key] = idx

    groups: dict[int, list[Alert]] = {}
    for idx, alert in enumerate(alerts):
        groups.setdefault(find(idx), []).append(alert)

    incidents = []
    for members in groups.values():
        members.sort(key=lambda a: a.ts_first)
        tactics = _uniq(a.tactic for a in members)
        top = max(SEVERITY_ORDER[a.severity] for a in members)
        if len(tactics) >= 4:
            top = 4  # a many-stage chain is critical no matter how each step scored
        elif len(tactics) >= 3:
            top = max(top, 3)
        raw = sum(SEV_WEIGHT[a.severity] for a in members) + 10 * (len(tactics) - 1)
        score = round(100 * (1 - math.exp(-raw / 150)))  # saturating: long chains rank above short ones
        title = ("Multi-stage intrusion: " + " > ".join(tactics)) if len(tactics) > 1 else members[0].title
        incidents.append(Incident(
            id="", title=title, severity=[k for k, v in SEVERITY_ORDER.items() if v == top][0], score=score,
            alerts=members, ts_first=members[0].ts_first, ts_last=max(a.ts_last for a in members),
            ips=_uniq(a.entities.get("src_ip", "") for a in members),
            users=_uniq(a.entities.get("user", "") for a in members),
            hosts=_uniq(a.entities.get("host", "") for a in members), tactics=tactics,
            techniques=_uniq(t for a in members for t in a.techniques),
            response=_uniq(r for a in members for r in a.response)))

    incidents.sort(key=lambda i: (-i.score, i.ts_first))
    for n, inc in enumerate(incidents, 1):
        inc.id = f"INC-{n:03d}"
    return incidents
