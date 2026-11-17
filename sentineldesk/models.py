"""Core data structures: normalised Events, Alerts."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_CORE = ("ts", "source", "host", "action", "user", "src_ip")


@dataclass
class Event:
    """One log record, normalised so rules do not care where it came from."""

    ts: datetime
    source: str  # ssh | windows | web
    host: str
    action: str  # login_failed, login_success, process_create, http_request, ...
    user: str = ""
    src_ip: str = ""
    fields: dict[str, Any] = field(default_factory=dict)
    raw: str = ""

    def get(self, name: str, default: Any = "") -> Any:
        if name in _CORE:
            return getattr(self, name)
        return self.fields.get(name, default)


@dataclass
class Alert:
    """A rule hit. Repeated hits for the same entity are merged into one alert."""

    rule_id: str
    title: str
    severity: str
    tactic: str
    techniques: list[str]
    description: str
    response: list[str]
    events: list[Event]
    group: str = ""
    keep_user: bool = True  # False for many-account alerts, where 'last user tried' is meaningless
    ts_first: datetime = None  # type: ignore[assignment]
    ts_last: datetime = None  # type: ignore[assignment]
    entities: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.ts_first = self.events[0].ts
        self.ts_last = self.events[-1].ts
        self._refresh_entities()

    @property
    def count(self) -> int:
        return len(self.events)

    @property
    def evidence(self) -> list[Event]:
        """First 3 and last 7 events - enough context without flooding a report."""
        if len(self.events) <= 10:
            return list(self.events)
        return self.events[:3] + self.events[-7:]

    def extend(self, event: Event) -> None:
        self.events.append(event)
        self.ts_last = event.ts
        self._refresh_entities()

    def _refresh_entities(self) -> None:
        last = self.events[-1]
        user = last.user if self.keep_user and last.user not in ("-", "") else ""
        self.entities = {"src_ip": last.src_ip, "user": user, "host": last.host}

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "tactic": self.tactic,
            "techniques": self.techniques,
            "first_seen": self.ts_first.isoformat(),
            "last_seen": self.ts_last.isoformat(),
            "count": self.count,
            "entities": self.entities,
            "description": self.description,
            "response": self.response,
            "evidence": [e.raw for e in self.evidence],
        }
