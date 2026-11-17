"""Pipeline: parse -> detect -> correlate -> enrich."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from .correlate import Incident, build_incidents
from .enrich import Enricher
from .models import Alert, Event
from .parsers import load_file
from .rules import Rule, load_rules, run_rules

DEFAULT_RULES = Path(__file__).resolve().parent.parent / "rules"


@dataclass
class Result:
    events: list[Event]
    skipped: dict[str, int]
    rules: list[Rule]
    alerts: list[Alert]
    incidents: list[Incident]
    enrichment: dict[str, dict] = field(default_factory=dict)

    @property
    def stats(self) -> dict:
        by_source = Counter(e.source for e in self.events)
        times = [e.ts for e in self.events]
        return {"events": len(self.events), "by_source": dict(by_source), "skipped": self.skipped,
                "first_event": min(times).isoformat() if times else "",
                "last_event": max(times).isoformat() if times else "",
                "alerts": len(self.alerts), "incidents": len(self.incidents), "rules_loaded": len(self.rules)}


def analyze(ssh: Iterable[str] = (), windows: Iterable[str] = (), web: Iterable[str] = (),
            rules_dir: str | Path = DEFAULT_RULES, year: Optional[int] = None, web_host: str = "web01",
            enricher: Optional[Enricher] = None) -> Result:
    events: list[Event] = []
    skipped: dict[str, int] = {}
    for kind, paths in (("ssh", ssh), ("windows", windows), ("web", web)):
        for path in paths:
            evs, skip = load_file(kind, path, year=year, web_host=web_host)
            events.extend(evs)
            skipped[kind] = skipped.get(kind, 0) + skip
    rules = load_rules(rules_dir)
    alerts = run_rules(rules, events)
    incidents = build_incidents(alerts)
    enricher = enricher or Enricher()
    ips = {ip for inc in incidents for ip in inc.ips}
    return Result(events, skipped, rules, alerts, incidents, {ip: enricher.lookup(ip) for ip in sorted(ips)})
