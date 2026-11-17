"""Command line interface."""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .core import DEFAULT_RULES, analyze
from .enrich import from_env
from .models import SEVERITY_ORDER
from .report import write_reports
from .rules import load_rules
from .samples import generate


def _cmd_analyze(a) -> int:
    res = analyze(a.ssh, a.windows, a.web, rules_dir=a.rules, year=a.year, web_host=a.web_host,
                  enricher=from_env(a.blocklist, a.abuseipdb))
    paths = write_reports(res, a.out)
    s = res.stats
    print(f"SentinelDesk {__version__}: {s['events']:,} events -> {s['alerts']} alerts -> {s['incidents']} incidents")
    for inc in res.incidents:
        print(f"  {inc.id}  [{inc.severity.upper():8}] score {inc.score:3}  {inc.title}")
    print(f"\nReport: {paths['html']}")
    if a.fail_on and any(SEVERITY_ORDER[i.severity] >= SEVERITY_ORDER[a.fail_on] for i in res.incidents):
        return 2
    return 0


def _cmd_rules(a) -> int:
    for r in load_rules(a.rules):
        print(f"{r.id:22} {r.severity:9} {r.tactic:22} {','.join(r.techniques):28} {r.type}")
    return 0


def _cmd_samples(a) -> int:
    for kind, path in generate(a.out, a.seed).items():
        print(f"wrote {kind:8} {path}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="sentineldesk", description="Small SOC detection and triage pipeline.")
    sub = p.add_subparsers(dest="cmd", required=True)

    an = sub.add_parser("analyze", help="parse logs, run detections, write reports")
    an.add_argument("--ssh", nargs="*", default=[], help="OpenSSH auth.log files")
    an.add_argument("--windows", nargs="*", default=[], help="Windows events as JSON lines")
    an.add_argument("--web", nargs="*", default=[], help="Apache/Nginx combined access logs")
    an.add_argument("--rules", default=str(DEFAULT_RULES), help="rules directory")
    an.add_argument("--out", default="out", help="output directory")
    an.add_argument("--year", type=int, help="year for syslog timestamps (default: current)")
    an.add_argument("--web-host", default="web01", help="hostname to attach to web events")
    an.add_argument("--blocklist", nargs="*", default=[], help="text files of bad IPs/CIDRs")
    an.add_argument("--abuseipdb", action="store_true", help="query AbuseIPDB (needs ABUSEIPDB_KEY)")
    an.add_argument("--fail-on", choices=list(SEVERITY_ORDER), help="exit 2 if an incident reaches this severity")
    an.set_defaults(func=_cmd_analyze)

    ru = sub.add_parser("rules", help="list loaded detection rules")
    ru.add_argument("--rules", default=str(DEFAULT_RULES))
    ru.set_defaults(func=_cmd_rules)

    sm = sub.add_parser("generate-samples", help="write sample logs with embedded attacks")
    sm.add_argument("--out", default="samples")
    sm.add_argument("--seed", type=int, default=7)
    sm.set_defaults(func=_cmd_samples)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
