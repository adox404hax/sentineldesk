"""Report writers: HTML (analyst-facing), JSON, CSV, ATT&CK Navigator layer."""
from __future__ import annotations

import csv
import json
from collections import Counter, OrderedDict
from html import escape as esc
from pathlib import Path

from . import __version__
from .core import Result
from .models import SEVERITY_ORDER

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--text:#1b1f27;--muted:#5d6675;--line:#e1e5eb;--accent:#2f5fd0;
--critical:#b42318;--high:#d9480f;--medium:#b7791f;--low:#2f7d4f;--chip:#eef1f6}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--card:#1b2029;--text:#e7eaf0;--muted:#9aa4b5;
--line:#2b3340;--accent:#7aa2ff;--critical:#ff6b5e;--high:#ff9248;--medium:#e6b84f;--low:#5fcb8a;--chip:#252c38}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:28px 20px 60px}
h1{font-size:26px;margin:0}h2{font-size:18px;margin:36px 0 12px}h3{font-size:15px;margin:18px 0 6px}
.sub{color:var(--muted);margin:4px 0 22px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
.kpi b{display:block;font-size:28px}.kpi span{color:var(--muted);font-size:13px}
.bars .row{display:flex;align-items:center;gap:10px;margin:6px 0}.bars .lbl{width:70px;color:var(--muted)}
.bars .bar{height:14px;border-radius:7px;min-width:2px}
.badge{display:inline-block;padding:1px 9px;border-radius:99px;font-size:12px;font-weight:600;color:#fff}
.critical{background:var(--critical)}.high{background:var(--high)}.medium{background:var(--medium)}.low{background:var(--low)}
.chip{display:inline-block;background:var(--chip);border-radius:6px;padding:1px 8px;margin:2px 4px 2px 0;font-size:12.5px}
.chip.bad{outline:1px solid var(--critical);color:var(--critical)}.chip.fired{background:var(--accent);color:#fff}
.inc{margin-bottom:18px}.inc header{display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between}
.inc h3{margin:0;font-size:17px}.score{font-weight:700;font-size:20px}
table{width:100%;border-collapse:collapse;font-size:13.5px}th,td{padding:7px 8px;border-bottom:1px solid var(--line);
text-align:left;vertical-align:top}th{color:var(--muted);font-weight:600}
.scroll{overflow-x:auto}pre{background:var(--chip);padding:10px;border-radius:8px;overflow-x:auto;font-size:12px;
white-space:pre-wrap;word-break:break-all}details summary{cursor:pointer;color:var(--accent)}
ul{margin:6px 0 0 18px;padding:0}.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px}
.notes{border:1px dashed var(--line);border-radius:8px;padding:10px;color:var(--muted);margin-top:12px}
footer{color:var(--muted);margin-top:40px;font-size:12.5px}
"""


def _t(ts) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def _sev(s: str) -> str:
    return f'<span class="badge {esc(s)}">{esc(s.upper())}</span>'


def _ip_chip(ip: str, enrich: dict) -> str:
    info = enrich.get(ip, {})
    verdict = info.get("verdict", "unknown")
    cls = "bad" if verdict in ("known-bad", "suspicious") else ""
    extra = f" ({verdict})" if verdict != "unknown" else ""
    return f'<span class="chip {cls} mono">{esc(ip)}{esc(extra)}</span>'


def render_html(res: Result) -> str:
    s = res.stats
    sev = Counter(a.severity for a in res.alerts)
    top = max(sev.values()) if sev else 1
    fired_rules = {a.rule_id for a in res.alerts}
    bars = "".join(
        f'<div class="row"><span class="lbl">{k}</span><div class="bar {k}" style="width:{max(2, 100 * sev.get(k, 0) // top)}%"></div>'
        f"<span>{sev.get(k, 0)}</span></div>" for k in ("critical", "high", "medium", "low"))

    inc_html = []
    for inc in res.incidents:
        rows = "".join(
            f"<tr><td class='mono'>{_t(a.ts_first)}</td><td>{_sev(a.severity)}</td><td>{esc(a.title)}</td>"
            f"<td>{esc(a.tactic)}<br><span class='mono'>{esc(', '.join(a.techniques))}</span></td>"
            f"<td>{a.count}</td><td class='mono'>{esc(a.entities.get('src_ip') or '-')}<br>"
            f"{esc(a.entities.get('user') or '-')} @ {esc(a.entities.get('host') or '-')}</td>"
            f"<td><details><summary>evidence</summary><pre>{esc(chr(10).join(e.raw for e in a.evidence))}</pre></details></td></tr>"
            for a in inc.alerts)
        actions = "".join(f"<li>{esc(r)}</li>" for r in inc.response)
        inc_html.append(f"""<section class="card inc"><header><div><h3>{esc(inc.id)} - {esc(inc.title)}</h3>
<span class="sub">{_t(inc.ts_first)} to {_t(inc.ts_last)} UTC - {len(inc.alerts)} alerts</span></div>
<div>{_sev(inc.severity)} <span class="score">{inc.score}</span><span class="sub">/100</span></div></header>
<div><b>Source IPs</b> {''.join(_ip_chip(i, res.enrichment) for i in inc.ips) or '-'}
&nbsp; <b>Users</b> {''.join(f'<span class="chip">{esc(u)}</span>' for u in inc.users) or '-'}
&nbsp; <b>Hosts</b> {''.join(f'<span class="chip">{esc(h)}</span>' for h in inc.hosts) or '-'}</div>
<div><b>Attack path</b> {' &rarr; '.join(f'<span class="chip">{esc(t)}</span>' for t in inc.tactics)}</div>
<h3>Timeline</h3><div class="scroll"><table><tr><th>Time (UTC)</th><th>Severity</th><th>Detection</th><th>ATT&amp;CK</th>
<th>Events</th><th>Entities</th><th></th></tr>{rows}</table></div>
<h3>Recommended response</h3><ul>{actions}</ul>
<div class="notes">Analyst verdict: &#9744; True positive &nbsp; &#9744; False positive &nbsp; &#9744; Benign &nbsp;|&nbsp; Notes: ________________</div>
</section>""")

    alert_rows = "".join(
        f"<tr><td class='mono'>{_t(a.ts_first)}</td><td>{_sev(a.severity)}</td><td>{esc(a.title)}</td>"
        f"<td class='mono'>{esc(a.rule_id)}</td><td>{a.count}</td>"
        f"<td class='mono'>{esc(a.entities.get('src_ip') or a.entities.get('host') or '-')}</td></tr>"
        for a in res.alerts)

    by_tactic: "OrderedDict[str, list]" = OrderedDict()
    for r in res.rules:
        by_tactic.setdefault(r.tactic, []).append(r)
    cov = "".join(
        f"<tr><td>{esc(t)}</td><td>" + "".join(
            f'<span class="chip {"fired" if r.id in fired_rules else ""}">{esc(r.id)} '
            f'<span class="mono">{esc(",".join(r.techniques))}</span></span>' for r in rs) + "</td></tr>"
        for t, rs in by_tactic.items())

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>SentinelDesk Incident Report</title>
<style>{CSS}</style></head><body><div class="wrap">
<h1>SentinelDesk incident report</h1>
<p class="sub">Telemetry window {esc(s['first_event'][:19])} to {esc(s['last_event'][:19])} UTC -
{s['events']:,} events from {esc(', '.join(f'{k} ({v:,})' for k, v in s['by_source'].items()))}</p>
<div class="kpis"><div class="card kpi"><b>{s['events']:,}</b><span>events analysed</span></div>
<div class="card kpi"><b>{s['alerts']}</b><span>alerts</span></div>
<div class="card kpi"><b>{s['incidents']}</b><span>incidents</span></div>
<div class="card kpi"><b>{res.incidents[0].score if res.incidents else 0}</b><span>top risk score</span></div>
<div class="card kpi"><b>{s['rules_loaded']}</b><span>detection rules</span></div></div>
<h2>Alerts by severity</h2><div class="card bars">{bars}</div>
<h2>Incidents (highest risk first)</h2>{''.join(inc_html) or '<div class="card">No incidents detected.</div>'}
<h2>All alerts</h2><div class="card scroll"><table><tr><th>First seen</th><th>Severity</th><th>Detection</th>
<th>Rule</th><th>Events</th><th>Entity</th></tr>{alert_rows}</table></div>
<h2>MITRE ATT&amp;CK coverage</h2><div class="card scroll"><table><tr><th>Tactic</th><th>Rules (highlighted = fired)</th></tr>{cov}</table></div>
<footer>Generated by SentinelDesk {__version__}. Detections are leads for an analyst to validate, not verdicts.</footer>
</div></body></html>"""


def navigator_layer(res: Result) -> dict:
    fired = Counter(t for a in res.alerts for t in a.techniques)
    covered = {t for r in res.rules for t in r.techniques}
    return {"name": "SentinelDesk coverage", "domain": "enterprise-attack",
            "versions": {"attack": "15", "navigator": "5.1.0", "layer": "4.5"},
            "description": "Blue = covered by a rule. Orange = fired in this analysis run.",
            "gradient": {"colors": ["#ffffff", "#8ec1ff", "#ff9248"], "minValue": 0, "maxValue": 2},
            "techniques": [{"techniqueID": t, "score": 2 if fired.get(t) else 1,
                            "comment": f"{fired.get(t, 0)} alert(s) in this run"} for t in sorted(covered)]}


def write_reports(res: Result, out_dir: str | Path) -> dict[str, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths = {k: out / v for k, v in {"html": "report.html", "alerts_json": "alerts.json",
                                      "incidents_json": "incidents.json", "csv": "alerts.csv",
                                      "navigator": "attack_navigator_layer.json"}.items()}
    paths["html"].write_text(render_html(res), encoding="utf-8")
    paths["alerts_json"].write_text(json.dumps([a.to_dict() for a in res.alerts], indent=2), encoding="utf-8")
    paths["incidents_json"].write_text(json.dumps([i.to_dict() for i in res.incidents], indent=2), encoding="utf-8")
    paths["navigator"].write_text(json.dumps(navigator_layer(res), indent=2), encoding="utf-8")
    with open(paths["csv"], "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["first_seen", "last_seen", "severity", "rule_id", "title", "tactic", "techniques",
                    "events", "src_ip", "user", "host"])
        for a in sorted(res.alerts, key=lambda a: (-SEVERITY_ORDER[a.severity], a.ts_first)):
            w.writerow([a.ts_first.isoformat(), a.ts_last.isoformat(), a.severity, a.rule_id, a.title, a.tactic,
                        ";".join(a.techniques), a.count, a.entities.get("src_ip", ""),
                        a.entities.get("user", ""), a.entities.get("host", "")])
    return paths
