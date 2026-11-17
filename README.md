# SentinelDesk

**A small, readable SOC detection and triage pipeline.** It ingests SSH, Windows and web server logs, runs
ATT&CK-mapped detection rules, correlates the alerts into **incidents** with a timeline and risk score, and writes an
analyst-ready HTML report. The only dependency is PyYAML.

It is built to show the core SOC loop end to end: **collect -> normalise -> detect -> correlate -> enrich -> triage -> report**.

```
 auth.log ─┐                                        ┌─> report.html (incidents, timeline, evidence)
 Windows   ├─> parsers ─> Event ─> rule engine ─> Alert ─> correlation ─> Incident ─┼─> alerts.csv / .json
 access.log┘   (normalise)          (YAML rules)         (shared IP / user@host)    └─> ATT&CK Navigator layer
                                          ▲                        ▲
                                   14 Sigma-style rules     IP enrichment (offline blocklists,
                                   mapped to MITRE ATT&CK   optional AbuseIPDB)
```

## Quick start

```bash
pip install -r requirements.txt
python -m sentineldesk generate-samples            # benign noise + 3 embedded attacks
python -m sentineldesk analyze \
    --ssh samples/auth.log --windows samples/windows_security.jsonl --web samples/access.log \
    --year 2026 --out out
open out/report.html                               # or xdg-open / start
```

Expected result on the samples: `572 events -> 16 alerts -> 3 incidents`.

| Incident | What actually happened | Detections that fired |
|---|---|---|
| INC-001 (score 91) | Password spray on an RDP server, successful login as `svc_backup`, then encoded PowerShell, certutil download, new admin user, rogue service, log cleared | spray, bruteforce-success, encoded-powershell, certutil-download, lolbin-remote-exec, new-local-user, admin-group-add, suspicious-service, log-cleared |
| INC-002 (score 72) | Nikto scan and SQLi/traversal against the web server, then SSH brute force that succeeds | web-scanner-ua, web-404-flood, web-sqli, web-path-traversal, login-bruteforce, bruteforce-success |
| INC-003 (score 10) | One lone `sqlmap` probe, correctly kept as low priority | web-scanner-ua |

`examples/` contains the generated report so you can see the output without running anything.

## Analyse your own logs

| Flag | Input |
|---|---|
| `--ssh` | OpenSSH `auth.log` / `/var/log/secure` |
| `--windows` | Windows events exported as JSON lines (4624, 4625, 4688, 4720, 4732, 7045, 1102, Sysmon 1) |
| `--web` | Apache / Nginx combined access logs |
| `--blocklist` | text files of bad IPs or CIDRs (feeds incident enrichment) |
| `--abuseipdb` | live reputation, needs `ABUSEIPDB_KEY` in the environment |
| `--fail-on high` | exit code 2 if an incident reaches that severity (handy in CI or cron) |

Windows logs need one JSON object per line with `TimeCreated`, `EventID`, `Computer` and `EventData`. The exact
fields the parser reads are in [docs/windows-fields.md](docs/windows-fields.md).

## Writing a detection

Rules are YAML and need no code. Four types: `match`, `threshold`, `distinct`, `sequence`.

```yaml
id: login-bruteforce
title: Brute-force login attempts
severity: high
tactic: Credential Access
techniques: [T1110.001]
type: threshold
selection:                 # field|operator: value   (eq, contains, startswith, endswith, re; list = OR)
  action: login_failed
group_by: src_ip
count: 10
window: 120                # seconds
response:
  - Block the source IP at the firewall or WAF.
```

Run `python -m sentineldesk rules` to list everything loaded. Bad rules fail fast with a clear error.

## Detections

| Rule | Type | ATT&CK |
|---|---|---|
| login-bruteforce | threshold | T1110.001 |
| password-spray | distinct | T1110.003 |
| bruteforce-success | sequence | T1078, T1110 |
| encoded-powershell | match | T1059.001, T1027 |
| certutil-download | match | T1105 |
| lolbin-remote-exec | match | T1218.005 / .010 / .011 |
| new-local-user | match | T1136.001 |
| admin-group-add | match | T1098 |
| suspicious-service | match | T1543.003 |
| log-cleared | match | T1070.001 |
| web-scanner-ua | match | T1595.002 |
| web-404-flood | threshold | T1595.003 |
| web-sqli | match | T1190 |
| web-path-traversal | match | T1190 |

`out/attack_navigator_layer.json` can be loaded into the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
to show coverage (blue) and what fired in the run (orange).

## Design notes (good interview material)

* **Alert fatigue**: repeated hits for the same entity merge into one alert instead of thousands.
* **Correlation**: alerts sharing a source IP, or the same user on the same host, become one incident. That is how a
  spray, a login and post-exploitation end up as a single story.
* **Risk scoring**: severity weights plus a bonus for each extra ATT&CK tactic, with a saturating curve so longer
  chains outrank shorter ones.
* **False-positive discipline**: the sample data includes benign failed logins and normal traffic, and a test asserts
  they never alert.
* **Known limits**: batch analysis only (no streaming), log-time ordering assumed, thresholds are static. Natural next
  steps: baseline-driven thresholds, GeoIP/impossible travel, Sigma rule import, a Slack/Telegram notifier.

## Playbooks

`docs/playbooks/` has triage steps for the two incident patterns in the samples:
[credential attack](docs/playbooks/credential-attack.md) and [post-compromise activity](docs/playbooks/post-compromise.md).

## Tests

```bash
pip install pytest && pytest -q       # 16 tests: parsers, operators, each rule type, end-to-end incidents
```

## Safety

All sample addresses use RFC 5737 documentation ranges and `example.net`. SentinelDesk only reads logs and never
touches the systems it reports on. Detections are leads for an analyst to validate, not verdicts.

MIT licensed.
