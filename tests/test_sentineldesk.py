from datetime import datetime, timedelta, timezone

import pytest

from sentineldesk.core import analyze
from sentineldesk.models import Event
from sentineldesk.parsers import parse_ssh_line, parse_web_line, parse_windows_line
from sentineldesk.rules import Rule, eval_distinct, eval_sequence, eval_threshold, load_rules, matches
from sentineldesk.samples import generate

T0 = datetime(2026, 11, 17, 9, 0, tzinfo=timezone.utc)


def ev(sec, action="login_failed", user="root", ip="203.0.113.5", **kw):
    return Event(T0 + timedelta(seconds=sec), "ssh", "web01", action, user=user, src_ip=ip, fields=kw)


def rule(**kw):
    base = dict(id="t", title="t", severity="high", tactic="x", techniques=["T1"], type="threshold",
                selection={"action": "login_failed"}, group_by=["src_ip"], count=3, window=60)
    base.update(kw)
    return Rule(**base)


# ---------------------------------------------------------------- parsers
def test_ssh_failed_invalid_user():
    e = parse_ssh_line("Nov 17 09:14:03 web01 sshd[812]: Failed password for invalid user admin from "
                       "203.0.113.50 port 40022 ssh2", 2026)
    assert (e.action, e.user, e.src_ip, e.host) == ("login_failed", "admin", "203.0.113.50", "web01")


def test_ssh_accepted_and_garbage():
    e = parse_ssh_line("Nov  7 01:02:03 h sshd[1]: Accepted publickey for bob from 10.0.0.4 port 22 ssh2", 2026)
    assert e.action == "login_success" and e.user == "bob"
    assert parse_ssh_line("not a log line", 2026) is None


def test_web_line_decodes_url():
    e = parse_web_line('1.2.3.4 - - [17/Nov/2026:08:43:00 +0000] "GET /a?id=1%20UNION%20SELECT%201 HTTP/1.1" '
                       '500 10 "-" "curl/8"')
    assert e.fields["url_decoded"] == "/a?id=1 UNION SELECT 1" and e.fields["status"] == "500"


def test_windows_4625_and_ignored_event():
    line = ('{"TimeCreated":"2026-11-17T10:00:00Z","EventID":4625,"Computer":"DC01",'
            '"EventData":{"TargetUserName":"alice","IpAddress":"198.51.100.7","LogonType":"3"}}')
    e = parse_windows_line(line)
    assert e.action == "login_failed" and e.src_ip == "198.51.100.7"
    assert parse_windows_line('{"TimeCreated":"2026-11-17T10:00:00Z","EventID":9999}') is None
    assert parse_windows_line("{broken") is None


# ---------------------------------------------------------------- matching
def test_matching_operators_are_case_insensitive():
    e = Event(T0, "windows", "h", "process_create", fields={"command_line": "CertUtil.exe -URLCache -f x"})
    assert matches(e, {"command_line|contains": "urlcache"})
    assert matches(e, {"command_line|re": r"certutil\.exe\s+-urlcache"})
    assert matches(e, {"command_line|startswith": ["nope", "certutil"]})
    assert not matches(e, {"action": "login_failed"})


# ---------------------------------------------------------------- evaluators
def test_threshold_fires_once_and_merges_followups():
    alerts = eval_threshold(rule(), [ev(i * 5) for i in range(10)])
    assert len(alerts) == 1 and alerts[0].count == 10


def test_threshold_respects_window():
    assert eval_threshold(rule(window=10), [ev(i * 30) for i in range(10)]) == []


def test_threshold_groups_per_ip():
    events = [ev(i, ip="1.1.1.1") for i in range(2)] + [ev(i, ip="2.2.2.2") for i in range(2)]
    assert eval_threshold(rule(), events) == []


def test_distinct_users_spray():
    events = [ev(i * 10, user=f"user{i}") for i in range(6)]
    assert len(eval_distinct(rule(type="distinct", distinct_field="user", count=6, window=300), events)) == 1
    assert eval_distinct(rule(type="distinct", distinct_field="user", count=7, window=300), events) == []


def test_sequence_needs_enough_failures_before_success():
    r = rule(type="sequence", window=300, first={"count": 3, "selection": {"action": "login_failed"}},
             then={"selection": {"action": "login_success"}})
    good = [ev(i) for i in range(3)] + [ev(10, action="login_success")]
    assert len(eval_sequence(r, good)) == 1
    assert eval_sequence(r, [ev(0), ev(1), ev(10, action="login_success")]) == []


# ---------------------------------------------------------------- rule loading
def test_all_shipped_rules_load_and_have_attack_ids():
    rules = load_rules("rules")
    assert len(rules) >= 14
    assert all(t.startswith("T") for r in rules for t in r.techniques)


def test_rule_with_colon_in_response_is_rejected(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("id: a\ntitle: a\nseverity: high\ntactic: x\ntechniques: [T1]\ntype: match\n"
                   "selection: {action: x}\nresponse:\n  - Do this: then that\n")
    with pytest.raises(ValueError, match="plain string"):
        load_rules(bad)


# ---------------------------------------------------------------- end to end
@pytest.fixture(scope="module")
def result(tmp_path_factory):
    d = tmp_path_factory.mktemp("samples")
    p = generate(d)
    return analyze(ssh=[p["ssh"]], windows=[p["windows"]], web=[p["web"]], year=2026)


def test_expected_detections_fire(result):
    fired = {a.rule_id for a in result.alerts}
    assert {"login-bruteforce", "password-spray", "bruteforce-success", "encoded-powershell", "certutil-download",
            "lolbin-remote-exec", "new-local-user", "admin-group-add", "suspicious-service", "log-cleared",
            "web-sqli", "web-path-traversal", "web-404-flood", "web-scanner-ua"} <= fired


def test_no_alerts_for_internal_benign_traffic(result):
    assert not [a for a in result.alerts if a.entities["src_ip"].startswith(("10.", "192.0.2.1"))]


def test_alerts_are_correlated_into_three_incidents(result):
    assert len(result.incidents) == 3
    rdp = next(i for i in result.incidents if "198.51.100.77" in i.ips)
    assert {a.rule_id for a in rdp.alerts} >= {"password-spray", "bruteforce-success", "log-cleared"}
    assert len(rdp.tactics) >= 6 and rdp.severity == "critical"
    web = next(i for i in result.incidents if "203.0.113.50" in i.ips)
    assert web.tactics[0] == "Reconnaissance"
    assert result.incidents[0].score >= result.incidents[1].score >= result.incidents[2].score


def test_reports_written(result, tmp_path):
    from sentineldesk.report import write_reports
    paths = write_reports(result, tmp_path)
    html = paths["html"].read_text()
    assert "INC-001" in html and "MITRE ATT&amp;CK coverage" in html
    assert all(p.exists() and p.stat().st_size > 0 for p in paths.values())
