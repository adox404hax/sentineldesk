"""Parsers: raw log lines -> normalised Event objects.

Supported inputs
  * Linux OpenSSH auth.log / secure  (syslog format)
  * Windows event logs exported as JSON lines (Security, System, Sysmon)
  * Apache / Nginx "combined" access logs
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import unquote_plus

from .models import Event

IP = r"[0-9a-fA-F:.]+"

SSH_LINE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<msg>.*)$")
SSH_FAILED = re.compile(rf"Failed (?P<method>[\w-]+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>{IP}) port \d+")
SSH_ACCEPT = re.compile(rf"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>{IP}) port \d+")

WEB_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<url>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?')


def parse_ssh_line(line: str, year: int) -> Optional[Event]:
    m = SSH_LINE.match(line.strip())
    if not m:
        return None
    try:
        ts = datetime.strptime(f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S").replace(
            tzinfo=timezone.utc)
    except ValueError:
        return None
    msg = m["msg"]
    for regex, action in ((SSH_FAILED, "login_failed"), (SSH_ACCEPT, "login_success")):
        hit = regex.search(msg)
        if hit:
            return Event(ts, "ssh", m["host"], action, user=hit["user"], src_ip=hit["ip"],
                         fields={"method": hit["method"]}, raw=line.rstrip("\n"))
    return None


def parse_web_line(line: str, host: str = "web01") -> Optional[Event]:
    m = WEB_LINE.match(line.strip())
    if not m:
        return None
    try:
        ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None
    user = "" if m["user"] == "-" else m["user"]
    return Event(ts, "web", host, "http_request", user=user, src_ip=m["ip"], raw=line.rstrip("\n"), fields={
        "method": m["method"], "url": m["url"], "url_decoded": unquote_plus(m["url"]),
        "status": m["status"], "user_agent": m["ua"] or ""})


def _clean_ip(value: Optional[str]) -> str:
    value = (value or "").strip()
    return "" if value in {"-", "::1", "127.0.0.1", "::", "0.0.0.0"} else value


def parse_windows_line(line: str) -> Optional[Event]:
    line = line.strip()
    if not line:
        return None
    try:
        rec = json.loads(line)
        eid = int(rec["EventID"])
        ts = datetime.fromisoformat(str(rec["TimeCreated"]).replace("Z", "+00:00"))
    except (ValueError, KeyError, TypeError):
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    d = rec.get("EventData") or {}
    host = rec.get("Computer", "")
    common = dict(host=host, raw=line)

    if eid in (4624, 4625):
        return Event(ts, "windows", action="login_success" if eid == 4624 else "login_failed",
                     user=d.get("TargetUserName", ""), src_ip=_clean_ip(d.get("IpAddress")),
                     fields={"logon_type": str(d.get("LogonType", ""))}, **common)
    if eid in (4688, 1):  # Security process creation / Sysmon process create
        return Event(ts, "windows", action="process_create",
                     user=d.get("SubjectUserName") or d.get("User", ""),
                     fields={"process": d.get("NewProcessName") or d.get("Image", ""),
                             "command_line": d.get("CommandLine", ""),
                             "parent_process": d.get("ParentProcessName") or d.get("ParentImage", "")}, **common)
    if eid == 4720:
        return Event(ts, "windows", action="user_created", user=d.get("SubjectUserName", ""),
                     fields={"target_user": d.get("TargetUserName", "")}, **common)
    if eid in (4728, 4732, 4756):
        return Event(ts, "windows", action="group_member_added", user=d.get("SubjectUserName", ""),
                     fields={"group": d.get("TargetUserName", ""), "member": d.get("MemberName", "")}, **common)
    if eid == 7045:
        return Event(ts, "windows", action="service_installed", user=d.get("SubjectUserName", ""),
                     fields={"service_name": d.get("ServiceName", ""), "image_path": d.get("ImagePath", "")}, **common)
    if eid == 1102:
        return Event(ts, "windows", action="log_cleared", user=d.get("SubjectUserName", ""), **common)
    return None


def load_file(kind: str, path: str | Path, year: Optional[int] = None, web_host: str = "web01"):
    """Parse a whole file. Returns (events, skipped_line_count)."""
    year = year or datetime.now(timezone.utc).year
    events: list[Event] = []
    skipped = 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line.strip():
                continue
            if kind == "ssh":
                ev = parse_ssh_line(line, year)
            elif kind == "windows":
                ev = parse_windows_line(line)
            elif kind == "web":
                ev = parse_web_line(line, web_host)
            else:
                raise ValueError(f"unknown log kind: {kind}")
            if ev is None:
                skipped += 1
            else:
                events.append(ev)
    return events, skipped
