"""IP enrichment: internal-vs-external, local blocklists, optional AbuseIPDB.

Works fully offline. Set --abuseipdb and the ABUSEIPDB_KEY environment variable
to add live reputation scores.
"""
from __future__ import annotations

import ipaddress
import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterable, Optional

INTERNAL = [ipaddress.ip_network(n) for n in
            ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "::1/128")]


class Enricher:
    def __init__(self, blocklists: Iterable[str] = (), abuseipdb_key: Optional[str] = None, timeout: int = 5):
        self.nets: list = []
        self.key = abuseipdb_key
        self.timeout = timeout
        self._cache: dict[str, dict] = {}
        for bl in blocklists:
            self._load_blocklist(Path(bl))

    def _load_blocklist(self, path: Path) -> None:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                try:
                    self.nets.append(ipaddress.ip_network(line, strict=False))
                except ValueError:
                    continue

    def lookup(self, ip: str) -> dict:
        if ip in self._cache:
            return self._cache[ip]
        info = {"ip": ip, "scope": "unknown", "blocklisted": False, "abuse_score": None,
                "country": "", "isp": "", "verdict": "unknown"}
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            self._cache[ip] = info
            return info
        info["scope"] = "internal" if any(addr in n for n in INTERNAL) else "external"
        info["blocklisted"] = any(addr in n for n in self.nets)
        if info["scope"] == "external" and self.key:
            info.update(self._abuseipdb(ip))
        if info["scope"] == "internal":
            info["verdict"] = "internal"
        elif info["blocklisted"] or (info["abuse_score"] or 0) >= 75:
            info["verdict"] = "known-bad"
        elif (info["abuse_score"] or 0) >= 25:
            info["verdict"] = "suspicious"
        self._cache[ip] = info
        return info

    def _abuseipdb(self, ip: str) -> dict:
        req = urllib.request.Request(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
            headers={"Key": self.key or "", "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                d = json.load(resp)["data"]
            return {"abuse_score": d.get("abuseConfidenceScore"), "country": d.get("countryCode") or "",
                    "isp": d.get("isp") or ""}
        except (urllib.error.URLError, TimeoutError, KeyError, ValueError):
            return {}


def from_env(blocklists: Iterable[str] = (), use_abuseipdb: bool = False) -> Enricher:
    return Enricher(blocklists, os.environ.get("ABUSEIPDB_KEY") if use_abuseipdb else None)
