"""Threat-intelligence lookups. Nothing is fabricated: no key => 'not configured'."""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

import requests

from ..models import IntelResult, Observation
from ..rules import make_finding
from ..utils import clean, ttl_cache
from .base import CheckOutput, ScanContext


class IntelError(Exception):
    pass


@ttl_cache(300)
def _fetch(url: str, headers: tuple) -> tuple[int, dict]:
    """GET JSON. Transient failures raise (and are therefore never cached)."""
    try:
        resp = requests.get(url, headers=dict(headers), timeout=6)
    except requests.RequestException as exc:
        raise IntelError(type(exc).__name__)
    if resp.status_code == 429:
        raise IntelError("rate limited")
    if resp.status_code in (401, 403):
        raise IntelError("API key rejected")
    if resp.status_code >= 500:
        raise IntelError(f"HTTP {resp.status_code}")
    try:
        data = resp.json()
    except ValueError:
        data = {}
    return resp.status_code, data if isinstance(data, dict) else {}


def _geoip(ctx: ScanContext, ip: str) -> CheckOutput:
    status, data = _fetch(f"https://ipwho.is/{quote(ip, safe='')}", ())
    out = CheckOutput()
    if data.get("success"):
        conn = data.get("connection") or {}
        text = f"{data.get('country', '?')} | {conn.get('org') or conn.get('isp') or '?'} | AS{conn.get('asn', '?')}"
        out.observations.append(Observation("geoip", clean(text, 160)))
    return out


def _internetdb(ctx: ScanContext, ip: str) -> CheckOutput:
    status, data = _fetch(f"https://internetdb.shodan.io/{quote(ip, safe='')}", ())
    out = CheckOutput()
    if status == 404:
        out.intel.append(IntelResult("Shodan InternetDB", "ok", "unknown", "no data for this IP"))
        return out
    ports, vulns = data.get("ports") or [], data.get("vulns") or []
    out.intel.append(IntelResult(
        "Shodan InternetDB", "ok", "suspicious" if vulns else "unknown",
        f"ports={len(ports)}, cves={len(vulns)}"))
    if ports:
        out.observations.append(Observation("indexed_ports", ", ".join(map(str, ports[:20]))))
    if data.get("hostnames"):
        out.observations.append(Observation("indexed_hostnames", clean(", ".join(data["hostnames"][:5]), 160)))
    if vulns:
        out.findings.append(make_finding(
            "INTEL-CVE", ctx.target.host, "Shodan-InternetDB",
            {"count": len(vulns), "cves": [clean(v, 24) for v in vulns[:15]], "ip": ip},
            status="Observed", confidence=0.5, key="cve", timestamp=ctx.timestamp,
        ))
    return out


def _abuseipdb(ctx: ScanContext, ip: str) -> CheckOutput:
    key = ctx.api_keys.get("ABUSEIPDB_API_KEY")
    if not key:
        return CheckOutput(intel=[IntelResult("AbuseIPDB", "not_configured")])
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={quote(ip, safe='')}&maxAgeInDays=90"
    _, data = _fetch(url, (("Key", key), ("Accept", "application/json")))
    info = data.get("data") or {}
    score = int(info.get("abuseConfidenceScore", 0))
    verdict = "malicious" if score >= 75 else "suspicious" if score >= 25 else "clean"
    out = CheckOutput(intel=[IntelResult(
        "AbuseIPDB", "ok", verdict,
        f"score={score}%, reports={info.get('totalReports', 0)}, usage={clean(info.get('usageType') or '?', 40)}")])
    if score >= 25:
        out.findings.append(make_finding(
            "INTEL-ABUSE", ctx.target.host, "AbuseIPDB",
            {"score": score, "reports": info.get("totalReports", 0), "ip": ip},
            confidence=0.8, key="abuse", timestamp=ctx.timestamp,
        ))
    return out


def _virustotal(ctx: ScanContext, value: str, kind: str) -> CheckOutput:
    key = ctx.api_keys.get("VIRUSTOTAL_API_KEY")
    if not key:
        return CheckOutput(intel=[IntelResult("VirusTotal", "not_configured")])
    status, data = _fetch(
        f"https://www.virustotal.com/api/v3/{kind}/{quote(value, safe='')}", (("x-apikey", key),))
    if status == 404:
        return CheckOutput(intel=[IntelResult("VirusTotal", "ok", "unknown", "not seen before")])
    stats = ((data.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
    mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
    verdict = "malicious" if mal >= 3 else "suspicious" if (mal or sus) else "clean"
    out = CheckOutput(intel=[IntelResult(
        "VirusTotal", "ok", verdict,
        f"malicious={mal}, suspicious={sus}, harmless={stats.get('harmless', 0)}, undetected={stats.get('undetected', 0)}")])
    if mal or sus:
        out.findings.append(make_finding(
            "INTEL-VT", ctx.target.host, "VirusTotal",
            {"malicious": mal, "suspicious": sus},
            confidence=0.8 if mal >= 3 else 0.5, key="vt", timestamp=ctx.timestamp,
        ))
    return out


def _rdns(ctx: ScanContext, ip: str) -> CheckOutput:
    out = CheckOutput()
    try:
        out.observations.append(Observation("rdns", clean(socket.gethostbyaddr(ip)[0], 120)))
    except OSError:
        pass
    return out


def check_intel(ctx: ScanContext) -> CheckOutput:
    t = ctx.target
    ip = t.ips[0] if t.ips else None
    jobs = []
    if ip:
        jobs += [("GeoIP", lambda: _geoip(ctx, ip)),
                 ("Shodan InternetDB", lambda: _internetdb(ctx, ip)),
                 ("AbuseIPDB", lambda: _abuseipdb(ctx, ip))]
    if t.kind == "ip":
        jobs += [("rDNS", lambda: _rdns(ctx, ip)),
                 ("VirusTotal", lambda: _virustotal(ctx, ip, "ip_addresses"))]
    else:
        jobs += [("VirusTotal", lambda: _virustotal(ctx, t.host, "domains"))]

    def run(job):
        source, fn = job
        try:
            return fn()
        except IntelError as exc:
            return CheckOutput(intel=[IntelResult(source, "error", "unknown", clean(exc, 80))]) if source != "GeoIP" else CheckOutput()
        except Exception as exc:
            return CheckOutput(intel=[IntelResult(source, "error", "unknown", type(exc).__name__)]) if source not in ("GeoIP", "rDNS") else CheckOutput()

    merged = CheckOutput()
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        for part in pool.map(run, jobs):
            merged.findings += part.findings
            merged.observations += part.observations
            merged.intel += part.intel
    if t.kind == "email":
        # Email targets only have domain-level reputation; no IP intel rows.
        merged.intel = [r for r in merged.intel if r.source == "VirusTotal"] or merged.intel
    return merged
