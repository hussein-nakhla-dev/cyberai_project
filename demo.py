"""Fictitious sample scan used for UI preview and report testing."""
from __future__ import annotations

import hashlib

from .models import CheckStatus, IntelResult, Observation, ScanResult, Target
from .rules import make_finding
from .scoring import compute_risk
from .utils import now_utc


def sample_result() -> ScanResult:
    host = "demo.example"
    t = Target(raw=host, kind="url", host=host, scheme="https", ips=("203.0.113.10",))
    ts = now_utc().isoformat(timespec="seconds")
    mk = lambda rid, ev, **kw: make_finding(rid, host, kw.pop("scanner", "Demo"), ev, timestamp=ts, **kw)
    findings = [
        mk("EXPOSE-ENV", {"path": "/.env", "variable_names": ["APP_KEY", "DB_PASSWORD", "MAIL_HOST"], "values": "[REDACTED]"},
           scanner="Exposure-Prober", confidence=0.98, key="/.env"),
        mk("PORT-RISKY", {"port": 3306, "service": "MySQL", "ip": "203.0.113.10"},
           scanner="Port-Checker", status="Observed", confidence=0.75, key="3306"),
        mk("TLS-EXPIRING", {"days_remaining": 12}, scanner="TLS-Inspector", confidence=1.0, key="expiring"),
        mk("HDR-CSP", {"missing_header": "content-security-policy", "http_status": 200}, scanner="HTTP-Header-Analyzer", key="csp"),
        mk("HDR-HSTS", {"missing_header": "strict-transport-security", "http_status": 200}, scanner="HTTP-Header-Analyzer", key="hsts"),
        mk("COOKIE-FLAGS", {"cookies": [{"cookie": "sessionid", "missing": ["HttpOnly", "SameSite"]}]},
           scanner="Cookie-Analyzer", status="Observed", confidence=0.6, key="cookies"),
        mk("INFO-BANNER", {"header": "server", "value": "Apache/2.4.41 (Ubuntu)"}, scanner="HTTP-Header-Analyzer", key="server"),
        mk("DNS-DMARC-WEAK", {"record": "v=DMARC1; p=none; rua=mailto:dmarc@demo.example"}, scanner="DNS-Analyzer", key="dmarc"),
        mk("HDR-PERMISSIONS", {"missing_header": "permissions-policy", "http_status": 200}, scanner="HTTP-Header-Analyzer", key="pp"),
    ]
    findings.sort(key=lambda f: (-f.cvss_score, f.rule_id))
    checks = [CheckStatus("http", "ok"), CheckStatus("exposure", "ok"), CheckStatus("tls", "ok"),
              CheckStatus("dns_email", "ok"), CheckStatus("ports", "ok"), CheckStatus("intel", "ok")]
    obs = [
        Observation("http_status", "200"), Observation("final_url", "https://demo.example/"),
        Observation("server", "Apache/2.4.41 (Ubuntu)"), Observation("tls_version", "TLSv1.3"),
        Observation("cert_issuer", "Demo CA"), Observation("cert_expiry", "2026-11-26 (12d)"),
        Observation("open_ports", "80/HTTP, 443/HTTPS, 3306/MySQL"),
    ]
    intel = [IntelResult("Shodan InternetDB", "ok", "unknown", "ports=3, cves=0"),
             IntelResult("AbuseIPDB", "not_configured"), IntelResult("VirusTotal", "not_configured")]
    digest = hashlib.sha256(b"evas-demo").hexdigest()
    return ScanResult(
        target=t, started_at=ts, finished_at=ts, options={"demo": True, "active": True, "port_scan": True},
        findings=findings, observations=obs, checks=checks, intel=intel,
        risk=compute_risk(findings, checks), report_id="EVAS-DEMO-SAMPLE", digest=digest,
    )
