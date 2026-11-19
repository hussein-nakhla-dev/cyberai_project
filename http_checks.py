"""HTTP checks: security headers, cookies, banners, HTTPS redirect, exposed files."""
from __future__ import annotations

import re

import requests

from ..models import Observation
from ..rules import make_finding
from ..security import HttpResult, safe_request
from ..utils import clean
from .base import CheckOutput, ScanContext

# (rule id, header, only meaningful over HTTPS)
HEADER_RULES = (
    ("HDR-HSTS", "strict-transport-security", True),
    ("HDR-CSP", "content-security-policy", False),
    ("HDR-XCTO", "x-content-type-options", False),
    ("HDR-XFO", "x-frame-options", False),
    ("HDR-REFERRER", "referrer-policy", False),
    ("HDR-PERMISSIONS", "permissions-policy", False),
)
BANNER_HEADERS = ("server", "x-powered-by", "x-aspnet-version")
_VERSION = re.compile(r"\d+\.\d+")
_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")


def _get(url: str, **kw) -> HttpResult:
    try:
        return safe_request(url, **kw)
    except requests.exceptions.SSLError:
        # Certificate problems are reported by the TLS check; keep going here.
        return safe_request(url, verify=False, **kw)


def _cookie_issues(set_cookies: list[str], https: bool) -> list[dict]:
    issues = []
    for raw in set_cookies:
        parts = [p.strip() for p in raw.split(";")]
        name = clean(parts[0].split("=", 1)[0], 60)   # never record the value
        flags = {p.split("=", 1)[0].strip().lower() for p in parts[1:]}
        missing = []
        if https and "secure" not in flags:
            missing.append("Secure")
        if "httponly" not in flags:
            missing.append("HttpOnly")
        if "samesite" not in flags:
            missing.append("SameSite")
        if missing:
            issues.append({"cookie": name, "missing": missing})
    return issues


def check_http(ctx: ScanContext) -> CheckOutput:
    t, out = ctx.target, CheckOutput()
    res = _get(t.url)
    final_https = res.url.lower().startswith("https://")

    out.observations.append(Observation("http_status", str(res.status)))
    out.observations.append(Observation("final_url", clean(res.url, 200)))
    if len(res.chain) > 1:
        out.observations.append(Observation("redirects", " > ".join(clean(u, 80) for u in res.chain)))

    headers = res.headers
    if headers.get("server"):
        out.observations.append(Observation("server", clean(headers["server"], 120)))

    if res.status < 500:
        for rule_id, header, https_only in HEADER_RULES:
            if https_only and not final_https:
                continue
            if header in headers:
                continue
            if header == "x-frame-options" and "frame-ancestors" in headers.get("content-security-policy", "").lower():
                continue
            out.findings.append(make_finding(
                rule_id, t.host, "HTTP-Header-Analyzer",
                {"missing_header": header, "http_status": res.status},
                confidence=0.9, key=header, timestamp=ctx.timestamp,
            ))

    for name in BANNER_HEADERS:
        value = headers.get(name)
        if value and _VERSION.search(value):
            out.findings.append(make_finding(
                "INFO-BANNER", t.host, "HTTP-Header-Analyzer",
                {"header": name, "value": clean(value, 120)},
                confidence=0.95, key=name, timestamp=ctx.timestamp,
            ))

    issues = _cookie_issues(res.set_cookies, final_https)
    if issues:
        out.findings.append(make_finding(
            "COOKIE-FLAGS", t.host, "Cookie-Analyzer", {"cookies": issues[:10]},
            status="Observed", confidence=0.6, key="cookies", timestamp=ctx.timestamp,
        ))

    if t.port is None:  # only test the default HTTP port for a plain target
        try:
            plain = safe_request(f"http://{t.host}/", follow=False, timeout=4)
            location = plain.headers.get("location", "").lower()
            if plain.status in (301, 302, 303, 307, 308) and location.startswith("https://"):
                out.observations.append(Observation("https_redirect", "yes"))
            elif plain.status < 400:
                out.observations.append(Observation("https_redirect", "no"))
                out.findings.append(make_finding(
                    "TRANSPORT-NOHTTPS", t.host, "Transport-Analyzer",
                    {"http_status": plain.status}, confidence=0.9, key="http",
                    timestamp=ctx.timestamp,
                ))
        except Exception:
            out.observations.append(Observation("https_redirect", "n/a"))
    return out


def _looks_like_env(body: bytes) -> list[str]:
    lines = [l for l in body.decode("utf-8", "ignore").splitlines() if l.strip() and not l.lstrip().startswith("#")]
    keys = [m.group(1) for l in lines if (m := _ENV_LINE.match(l))]
    return keys if keys and len(keys) >= 0.6 * len(lines) else []


def _looks_like_git(body: bytes) -> bool:
    text = body.decode("utf-8", "ignore").strip()
    return text.startswith("ref: refs/") or bool(re.fullmatch(r"[0-9a-f]{40}", text))


def check_exposure(ctx: ScanContext) -> CheckOutput:
    if not ctx.active:
        return CheckOutput(status="skipped", detail="active probes disabled")
    t, out = ctx.target, CheckOutput()
    errors = 0
    for path, rule_id in (("/.env", "EXPOSE-ENV"), ("/.git/HEAD", "EXPOSE-GIT")):
        try:
            res = _get(f"{t.origin}{path}", follow=False, max_bytes=2048, timeout=4)
        except Exception:
            errors += 1
            continue
        if res.status != 200 or "html" in res.headers.get("content-type", "").lower():
            continue
        if rule_id == "EXPOSE-ENV":
            keys = _looks_like_env(res.body)
            if keys:   # evidence lists variable NAMES only; values are never stored
                out.findings.append(make_finding(
                    rule_id, t.host, "Exposure-Prober",
                    {"path": path, "variable_names": keys[:8], "values": "[REDACTED]"},
                    confidence=0.98, key=path, timestamp=ctx.timestamp,
                ))
        elif _looks_like_git(res.body):
            out.findings.append(make_finding(
                rule_id, t.host, "Exposure-Prober", {"path": path},
                confidence=0.98, key=path, timestamp=ctx.timestamp,
            ))
    if errors == 2:
        raise RuntimeError("target unreachable for exposure probes")
    return out
