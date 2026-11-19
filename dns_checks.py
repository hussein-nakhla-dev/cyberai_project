"""Passive DNS checks: MX, SPF, DMARC, CAA (requires dnspython)."""
from __future__ import annotations

import re

from ..models import Observation
from ..rules import make_finding
from ..utils import clean
from .base import CheckOutput, ScanContext


def registrable_domain(host: str) -> str:
    """Organizational domain (DMARC falls back to it). Uses tldextract if present."""
    try:
        import tldextract

        ext = tldextract.TLDExtract(suffix_list_urls=())(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
    except Exception:
        pass
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) > 2 else host


def _resolver():
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.timeout, resolver.lifetime = 3.0, 5.0
    return resolver


def _query(name: str, rtype: str) -> list:
    import dns.resolver

    try:
        return list(_resolver().resolve(name, rtype))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []


def _txt(name: str) -> list[str]:
    return ["".join(s.decode("utf-8", "ignore") for s in rr.strings) for rr in _query(name, "TXT")]


def check_email_auth(ctx: ScanContext) -> CheckOutput:
    t, out = ctx.target, CheckOutput()
    domain = registrable_domain(t.host)
    scanner = "DNS-Analyzer"

    mx = sorted(str(r.exchange).rstrip(".") for r in _query(domain, "MX"))
    spf = [r for r in _txt(domain) if r.lower().startswith("v=spf1")]
    dmarc = [r for r in _txt(f"_dmarc.{domain}") if r.lower().startswith("v=dmarc1")]

    out.observations.append(Observation("mx", ", ".join(mx[:5]) or "none"))
    out.observations.append(Observation("spf", clean(spf[0], 140) if spf else "none"))
    out.observations.append(Observation("dmarc", clean(dmarc[0], 140) if dmarc else "none"))

    def add(rule_id, evidence, key, confidence=0.85):
        out.findings.append(make_finding(
            rule_id, domain, scanner, evidence, confidence=confidence, key=key,
            timestamp=ctx.timestamp,
        ))

    if t.kind == "email" and not mx:
        add("DNS-MX-MISSING", {"domain": domain}, "mx")

    if not spf:
        add("DNS-SPF-MISSING", {"domain": domain}, "spf")
    elif re.search(r"(?:^|\s)[+?]all\b", spf[0].lower()):
        add("DNS-SPF-WEAK", {"record": clean(spf[0], 140)}, "spf-weak", 0.95)

    if not dmarc:
        add("DNS-DMARC-MISSING", {"domain": domain}, "dmarc")
    else:
        policy = re.search(r"\bp\s*=\s*(\w+)", dmarc[0].lower())
        if policy and policy.group(1) == "none":
            add("DNS-DMARC-WEAK", {"record": clean(dmarc[0], 140)}, "dmarc-weak", 0.95)

    if t.kind == "url":
        caa = _query(domain, "CAA")
        out.observations.append(Observation("caa", "present" if caa else "none"))
        if not caa:
            add("DNS-CAA-MISSING", {"domain": domain}, "caa", 0.8)
    return out
