"""Scan orchestrator: runs applicable checks in parallel and builds a ScanResult."""
from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable

from .models import CheckStatus, ScanResult, Target
from .scanners.base import CheckOutput, ScanContext
from .scanners.dns_checks import check_email_auth
from .scanners.http_checks import check_exposure, check_http
from .scanners.intel import check_intel
from .scanners.port_scan import check_ports
from .scanners.tls_check import check_tls
from .scoring import compute_risk
from .utils import clean, now_utc

# check id -> (function, target kinds it applies to)
CHECKS: dict[str, tuple[Callable[[ScanContext], CheckOutput], set[str]]] = {
    "http": (check_http, {"url"}),
    "exposure": (check_exposure, {"url"}),
    "tls": (check_tls, {"url"}),
    "dns_email": (check_email_auth, {"url", "email"}),
    "ports": (check_ports, {"url", "ip"}),
    "intel": (check_intel, {"url", "ip", "email"}),
}

OBS_ORDER = [
    "http_status", "final_url", "redirects", "https_redirect", "server",
    "tls_version", "tls_cipher", "cert_subject", "cert_issuer", "cert_expiry", "cert_key",
    "mx", "spf", "dmarc", "caa", "scanned_ip", "open_ports",
    "geoip", "rdns", "indexed_ports", "indexed_hostnames",
]


@dataclass
class ScanOptions:
    active: bool = True
    port_scan: bool = True
    api_keys: dict[str, str] = field(default_factory=dict)


def _run_one(check_id: str, fn, ctx: ScanContext):
    try:
        return check_id, fn(ctx), None
    except Exception as exc:  # a failing check must never abort the scan
        return check_id, None, f"{type(exc).__name__}: {clean(exc, 120)}"


def run_scan(
    target: Target,
    options: ScanOptions,
    on_progress: Callable[[int, int, str], None] | None = None,
) -> ScanResult:
    started = now_utc()
    ts = started.isoformat(timespec="seconds")
    ctx = ScanContext(target, options.api_keys, options.active, options.port_scan, ts)
    plan = [(cid, fn) for cid, (fn, kinds) in CHECKS.items() if target.kind in kinds]

    findings, observations, intel, checks = [], [], [], []
    with ThreadPoolExecutor(max_workers=len(plan)) as pool:
        futures = [pool.submit(_run_one, cid, fn, ctx) for cid, fn in plan]
        for done, future in enumerate(as_completed(futures), 1):
            cid, out, error = future.result()
            if error:
                checks.append(CheckStatus(cid, "failed", error))
            else:
                checks.append(CheckStatus(cid, out.status, out.detail))
                findings += out.findings
                observations += out.observations
                intel += out.intel
            if on_progress:
                on_progress(done, len(plan), cid)

    order = {cid: i for i, (cid, _) in enumerate(plan)}
    checks.sort(key=lambda c: order[c.id])
    unique = {f.finding_id: f for f in findings}
    findings = sorted(unique.values(), key=lambda f: (-f.cvss_score, f.rule_id, f.finding_id))
    observations.sort(key=lambda o: OBS_ORDER.index(o.key) if o.key in OBS_ORDER else 99)

    finished = now_utc()
    payload = json.dumps({
        "target": target.label,
        "started": ts,
        "findings": [(f.finding_id, f.severity, f.cvss_score, f.evidence) for f in findings],
    }, sort_keys=True, default=str)
    digest = hashlib.sha256(payload.encode()).hexdigest()

    return ScanResult(
        target=target,
        started_at=ts,
        finished_at=finished.isoformat(timespec="seconds"),
        options={"active": options.active, "port_scan": options.port_scan},
        findings=findings,
        observations=observations,
        checks=checks,
        intel=intel,
        risk=compute_risk(findings, checks),
        report_id=f"EVAS-{started:%Y%m%d}-{digest[:8].upper()}",
        digest=digest,
    )
