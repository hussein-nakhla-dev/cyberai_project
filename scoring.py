"""Transparent, auditable risk model (no hidden ML)."""
from __future__ import annotations

from .models import SEVERITIES, CheckStatus, Finding, RiskSummary

# Score = strongest weighted finding + 5% of all the others, capped at 100.
BAND_THRESHOLDS = ((85, "critical"), (70, "high"), (35, "medium"))


def _weighted(f: Finding) -> float:
    return f.cvss_score * 10 * (0.5 + 0.5 * f.confidence)


def compute_risk(findings: list[Finding], checks: list[CheckStatus]) -> RiskSummary:
    values = sorted((_weighted(f) for f in findings if f.cvss_score > 0), reverse=True)
    score = min(100.0, values[0] + 0.05 * sum(values[1:])) if values else 0.0
    score = round(score, 1)

    executed = [c for c in checks if c.status != "skipped"]
    coverage = (sum(c.status == "ok" for c in executed) / len(executed)) if executed else 0.0

    if executed and coverage == 0:
        band = "unknown"
    elif not values:
        band = "none"
    else:
        band = next((name for limit, name in BAND_THRESHOLDS if score >= limit), "low")

    counts = {s: sum(f.severity == s for f in findings) for s in SEVERITIES}
    return RiskSummary(score=score, band=band, coverage=round(coverage, 2), counts=counts)


def diff_findings(previous, current) -> tuple[set[str], set[str]]:
    """Return (new_ids, resolved_ids) between two ScanResult objects."""
    before = {f.finding_id for f in previous.findings}
    after = {f.finding_id for f in current.findings}
    return after - before, before - after
