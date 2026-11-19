"""Shared helpers for all report formats."""
from __future__ import annotations

import json

from ..i18n import tr
from ..models import SEVERITIES, Finding, ScanResult

SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}
SEV_COLORS = {
    "Critical": "#c0392b", "High": "#e67e22", "Medium": "#d4a017",
    "Low": "#2e8b57", "Info": "#5d6d7e",
}
BAND_COLORS = {
    "critical": "#c0392b", "high": "#e67e22", "medium": "#d4a017",
    "low": "#2e8b57", "none": "#2e8b57", "unknown": "#5d6d7e",
}


def evidence_lines(evidence: dict) -> list[str]:
    lines = []
    for key, value in evidence.items():
        if isinstance(value, (list, tuple)):
            value = ", ".join(json.dumps(v, ensure_ascii=False) if isinstance(v, dict) else str(v) for v in value)
        elif isinstance(value, dict):
            value = json.dumps(value, ensure_ascii=False)
        lines.append(f"{key}: {value}")
    return lines


def obs_label(lang: str, key: str) -> str:
    label = tr(lang, f"obs.{key}")
    return key if label == f"obs.{key}" else label


def kind_label(lang: str, result: ScanResult) -> str:
    return tr(lang, f"kind.{result.target.kind}")


def sorted_findings(result: ScanResult) -> list[Finding]:
    return sorted(result.findings, key=lambda f: (SEV_ORDER[f.severity], -f.cvss_score, f.rule_id))


def summary_text(result: ScanResult, lang: str) -> str:
    c, r = result.risk.counts, result.risk
    executed = [x for x in result.checks if x.status != "skipped"]
    return tr(
        lang, "pdf.summary",
        ok=sum(x.status == "ok" for x in executed), total=len(executed),
        target=result.target.label, n=len(result.findings),
        crit=c["Critical"], high=c["High"], med=c["Medium"], low=c["Low"], info=c["Info"],
        score=f"{r.score:g}", band=tr(lang, f"band.{r.band}"),
    )


def fmt_ts(iso: str) -> str:
    """'2026-11-13T22:16:18+00:00' -> '2026-11-13 22:16:18'."""
    return iso.replace("T", " ").split("+")[0]
