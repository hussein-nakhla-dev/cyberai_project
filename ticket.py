from __future__ import annotations

from ..i18n import tr
from ..models import ScanResult
from ..rules import fix_of, title_of
from .common import sorted_findings


def build_ticket_md(result: ScanResult, lang: str) -> str:
    actionable = [f for f in sorted_findings(result) if f.cvss_score > 0]
    top = actionable[0].severity if actionable else "Info"
    lines = [
        f"# {tr(lang, 'ticket.title')} [{tr(lang, 'prio.' + top)}]",
        "",
        f"- **{tr(lang, 'ov.report')}:** {result.report_id}",
        f"- **{tr(lang, 'ov.target')}:** {result.target.label}",
        f"- **{tr(lang, 'ov.score')}:** {result.risk.score:g}/100 ({tr(lang, 'band.' + result.risk.band)})",
        "",
    ]
    if not actionable:
        lines.append(tr(lang, "plan.none"))
    for i, f in enumerate(actionable, 1):
        lines += [
            f"## {i}. [{tr(lang, 'prio.' + f.severity)}] {title_of(f, lang)}",
            f"- **{tr(lang, 'field.severity')}:** {tr(lang, 'sev.' + f.severity)} (CVSS {f.cvss_score})",
            f"- **{tr(lang, 'col.sla')}:** {tr(lang, 'sla.' + f.severity)}",
            f"- **{tr(lang, 'field.remediation')}:** {fix_of(f, lang)}",
            f"- **{tr(lang, 'field.id')}:** {f.finding_id}",
            "",
        ]
    lines.append(f"_{tr(lang, 'plan.sla_note')}_")
    return "\n".join(lines)
