"""Self-contained, print-friendly HTML report. Every dynamic value is escaped."""
from __future__ import annotations

from ..config import ORG_NAME
from ..i18n import tr
from ..models import ScanResult
from ..rules import fix_of, title_of
from ..utils import esc
from .common import BAND_COLORS, fmt_ts, SEV_COLORS, evidence_lines, kind_label, obs_label, sorted_findings, summary_text

CSS = """
body{font-family:Tahoma,Segoe UI,Arial,sans-serif;background:#eef2f6;color:#1b2733;margin:0;padding:24px}
.page{max-width:900px;margin:auto;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 14px rgba(0,0,0,.12)}
header{background:#0b2540;color:#fff;padding:22px 30px}header h1{margin:0;font-size:22px}header p{margin:6px 0 0;opacity:.8;font-size:13px}
section{padding:6px 30px 14px}h2{color:#00838f;border-bottom:2px solid #e3e9ef;padding-bottom:6px;margin-top:26px;font-size:17px}
table{width:100%;border-collapse:collapse;font-size:13px;margin:8px 0}th{background:#0b2540;color:#fff;padding:7px 9px;text-align:start}
td{padding:7px 9px;border-bottom:1px solid #e3e9ef;vertical-align:top;word-break:break-word}tr:nth-child(even) td{background:#f6f9fb}
.chip{display:inline-block;padding:2px 10px;border-radius:12px;color:#fff;font-size:12px;font-weight:bold}
.score{font-size:34px;font-weight:bold}.finding{border:1px solid #d5dbe3;border-radius:8px;margin:12px 0;overflow:hidden}
.finding h3{margin:0;padding:9px 14px;color:#fff;font-size:14px}.finding .body{padding:10px 14px;font-size:13px}
code,.mono{font-family:Consolas,monospace;font-size:12px;direction:ltr;unicode-bidi:plaintext}
footer{padding:14px 30px;background:#f6f9fb;font-size:11px;color:#5d6d7e}
@media print{body{background:#fff;padding:0}.page{box-shadow:none}}
"""


def _table(headers: list[str], rows: list[list[str]]) -> str:
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows)
    return f"<table><tr>{head}</tr>{body}</table>"


def build_html(result: ScanResult, lang: str) -> str:
    T = lambda k, **kw: tr(lang, k, **kw)
    rtl = lang == "ar"
    r = result.risk
    band_color = BAND_COLORS[r.band]
    chip = lambda sev: f'<span class="chip" style="background:{SEV_COLORS[sev]}">{esc(T("sev." + sev))}</span>'

    meta = _table([T("col.item"), T("col.value")], [
        [esc(T("ov.target")), f'<span class="mono">{esc(result.target.label)}</span>'],
        [esc(T("ov.type")), esc(kind_label(lang, result))],
        [esc(T("ov.started")), esc(fmt_ts(result.started_at))],
        [esc(T("ov.duration")), esc(f"{result.duration} s")],
        [esc(T("ov.report")), f'<span class="mono">{esc(result.report_id)}</span>'],
        [esc(T("pdf.digest")), f'<span class="mono">{esc(result.digest)}</span>'],
    ])
    counts = "".join(f"{chip(s)} <b>{n}</b>&nbsp;&nbsp;" for s, n in r.counts.items())

    overview_rows = [
        [esc(f.finding_id), esc(title_of(f, lang)), chip(f.severity), esc(f"{f.cvss_score:g}"), esc(T("status." + f.status))]
        for f in sorted_findings(result)
    ]
    overview = (_table([T("field.id"), T("field.title"), T("field.severity"), T("field.cvss"), T("field.status")], overview_rows)
                if overview_rows else f"<p>{esc(T('pdf.no_findings'))}</p>")

    details = ""
    for f in sorted_findings(result):
        evidence = "<br>".join(f'<span class="mono">{esc(line)}</span>' for line in evidence_lines(f.evidence))
        vector = f'<div class="mono">{esc(f.cvss_vector)}</div>' if f.cvss_vector else ""
        details += (
            f'<div class="finding"><h3 style="background:{SEV_COLORS[f.severity]}">{esc(title_of(f, lang))}</h3>'
            f'<div class="body"><p><b>{esc(T("field.cwe"))}:</b> {esc(f.cwe or "-")} &nbsp; '
            f'<b>{esc(T("field.cvss"))}:</b> {esc(f"{f.cvss_score:g}")} &nbsp; '
            f'<b>{esc(T("field.status"))}:</b> {esc(T("status." + f.status))} &nbsp; '
            f'<b>{esc(T("field.confidence"))}:</b> {int(f.confidence * 100)}% &nbsp; '
            f'<b>{esc(T("field.scanner"))}:</b> {esc(f.scanner)}</p>{vector}'
            f'<p><b>{esc(T("field.evidence"))}:</b><br>{evidence}</p>'
            f'<p><b>{esc(T("field.remediation"))}:</b> {esc(fix_of(f, lang))}</p></div></div>'
        )

    obs = _table([T("col.item"), T("col.value")],
                 [[esc(obs_label(lang, o.key)), f'<span class="mono">{esc(o.value)}</span>'] for o in result.observations])
    checks = _table([T("col.check"), T("col.status"), T("col.detail")],
                    [[esc(T("check." + c.id)), esc(T("cs." + c.status)), esc(c.detail)] for c in result.checks])
    intel = _table([T("col.source"), T("col.status"), T("col.verdict"), T("col.detail")],
                   [[esc(i.source), esc(T("is." + i.status)), esc(T("verdict." + i.verdict)), esc(i.detail)] for i in result.intel])
    limits = "".join(f"<li>{esc(T(f'pdf.lim{n}'))}</li>" for n in range(1, 6))

    return f"""<!DOCTYPE html>
<html lang="{lang}" dir="{'rtl' if rtl else 'ltr'}"><head><meta charset="utf-8">
<title>{esc(T('pdf.title'))} - {esc(result.target.label)}</title><style>{CSS}</style></head>
<body><div class="page">
<header><h1>{esc(T('pdf.title'))}</h1><p>EVAS-2026 · {esc(result.target.label)} · {esc(T('pdf.confidential'))}</p></header>
<section>
<h2>{esc(T('pdf.exec'))}</h2>
<p><span class="score" style="color:{band_color}">{r.score:g}</span><b>/100</b> &nbsp; <span class="chip" style="background:{band_color}">{esc(T('band.' + r.band))}</span></p>
<p>{counts}</p><p>{esc(summary_text(result, lang))}</p>{meta}
<h2>{esc(T('pdf.scope'))}</h2><p>{esc(T('pdf.scope_text'))}</p>{checks}
<h2>{esc(T('pdf.overview'))}</h2>{overview}
<h2>{esc(T('pdf.details'))}</h2>{details}
<h2>{esc(T('pdf.tech'))}</h2>{obs}
<h2>{esc(T('pdf.intel'))}</h2>{intel}
<h2>{esc(T('pdf.limits'))}</h2><ul>{limits}</ul>
</section>
<footer>{esc(T('pdf.prepared'))}: {esc(ORG_NAME)} · {esc(result.report_id)}</footer>
</div></body></html>"""
