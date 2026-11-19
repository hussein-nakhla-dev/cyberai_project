"""EVAS-2026 - Streamlit entry point.  Run:  streamlit run app.py"""
from __future__ import annotations

import time

import streamlit as st

from evas import __version__
from evas.config import (API_KEY_NAMES, MAX_SCANS_PER_SESSION, ORG_NAME,
                         SCAN_COOLDOWN_SECONDS, load_api_keys)
from evas.demo import sample_result
from evas.engine import ScanOptions, run_scan
from evas.i18n import tr
from evas.models import SEVERITIES, ScanResult
from evas.reports.common import fmt_ts, kind_label, obs_label, sorted_findings
from evas.reports.html_report import build_html
from evas.reports.json_report import build_json
from evas.reports.pdf_report import generate_pdf
from evas.reports.ticket import build_ticket_md
from evas.rules import fix_of, title_of
from evas.scoring import diff_findings
from evas.security import TargetError, parse_target
from evas.ui.components import card, chip, data_table, gauge, kv_table, sev_chip
from evas.ui.styles import build_css
from evas.utils import esc

st.set_page_config(page_title="EVAS-2026", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

ss = st.session_state
for key, default in (("lang", "ar"), ("result", None), ("prev", None), ("last_scan_ts", 0.0), ("scan_count", 0)):
    ss.setdefault(key, default)

lang = ss.lang
T = lambda key, **kw: tr(lang, key, **kw)
st.markdown(build_css(lang), unsafe_allow_html=True)


def toggle_language() -> None:
    ss.lang = "en" if ss.lang == "ar" else "ar"


@st.cache_data(show_spinner=False, max_entries=8)
def cached_pdf(report_id: str, language: str, _result: ScanResult):
    return generate_pdf(_result, language)


# ------------------------------------------------------------------ header
head_col, lang_col = st.columns([6, 1])
head_col.markdown(f'<h1 class="evas-title">🛡️ {esc(T("app.title"))}</h1>'
                  f'<p class="evas-sub">{esc(T("app.subtitle"))}</p>', unsafe_allow_html=True)
lang_col.button(T("lang.switch"), on_click=toggle_language, key="lang_btn")

# ----------------------------------------------------------------- sidebar
with st.sidebar:
    st.subheader(T("side.options"))
    opt_active = st.checkbox(T("opt.active"), value=True, help=T("opt.active_help"))
    opt_ports = st.checkbox(T("opt.ports"), value=True, help=T("opt.ports_help"))
    st.subheader(T("side.keys"))
    api_keys = load_api_keys()
    st.markdown("  \n".join(f"{'✅' if name in api_keys else '⚪'} {label}" for name, label in API_KEY_NAMES.items())
                + "  \n✅ Shodan InternetDB")
    st.caption(T("side.keys_hint"))
    st.divider()
    if st.button(T("btn.demo"), key="demo_btn"):
        ss.prev, ss.result = None, sample_result()
    st.caption(f"v{__version__} · {ORG_NAME}")

# -------------------------------------------------------------------- form
with st.form("scan_form"):
    target_input = st.text_input(T("input.label"), placeholder=T("input.placeholder"), max_chars=500)
    authorized = st.checkbox(T("auth.label"))
    submitted = st.form_submit_button(T("btn.scan"), type="primary")


def start_scan() -> None:
    if not authorized:
        st.warning(T("auth.required"))
        return
    wait = SCAN_COOLDOWN_SECONDS - (time.time() - ss.last_scan_ts)
    if wait > 0:
        st.warning(T("err.cooldown", s=int(wait) + 1))
        return
    if ss.scan_count >= MAX_SCANS_PER_SESSION:
        st.error(T("err.limit"))
        return
    try:
        with st.spinner(T("progress.resolve")):
            target = parse_target(target_input)
    except TargetError as exc:
        st.error(T(f"err.{exc.code}"))
        return

    bar = st.progress(0.0, text=T("progress.resolve"))

    def on_progress(done: int, total: int, check_id: str) -> None:
        bar.progress(done / total, text=T("progress.label", name=T(f"check.{check_id}"), done=done, total=total))

    options = ScanOptions(active=opt_active, port_scan=opt_ports, api_keys=api_keys)
    result = run_scan(target, options, on_progress)
    bar.empty()
    ss.last_scan_ts, ss.scan_count = time.time(), ss.scan_count + 1
    same = ss.result if ss.result and ss.result.target.label == result.target.label else None
    ss.prev, ss.result = same, result


if submitted:
    start_scan()


# ----------------------------------------------------------------- results
def tab_overview(res: ScanResult) -> None:
    r = res.risk
    if res.options.get("demo"):
        st.markdown(f'<div class="demo-banner">⚠️ {esc(T("demo.banner"))}</div>', unsafe_allow_html=True)
    c1, c2, c3 = st.columns([1.2, 1.6, 1.4])
    c1.markdown(card(T("ov.score"), gauge(r.score, r.band, T(f"band.{r.band}"))), unsafe_allow_html=True)
    c2.markdown(card(T("ov.target"), kv_table([
        (T("ov.target"), res.target.label), (T("ov.type"), kind_label(lang, res)),
        (T("ov.started"), fmt_ts(res.started_at)), (T("ov.duration"), f"{res.duration} s"),
        (T("ov.report"), res.report_id), (T("ov.coverage"), f"{int(r.coverage * 100)}%"),
    ], mono_values=True)), unsafe_allow_html=True)
    chips = "".join(f"{sev_chip(s, T('sev.' + s))} <b>{r.counts[s]}</b><br>" for s in SEVERITIES)
    c3.markdown(card(T("ov.counts"), chips), unsafe_allow_html=True)

    if ss.prev is not None:
        new, fixed = diff_findings(ss.prev, res)
        st.info(T("ov.delta", new=len(new), fixed=len(fixed)))

    top = [f for f in sorted_findings(res) if f.cvss_score > 0][:3]
    if top:
        st.markdown(f"**{T('ov.top')}**")
        for f in top:
            st.markdown(f"- {sev_chip(f.severity, T('sev.' + f.severity))} {esc(title_of(f, lang))}", unsafe_allow_html=True)
    with st.expander(T("ov.method")):
        st.write(T("ov.method_text"))


def tab_findings(res: ScanResult) -> None:
    findings = sorted_findings(res)
    if not findings:
        st.info(T("f.none"))
        return
    present = [s for s in SEVERITIES if any(f.severity == s for f in findings)]
    chosen = st.multiselect(T("f.filter"), present, default=present, format_func=lambda s: T(f"sev.{s}"))
    for f in findings:
        if f.severity not in chosen:
            continue
        with st.expander(f"[{T('sev.' + f.severity)}] {title_of(f, lang)} · CVSS {f.cvss_score:g}"):
            st.markdown(kv_table([
                (T("field.id"), f.finding_id), (T("field.cwe"), f.cwe or "-"),
                (T("field.category"), T(f"cat.{f.category}")), (T("field.status"), T(f"status.{f.status}")),
                (T("field.confidence"), f"{int(f.confidence * 100)}%"), (T("field.scanner"), f.scanner),
                (T("field.vector"), f.cvss_vector or "-"),
            ], mono_values=True), unsafe_allow_html=True)
            st.markdown(f"**{T('field.evidence')}**")
            st.json(f.evidence)
            st.markdown(f"**{T('field.remediation')}**")
            st.write(fix_of(f, lang))


def tab_technical(res: ScanResult) -> None:
    st.markdown(f"#### {T('tech.obs')}")
    if res.observations:
        st.markdown(data_table([T("col.item"), T("col.value")],
                               [[obs_label(lang, o.key), o.value] for o in res.observations]), unsafe_allow_html=True)
    else:
        st.info(T("tech.none"))
    st.markdown(f"#### {T('tech.checks')}")
    icons = {"ok": "✅", "failed": "❌", "skipped": "⏭️"}
    st.markdown(data_table(
        [T("col.check"), T("col.status"), T("col.detail")],
        [[T(f"check.{c.id}"), f"{icons[c.status]} {T('cs.' + c.status)}", c.detail or "-"] for c in res.checks]),
        unsafe_allow_html=True)


def tab_intel(res: ScanResult) -> None:
    st.markdown(f"#### {T('intel.title')}")
    st.caption(T("intel.note"))
    if not res.intel:
        st.info(T("intel.none"))
        return
    colors = {"clean": "#2e8b57", "suspicious": "#d4a017", "malicious": "#c0392b", "unknown": "#5d6d7e"}
    rows = [[i.source, T(f"is.{i.status}"), chip(T(f"verdict.{i.verdict}"), colors[i.verdict]), i.detail or "-"] for i in res.intel]
    st.markdown(data_table([T("col.source"), T("col.status"), T("col.verdict"), T("col.detail")], rows, raw_cols={2}),
                unsafe_allow_html=True)


def tab_plan(res: ScanResult) -> None:
    st.markdown(f"#### {T('plan.title')}")
    actionable = [f for f in sorted_findings(res) if f.cvss_score > 0]
    if not actionable:
        st.success(T("plan.none"))
        return
    rows = [[sev_chip(f.severity, T(f"prio.{f.severity}")), title_of(f, lang), fix_of(f, lang), T(f"sla.{f.severity}")] for f in actionable]
    st.markdown(data_table([T("col.priority"), T("col.finding"), T("col.action"), T("col.sla")], rows, raw_cols={0}),
                unsafe_allow_html=True)
    st.caption(T("plan.sla_note"))


def tab_export(res: ScanResult) -> None:
    st.markdown(f"#### {T('exp.title')}")
    name = f"EVAS_{res.report_id}_{lang}"
    c1, c2, c3, c4 = st.columns(4)
    with st.spinner("PDF…"):
        pdf_bytes, used = cached_pdf(res.report_id, lang, res)
    c1.download_button(T("exp.pdf"), pdf_bytes, f"{name}.pdf", "application/pdf")
    c2.download_button(T("exp.html"), build_html(res, lang), f"{name}.html", "text/html")
    c3.download_button(T("exp.json"), build_json(res), f"{name}.json", "application/json")
    c4.download_button(T("exp.ticket"), build_ticket_md(res, lang), f"{name}_ticket.md", "text/markdown")
    if used != lang:
        st.warning(T("exp.font_warn"))
    st.caption(T("exp.note"))


if ss.result is not None:
    res: ScanResult = ss.result
    if not res.options.get("demo"):
        st.success(T("done", n=len(res.findings), s=res.duration))
    tabs = st.tabs([T("tab.overview"), T("tab.findings"), T("tab.technical"), T("tab.intel"), T("tab.plan"), T("tab.export")])
    for tab, render in zip(tabs, (tab_overview, tab_findings, tab_technical, tab_intel, tab_plan, tab_export)):
        with tab:
            render(res)

st.markdown(f'<div class="foot">{esc(T("footer", org=ORG_NAME, v=__version__))}</div>', unsafe_allow_html=True)
