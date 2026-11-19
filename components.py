"""Small HTML building blocks. Every dynamic value goes through esc()."""
from __future__ import annotations

import math

from ..utils import esc
from ..reports.common import BAND_COLORS, SEV_COLORS


def chip(text: str, color: str) -> str:
    return (f'<span class="chip" style="background:{color}22;color:{color};'
            f'border:1px solid {color}77">{esc(text)}</span>')


def sev_chip(severity: str, label: str) -> str:
    return chip(label, SEV_COLORS[severity])


def card(title: str, inner: str) -> str:
    return f'<div class="card"><h4>{esc(title)}</h4>{inner}</div>'


def gauge(score: float, band: str, band_label: str) -> str:
    color = BAND_COLORS[band]
    arc = math.pi * 50
    filled = arc * max(0.0, min(score, 100.0)) / 100
    return (
        '<div class="gauge"><svg viewBox="0 0 120 70" width="100%" style="max-width:260px">'
        '<path d="M10 62 A50 50 0 0 1 110 62" fill="none" stroke="#30363d" stroke-width="10" stroke-linecap="round"/>'
        f'<path d="M10 62 A50 50 0 0 1 110 62" fill="none" stroke="{color}" stroke-width="10" stroke-linecap="round" '
        f'stroke-dasharray="{filled:.1f} {arc:.1f}"/></svg>'
        f'<div class="num" style="color:{color}">{score:g}</div>'
        f'<div class="lbl" style="color:{color}">{esc(band_label)}</div></div>'
    )


def kv_table(rows: list[tuple[str, str]], mono_values: bool = False) -> str:
    cls = ' class="mono"' if mono_values else ""
    body = "".join(f"<tr><th>{esc(k)}</th><td{cls}>{esc(v)}</td></tr>" for k, v in rows)
    return f'<table class="kv">{body}</table>'


def data_table(headers: list[str], rows: list[list[str]], raw_cols: set[int] | None = None) -> str:
    """rows hold plain strings (escaped here) except columns in raw_cols (pre-built safe HTML)."""
    raw_cols = raw_cols or set()
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = ""
    for row in rows:
        cells = "".join(f"<td>{c if i in raw_cols else esc(c)}</td>" for i, c in enumerate(row))
        body += f"<tr>{cells}</tr>"
    return f'<table class="kv"><tr>{head}</tr>{body}</table>'
