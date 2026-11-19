"""Professional PDF report (ReportLab) with full Arabic/RTL support.

Arabic needs: an Arabic-capable .ttf (assets/fonts/ or a system font),
`arabic-reshaper` and `python-bidi`. If any is missing the report is
generated in English and the caller is told via the returned language.
"""
from __future__ import annotations

import re
from io import BytesIO
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.graphics.shapes import Drawing, Rect
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import (BaseDocTemplate, Frame, KeepTogether, PageTemplate,
                                Paragraph, Spacer, Table, TableStyle)

from ..config import FONT_DIR, ORG_NAME
from ..i18n import tr
from ..models import SEVERITIES, ScanResult
from ..rules import fix_of, title_of
from ..utils import clean
from .common import BAND_COLORS, SEV_COLORS, evidence_lines, fmt_ts, kind_label, obs_label, sorted_findings, summary_text

try:  # optional: only needed for Arabic
    import arabic_reshaper
    try:
        from bidi import get_display
    except ImportError:  # python-bidi < 0.5
        from bidi.algorithm import get_display
    HAVE_BIDI = True
except Exception:
    HAVE_BIDI = False

NAVY, TEAL = colors.HexColor("#0b2540"), colors.HexColor("#00838f")
GRID, LIGHT, MUTED = colors.HexColor("#d5dbe3"), colors.HexColor("#f4f7fa"), colors.HexColor("#5d6d7e")
MARGIN = 18 * mm
_ARABIC = re.compile(r"[\u0600-\u06FF\u0750-\u077F]")

_SYSTEM_FONTS = [  # (regular, bold)
    ("/usr/share/fonts/truetype/noto/NotoNaskhArabic-Regular.ttf", "/usr/share/fonts/truetype/noto/NotoNaskhArabic-Bold.ttf"),
    ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
    ("C:/Windows/Fonts/tahoma.ttf", "C:/Windows/Fonts/tahomabd.ttf"),
    ("C:/Windows/Fonts/arial.ttf", "C:/Windows/Fonts/arialbd.ttf"),
    ("/System/Library/Fonts/Supplemental/Arial.ttf", "/System/Library/Fonts/Supplemental/Arial Bold.ttf"),
    ("/Library/Fonts/Arial.ttf", "/Library/Fonts/Arial Bold.ttf"),
]


def _font_candidates() -> list[tuple[Path, Path]]:
    found: list[tuple[Path, Path]] = []
    if FONT_DIR.is_dir():
        files = sorted(FONT_DIR.glob("*.ttf")) + sorted(FONT_DIR.glob("*.otf"))
        regular = [f for f in files if "bold" not in f.stem.lower()]
        bold = [f for f in files if "bold" in f.stem.lower()]
        for reg in regular:
            family = reg.stem.lower().split("-")[0]
            match = next((b for b in bold if b.stem.lower().startswith(family)), reg)
            found.append((reg, match))
    found += [(Path(r), Path(b)) for r, b in _SYSTEM_FONTS]
    return found


def register_fonts() -> tuple[str, str, bool]:
    """Return (regular_name, bold_name, supports_arabic)."""
    for reg, bold in _font_candidates():
        if not reg.exists():
            continue
        try:
            font = TTFont("EVAS", str(reg))
            pdfmetrics.registerFont(font)
            pdfmetrics.registerFont(TTFont("EVAS-Bold", str(bold if bold.exists() else reg)))
            pdfmetrics.registerFontFamily("EVAS", normal="EVAS", bold="EVAS-Bold", italic="EVAS", boldItalic="EVAS-Bold")
            return "EVAS", "EVAS-Bold", 0xFE8D in font.face.charToGlyph   # Arabic presentation form
        except Exception:
            continue
    return "Helvetica", "Helvetica-Bold", False


class _Doc:
    """Holds language, fonts and style factories for one PDF build."""

    def __init__(self, lang: str, fonts: tuple[str, str]):
        self.lang, self.rtl = lang, lang == "ar"
        self.f, self.fb = fonts
        self.width = A4[0] - 2 * MARGIN
        self.align = TA_RIGHT if self.rtl else TA_LEFT

    def style(self, name, size=9.5, bold=False, color=colors.HexColor("#1b2733"), align=None, leading=None, **kw):
        return ParagraphStyle(name, fontName=self.fb if bold else self.f, fontSize=size,
                              leading=leading or size * 1.45, textColor=color,
                              alignment=self.align if align is None else align, **kw)

    def shape(self, text: str) -> str:
        if self.rtl and _ARABIC.search(text):
            return get_display(arabic_reshaper.reshape(text), base_dir="R")
        return text

    def _wrap(self, text: str, style: ParagraphStyle, width: float) -> list[str]:
        lines: list[str] = []
        for block in text.split("\n"):
            current = ""
            for word in block.split():
                trial = f"{current} {word}".strip()
                if not current or pdfmetrics.stringWidth(self.shape(trial), style.fontName, style.fontSize) <= width:
                    current = trial
                else:
                    lines.append(current)
                    current = word
            lines.append(current)
        return lines

    def P(self, text, style: ParagraphStyle, width: float | None = None) -> Paragraph:
        text = str(text)
        if self.rtl and _ARABIC.search(text):
            avail = (width or self.width) - style.leftIndent - style.rightIndent
            lines = self._wrap(text, style, avail)
            return Paragraph("<br/>".join(escape(self.shape(line)) for line in lines), style)
        return Paragraph(escape(text), style)

    def table(self, rows, widths, style_cmds=None, header=True, repeat=1):
        if self.rtl:   # mirror column order for right-to-left reading
            rows = [list(reversed(r)) for r in rows]
            widths = list(reversed(widths))
            style_cmds = _mirror(style_cmds, len(widths))
        t = Table(rows, colWidths=widths, repeatRows=repeat if header else 0)
        cmds = [
            ("GRID", (0, 0), (-1, -1), 0.4, GRID), ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]
        if header:
            cmds += [("BACKGROUND", (0, 0), (-1, 0), NAVY)]
        cmds += [("ROWBACKGROUNDS", (0, 1 if header else 0), (-1, -1), [colors.white, LIGHT])]
        t.setStyle(TableStyle(cmds + (style_cmds or [])))
        return t


def _mirror(cmds, ncols):
    """Mirror column coordinates of table style commands for RTL layouts."""
    if not cmds:
        return cmds
    norm = lambda c: c if c >= 0 else ncols + c
    out = []
    for name, (c0, r0), (c1, r1), *rest in cmds:
        a, b = ncols - 1 - norm(c0), ncols - 1 - norm(c1)
        out.append((name, (min(a, b), r0), (max(a, b), r1), *rest))
    return out


def _canvas_class(doc: _Doc, result: ScanResult):
    class Numbered(canvas.Canvas):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self._pages: list[dict] = []

        def showPage(self):
            self._pages.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total = len(self._pages)
            for state in self._pages:
                self.__dict__.update(state)
                self._chrome(total)
                super().showPage()
            super().save()

        def _text(self, x, y, text, font, size, right=False, color=colors.white):
            self.setFont(font, size)
            self.setFillColor(color)
            text = doc.shape(text)
            (self.drawRightString if right else self.drawString)(x, y, text)

        def _chrome(self, total):
            w, h = A4
            self.setFillColor(NAVY)
            self.rect(0, h - 13 * mm, w, 13 * mm, stroke=0, fill=1)
            self.setFillColor(TEAL)
            self.rect(0, h - 13.8 * mm, w, 0.8 * mm, stroke=0, fill=1)
            brand_x, tag_x = (w - MARGIN, MARGIN) if doc.rtl else (MARGIN, w - MARGIN)
            self._text(brand_x, h - 8.6 * mm, "EVAS-2026", doc.fb, 12, right=doc.rtl)
            self._text(tag_x, h - 8.4 * mm, tr(doc.lang, "pdf.confidential"), doc.f, 8.5, right=not doc.rtl)
            self.setStrokeColor(GRID)
            self.line(MARGIN, 13 * mm, w - MARGIN, 13 * mm)
            page = f"{tr(doc.lang, 'pdf.page')} {self._pageNumber} {tr(doc.lang, 'pdf.of')} {total}"
            left_x, right_x = (MARGIN, w - MARGIN)
            id_text = f"{result.report_id}"
            self._text(right_x if doc.rtl else left_x, 8 * mm, id_text, doc.f, 8, right=doc.rtl, color=MUTED)
            self._text(left_x if doc.rtl else right_x, 8 * mm, page, doc.f, 8, right=not doc.rtl, color=MUTED)

    return Numbered


def _bar(doc: _Doc, score: float, color) -> Drawing:
    d = Drawing(doc.width, 9)
    d.add(Rect(0, 0, doc.width, 9, fillColor=colors.HexColor("#e3e9ef"), strokeColor=None))
    fill = doc.width * max(0.0, min(score, 100.0)) / 100
    d.add(Rect(doc.width - fill if doc.rtl else 0, 0, fill, 9, fillColor=color, strokeColor=None))
    return d


def generate_pdf(result: ScanResult, lang: str = "en") -> tuple[bytes, str]:
    """Return (pdf_bytes, language_used). Falls back to English if Arabic is unavailable."""
    regular, bold, arabic_ok = register_fonts()
    used = "ar" if (lang == "ar" and arabic_ok and HAVE_BIDI) else "en"
    d = _Doc(used, (regular, bold))
    T = lambda k, **kw: tr(used, k, **kw)
    r = result.risk
    band_color = colors.HexColor(BAND_COLORS[r.band])

    h1 = d.style("h1", 21, True, NAVY, leading=26)
    sub = d.style("sub", 10.5, False, MUTED)
    h2 = d.style("h2", 13, True, TEAL, spaceBefore=14, spaceAfter=6, keepWithNext=1)
    body = d.style("body", 9.5)
    small = d.style("small", 8, False, MUTED)
    cell, cellb = d.style("cell", 8.5, leading=12), d.style("cellb", 8.5, True, leading=12)
    head = d.style("head", 8.5, True, colors.white, leading=12)
    mono = d.style("mono", 7, False, colors.HexColor("#33475b"), align=TA_LEFT, leading=10.5)
    big = d.style("big", 26, True, band_color, align=TA_CENTER, leading=30)
    cap = d.style("cap", 8, False, MUTED, align=TA_CENTER)
    bullet = d.style("bullet", 9, leading=13, spaceAfter=3)

    C = lambda text, w, st=cell: d.P(text, st, w - 10)
    story: list = []

    # ---- cover block
    story += [d.P(T("pdf.title"), h1), d.P(result.target.label, sub), Spacer(1, 8)]
    w1, w2 = 42 * mm, d.width - 42 * mm
    meta = [
        (T("ov.target"), result.target.label), (T("ov.type"), kind_label(used, result)),
        (T("ov.started"), fmt_ts(result.started_at)), (T("ov.duration"), f"{result.duration} s"),
        (T("ov.report"), result.report_id), (T("pdf.prepared"), ORG_NAME),
    ]
    rows = [[C(k, w1, cellb), C(v, w2)] for k, v in meta]
    rows.append([C(T("pdf.digest"), w1, cellb), Paragraph(escape(result.digest), mono)])
    story += [d.table(rows, [w1, w2], header=False), Spacer(1, 10)]

    third = d.width / 3
    kpi = d.table(
        [[Paragraph(f"{r.score:g}/100", big), d.P(T("band." + r.band), d.style("bandv", 13, True, band_color, align=TA_CENTER), third - 10),
          Paragraph(f"{int(r.coverage * 100)}%", d.style("covv", 20, True, NAVY, align=TA_CENTER, leading=30))],
         [d.P(T("ov.score"), cap, third - 10), d.P(T("ov.band"), cap, third - 10), d.P(T("ov.coverage"), cap, third - 10)]],
        [third] * 3, header=False,
        style_cmds=[("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white])])
    story += [kpi, Spacer(1, 6), _bar(d, r.score, band_color), Spacer(1, 10)]

    fifth = d.width / 5
    sev_cells = [[Paragraph(str(r.counts[s]), d.style(f"n{s}", 20, True, colors.HexColor(SEV_COLORS[s]), align=TA_CENTER, leading=24)) for s in SEVERITIES],
                 [d.P(T("sev." + s), cap, fifth - 10) for s in SEVERITIES]]
    story += [d.table(sev_cells, [fifth] * 5, header=False,
                      style_cmds=[("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white])])]

    # ---- 1 executive summary
    story += [d.P(T("pdf.exec"), h2), d.P(summary_text(result, used), body)]
    top = [f for f in sorted_findings(result) if f.cvss_score > 0][:3]
    if top:
        story += [Spacer(1, 4), d.P(T("pdf.top"), d.style("topt", 10, True, NAVY))]
        story += [d.P(f"{i}. {title_of(f, used)} ({T('sev.' + f.severity)}, CVSS {f.cvss_score:g})", bullet)
                  for i, f in enumerate(top, 1)]

    # ---- 2 scope
    story += [d.P(T("pdf.scope"), h2), d.P(T("pdf.scope_text"), body), Spacer(1, 6)]
    cw = [55 * mm, 25 * mm, d.width - 80 * mm]
    rows = [[C(T("col.check"), cw[0], head), C(T("col.status"), cw[1], head), C(T("col.detail"), cw[2], head)]]
    rows += [[C(T("check." + c.id), cw[0]), C(T("cs." + c.status), cw[1]), C(c.detail or "-", cw[2], mono)] for c in result.checks]
    story.append(d.table(rows, cw))

    # ---- 3 overview table
    findings = sorted_findings(result)
    story.append(d.P(T("pdf.overview"), h2))
    if not findings:
        story.append(d.P(T("pdf.no_findings"), body))
    else:
        cw = [8 * mm, 49 * mm, d.width - (8 + 49 + 24 + 14 + 27) * mm, 24 * mm, 14 * mm, 27 * mm]
        rows = [[C(h, w, head) for h, w in zip(("#", T("field.id"), T("field.title"), T("field.severity"), T("field.cvss"), T("field.status")), cw)]]
        cmds = []
        for i, f in enumerate(findings, 1):
            sev_style = d.style(f"sv{i}", 8.5, True, colors.white, align=TA_CENTER, leading=12)
            rows.append([C(str(i), cw[0]), Paragraph(escape(f.finding_id), mono), C(title_of(f, used), cw[2]),
                         C(T("sev." + f.severity), cw[3], sev_style), C(f"{f.cvss_score:g}" if f.cvss_score else "-", cw[4]), C(T("status." + f.status), cw[5])])
            cmds.append(("BACKGROUND", (3, i), (3, i), colors.HexColor(SEV_COLORS[f.severity])))
        story.append(d.table(rows, cw, cmds))

    # ---- 4 details
    if findings:
        story.append(d.P(T("pdf.details"), h2))
    for i, f in enumerate(findings, 1):
        sev_color = colors.HexColor(SEV_COLORS[f.severity])
        head_style = d.style(f"fh{i}", 10.5, True, colors.white, leading=14)
        hw = [d.width - 28 * mm, 28 * mm]
        header = d.table([[d.P(f"{i}. {title_of(f, used)}", head_style, hw[0] - 10),
                           d.P(f"{T('sev.' + f.severity)} · {f.cvss_score:g}", d.style(f"fs{i}", 9, True, colors.white, align=TA_CENTER), hw[1] - 10)]],
                         hw, header=False,
                         style_cmds=[("BACKGROUND", (0, 0), (-1, -1), sev_color), ("VALIGN", (0, 0), (-1, -1), "MIDDLE")])
        mw = [d.width / 4] * 4
        meta_rows = [[C(T("field.cwe"), mw[0], cellb), C(T("field.status"), mw[1], cellb), C(T("field.confidence"), mw[2], cellb), C(T("field.category"), mw[3], cellb)],
                     [C(f.cwe or "-", mw[0]), C(T("status." + f.status), mw[1]), C(f"{int(f.confidence * 100)}%", mw[2]), C(T("cat." + f.category), mw[3])]]
        meta_t = d.table(meta_rows, mw, header=False, style_cmds=[("BACKGROUND", (0, 0), (-1, 0), LIGHT)])
        block = [header, meta_t, Spacer(1, 3)]
        if f.cvss_vector:
            block.append(Paragraph(escape(f"{T('field.vector')}: {f.cvss_vector}   |   {T('field.scanner')}: {f.scanner}"), mono))
        block += [Spacer(1, 3), d.P(T("field.evidence"), d.style(f"el{i}", 8.5, True, NAVY))]
        block += [Paragraph(escape(clean(line, 300)), mono) for line in evidence_lines(f.evidence)]
        block += [Spacer(1, 3), d.P(T("field.remediation"), d.style(f"rl{i}", 8.5, True, NAVY)), d.P(fix_of(f, used), body), Spacer(1, 12)]
        story.append(KeepTogether(block))

    # ---- 5 observations
    story.append(d.P(T("pdf.tech"), h2))
    ow = [60 * mm, d.width - 60 * mm]
    rows = [[C(T("col.item"), ow[0], head), C(T("col.value"), ow[1], head)]]
    rows += [[C(obs_label(used, o.key), ow[0], cellb), Paragraph(escape(clean(o.value, 300)), mono)] for o in result.observations]
    story.append(d.table(rows, ow) if result.observations else d.P("-", body))

    # ---- 6 intelligence
    story.append(d.P(T("pdf.intel"), h2))
    iw = [38 * mm, 28 * mm, 24 * mm, d.width - 90 * mm]
    rows = [[C(h, w, head) for h, w in zip((T("col.source"), T("col.status"), T("col.verdict"), T("col.detail")), iw)]]
    rows += [[C(i.source, iw[0], cellb), C(T("is." + i.status), iw[1]), C(T("verdict." + i.verdict), iw[2]), C(i.detail or "-", iw[3], mono)]
             for i in result.intel]
    story.append(d.table(rows, iw) if result.intel else d.P("-", body))

    # ---- 7 limitations
    story.append(d.P(T("pdf.limits"), h2))
    story += [d.P(f"- {T(f'pdf.lim{n}')}", bullet) for n in range(1, 6)]

    buf = BytesIO()
    doc = BaseDocTemplate(buf, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN,
                          topMargin=22 * mm, bottomMargin=20 * mm,
                          title=f"{T('pdf.title')} - {result.target.label}", author=ORG_NAME, subject=result.report_id)
    frame = Frame(MARGIN, 20 * mm, d.width, A4[1] - 42 * mm, id="main", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    doc.addPageTemplates([PageTemplate(id="p", frames=[frame])])
    doc.build(story, canvasmaker=_canvas_class(d, result))
    return buf.getvalue(), used
