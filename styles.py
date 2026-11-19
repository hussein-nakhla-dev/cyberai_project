from __future__ import annotations


def build_css(lang: str) -> str:
    rtl = lang == "ar"
    direction, align = ("rtl", "right") if rtl else ("ltr", "left")
    return f"""
<style>
.stApp, [data-testid="stSidebar"] {{ direction: {direction}; text-align: {align}; }}
.stApp [data-testid="stMarkdownContainer"], .stApp label, .stApp .stAlert,
.stApp [data-testid="stExpander"] summary {{ text-align: {align}; }}
code, pre, .stJson, .mono, [data-testid="stJson"] {{ direction: ltr !important; text-align: left !important; unicode-bidi: plaintext; }}
.stButton button, .stDownloadButton button, [data-testid="stFormSubmitButton"] button {{
    width: 100%; border-radius: 8px; font-weight: 700;
}}
.stButton button[kind="primary"], [data-testid="stFormSubmitButton"] button {{
    background: linear-gradient(135deg, #00adb5, #1f4068); color: #fff; border: none; padding: .6rem 1rem;
}}
.evas-title {{ margin: 0 0 .15rem 0; font-size: 1.9rem; font-weight: 800; }}
.evas-sub {{ margin: 0 0 1rem 0; color: #8b949e; font-size: .95rem; }}
.card {{ background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 16px 18px; margin-bottom: 12px; }}
.card h4 {{ margin: 0 0 10px 0; font-size: .95rem; color: #8b949e; font-weight: 600; }}
.chip {{ display: inline-block; padding: 2px 11px; border-radius: 12px; font-size: .78rem; font-weight: 700; margin: 2px 3px; }}
.kv {{ width: 100%; border-collapse: collapse; font-size: .9rem; }}
.kv td, .kv th {{ padding: 7px 9px; border-bottom: 1px solid #30363d; vertical-align: top; text-align: {align}; word-break: break-word; }}
.kv th {{ color: #8b949e; font-weight: 600; width: 34%; }}
.gauge {{ text-align: center; }}
.gauge .num {{ font-size: 2.3rem; font-weight: 800; line-height: 1; margin-top: -34px; }}
.gauge .lbl {{ margin-top: 6px; font-weight: 700; }}
.demo-banner {{ background: #3b2f12; border: 1px solid #d4a017; color: #ffd666; border-radius: 8px; padding: 8px 14px; margin-bottom: 12px; }}
.foot {{ text-align: center; color: #8b949e; font-size: .8rem; padding: 18px 0 4px; }}
</style>
"""
