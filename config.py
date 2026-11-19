"""Central configuration. Edit values here, not in the scanners."""
from __future__ import annotations

import os
from pathlib import Path

from . import __version__

APP_NAME = "EVAS-2026"
ORG_NAME = "Eng. Hussein Nakhla"          # shown in reports and footer
BASE_DIR = Path(__file__).resolve().parent.parent
FONT_DIR = BASE_DIR / "assets" / "fonts"   # drop an Arabic .ttf here for PDF

USER_AGENT = f"EVAS-Scanner/{__version__} (authorized security assessment)"

# --- Network safety -------------------------------------------------------
ALLOWED_WEB_PORTS = {80, 443, 8080, 8443}  # SSRF hardening: no arbitrary ports
MAX_REDIRECTS = 4
HTTP_TIMEOUT = 6.0
TLS_TIMEOUT = 5.0
PORT_TIMEOUT = 1.5

# --- Abuse protection (per Streamlit session) ------------------------------
SCAN_COOLDOWN_SECONDS = 20
MAX_SCANS_PER_SESSION = 25

# --- Threat-intel API keys -------------------------------------------------
API_KEY_NAMES = {
    "VIRUSTOTAL_API_KEY": "VirusTotal",
    "ABUSEIPDB_API_KEY": "AbuseIPDB",
}


def load_api_keys() -> dict[str, str]:
    """Read keys from st.secrets first, then environment variables."""
    keys: dict[str, str] = {}
    for name in API_KEY_NAMES:
        value = os.environ.get(name, "")
        try:
            import streamlit as st

            value = st.secrets.get(name, value)
        except Exception:  # no secrets file / not running in streamlit
            pass
        if value:
            keys[name] = str(value)
    return keys
