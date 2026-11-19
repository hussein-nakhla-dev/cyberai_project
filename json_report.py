from __future__ import annotations

import json

from ..models import ScanResult


def build_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), ensure_ascii=False, indent=2, default=str)
