"""CVSS v3.1 base-score calculator (FIRST specification)."""
from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    parts = vector.split("/")
    if not parts or not parts[0].startswith("CVSS:3"):
        raise ValueError(f"Unsupported CVSS vector: {vector}")
    metrics = dict(p.split(":", 1) for p in parts[1:])
    for key in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"):
        if key not in metrics:
            raise ValueError(f"Missing metric {key} in {vector}")
    return metrics


def base_score(vector: str) -> float:
    m = parse_vector(vector)
    changed = m["S"] == "C"
    pr = (_PR_C if changed else _PR_U)[m["PR"]]
    c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    raw = 1.08 * (impact + exploitability) if changed else impact + exploitability
    return _roundup(min(raw, 10.0))


def severity_from_score(score: float) -> str:
    if score <= 0:
        return "Info"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"
