from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Finding, IntelResult, Observation, Target


@dataclass
class ScanContext:
    target: Target
    api_keys: dict[str, str]
    active: bool          # allow active probes (exposed-file requests)
    port_scan: bool       # allow TCP connect checks
    timestamp: str


@dataclass
class CheckOutput:
    findings: list[Finding] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    intel: list[IntelResult] = field(default_factory=list)
    status: str = "ok"    # ok | skipped
    detail: str = ""
