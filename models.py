from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")


@dataclass(frozen=True)
class Target:
    raw: str
    kind: str                      # url | ip | email
    host: str
    scheme: str | None = None
    port: int | None = None        # explicit, non-default port only
    path: str = "/"
    ips: tuple[str, ...] = ()
    email: str | None = None

    @property
    def origin(self) -> str:
        if not self.scheme:
            return ""
        port = f":{self.port}" if self.port else ""
        return f"{self.scheme}://{self.host}{port}"

    @property
    def url(self) -> str:
        return f"{self.origin}{self.path}" if self.scheme else ""

    @property
    def label(self) -> str:
        return self.email or self.url or self.host


@dataclass
class Finding:
    finding_id: str
    rule_id: str
    category: str
    cwe: str | None
    severity: str
    cvss_score: float
    cvss_vector: str | None
    status: str                    # Verified | Observed | Informational
    confidence: float
    scanner: str
    evidence: dict[str, Any]
    timestamp: str


@dataclass
class Observation:
    key: str
    value: str


@dataclass
class CheckStatus:
    id: str
    status: str                    # ok | failed | skipped
    detail: str = ""


@dataclass
class IntelResult:
    source: str
    status: str                    # ok | not_configured | error
    verdict: str = "unknown"       # clean | suspicious | malicious | unknown
    detail: str = ""


@dataclass
class RiskSummary:
    score: float
    band: str                      # critical|high|medium|low|none|unknown
    coverage: float
    counts: dict[str, int]


@dataclass
class ScanResult:
    target: Target
    started_at: str
    finished_at: str
    options: dict[str, Any]
    findings: list[Finding]
    observations: list[Observation]
    checks: list[CheckStatus]
    intel: list[IntelResult]
    risk: RiskSummary
    report_id: str
    digest: str

    @property
    def duration(self) -> float:
        a = datetime.fromisoformat(self.started_at)
        b = datetime.fromisoformat(self.finished_at)
        return round((b - a).total_seconds(), 1)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
