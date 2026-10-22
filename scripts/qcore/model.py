"""Core data model shared by every rule layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict

SEVERITIES = ("INFO", "WARNING", "CRITICAL")
_SEV_RANK = {"INFO": 1, "WARNING": 2, "CRITICAL": 3}

CATEGORIES = ("ad_injection", "supply_chain", "architecture_deviation", "ai_review")


def sev_rank(sev: str) -> int:
    return _SEV_RANK.get((sev or "").upper(), 0)


def normalize_severity(value: str, default: str = "WARNING") -> str:
    v = (value or "").strip().upper()
    return v if v in _SEV_RANK else default


@dataclass
class Finding:
    """One reported hit.

    ``evidence`` must always be text actually read from the file, never a
    reconstructed or inferred snippet.
    """

    rule_id: str
    severity: str
    category: str
    path: str
    line: int
    column: int = 1
    message: str = ""
    evidence: str = ""
    suggestion: str = ""
    confidence: str = "high"
    extra: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)
        if len(self.evidence) > 400:
            self.evidence = self.evidence[:397] + "..."

    @property
    def rank(self) -> int:
        return sev_rank(self.severity)

    def dedup_key(self) -> tuple:
        ev = " ".join((self.evidence or "").split())
        return (self.rule_id, self.path, self.line, ev[:160])

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "category": self.category,
            "file": self.path,
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "evidence": self.evidence,
            "suggestion": self.suggestion,
            "confidence": self.confidence,
        }
        if self.extra:
            data["extra"] = self.extra
        return data


@dataclass
class ScanResult:
    root: str
    mode: str
    findings: list = field(default_factory=list)
    scanned: list = field(default_factory=list)
    skipped: list = field(default_factory=list)
    capabilities: Dict[str, Any] = field(default_factory=dict)
    notes: list = field(default_factory=list)
    duration_ms: int = 0
    version: str = ""
    # Non-empty means the scan itself failed (bad git ref, unreadable rules...).
    # A failed scan must never be reported as SAFE.
    error: str = ""

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def counts(self) -> Dict[str, int]:
        out = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def category_counts(self) -> Dict[str, int]:
        out = {c: 0 for c in CATEGORIES}
        for f in self.findings:
            out[f.category] = out.get(f.category, 0) + 1
        return out

    def verdict(self) -> str:
        if self.error:
            return "ERROR"
        counts = self.counts()
        if counts.get("CRITICAL"):
            return "BLOCK"
        if counts.get("WARNING"):
            return "REVIEW"
        return "SAFE"

    def sorted_findings(self) -> list:
        return sorted(
            self.findings,
            key=lambda f: (-f.rank, f.category, f.path, f.line, f.rule_id),
        )
