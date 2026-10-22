"""Finding construction helpers shared by all rule layers."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .model import Finding


def make(
    cfg,
    rule_id: str,
    source,
    rel_path: str,
    offset: int,
    message: Optional[str] = None,
    evidence: Optional[str] = None,
    severity: Optional[str] = None,
    confidence: str = "high",
    extra: Optional[Dict[str, Any]] = None,
) -> Finding:
    line = source.line_of(max(0, offset)) if offset >= 0 else 1
    column = source.col_of(max(0, offset)) if offset >= 0 else 1
    if evidence is None:
        evidence = source.line_text(line).strip()
    return Finding(
        rule_id=rule_id,
        severity=severity or cfg.severity(rule_id),
        category=cfg.category(rule_id),
        path=rel_path,
        line=line,
        column=column,
        message=message or cfg.message(rule_id),
        evidence=(evidence or "").strip(),
        suggestion=cfg.suggestion(rule_id),
        confidence=confidence,
        extra=extra or {},
    )


def dedupe(findings: List[Finding]) -> List[Finding]:
    seen = set()
    out = []
    for f in findings:
        key = f.dedup_key()
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out
