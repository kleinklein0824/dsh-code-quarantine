"""Report renderers: text / json / markdown / sarif."""

from __future__ import annotations

import json
from typing import Dict, List

from .model import ScanResult

RESET = "\033[0m"
COLORS = {"CRITICAL": "\033[91m", "WARNING": "\033[93m", "INFO": "\033[96m", "DIM": "\033[90m"}


def _c(text: str, severity: str, color: bool) -> str:
    if not color:
        return text
    return COLORS.get(severity, "") + text + RESET


def render_text(result: ScanResult, color: bool = False) -> str:
    counts = result.counts()
    verdict = result.verdict()
    lines: List[str] = []
    lines.append("dsh-code-quarantine %s  |  mode=%s  |  %d files  |  %dms" % (
        result.version, result.mode, len(result.scanned), result.duration_ms))
    lines.append("target : %s" % result.root)
    if result.notes:
        for note in result.notes:
            lines.append("note   : %s" % note)
    caps = result.capabilities or {}
    if caps:
        lines.append("engine : ast=%s | lexical-only=%s" % (
            ",".join(caps.get("ast_available") or []) or "-",
            ",".join(caps.get("lexical_only") or []) or "-",
        ))
        ai = caps.get("llm")
        if ai:
            if ai.get("ready"):
                lines.append("ai     : model=%s calls=%d | 排除误报 %d | 补漏 %d%s" % (
                    ai.get("model") or "-", ai.get("calls", 0),
                    ai.get("suppressed", 0), ai.get("added", 0),
                    " | 命中缓存 %d" % ai["cached"] if ai.get("cached") else "",
                ))
            else:
                lines.append("ai     : 未启用（缺 base_url / model / api_key）")
    lines.append("")
    verdict_line = "VERDICT: %s   CRITICAL %d | WARNING %d | INFO %d" % (
        verdict, counts.get("CRITICAL", 0), counts.get("WARNING", 0), counts.get("INFO", 0))
    lines.append(_c(verdict_line, "CRITICAL" if verdict in ("BLOCK", "ERROR") else "WARNING", color))
    if result.error:
        lines.append(_c("ERROR: %s" % result.error, "CRITICAL", color))
    lines.append("")

    if not result.findings:
        lines.append("未发现问题。" if not result.error else "扫描未完成，未产生任何结论。")
        return "\n".join(lines)

    current = None
    for finding in result.sorted_findings():
        if finding.severity != current:
            current = finding.severity
            lines.append(_c("── %s ──" % current, current, color))
        lines.append("  %s  %s:%d:%d  [%s]" % (
            finding.rule_id, finding.path, finding.line, finding.column, finding.category))
        if finding.message:
            lines.append("    why      : %s" % finding.message)
        if finding.evidence:
            evidence = finding.evidence.replace("\n", " ⏎ ")
            if len(evidence) > 200:
                evidence = evidence[:197] + "..."
            lines.append("    evidence : %s" % evidence)
        if finding.suggestion:
            lines.append("    fix      : %s" % finding.suggestion)
        if finding.confidence != "high":
            lines.append("    confidence: %s" % finding.confidence)
    lines.append("")
    if result.skipped:
        reasons: Dict[str, int] = {}
        for _, reason in result.skipped:
            reasons[reason] = reasons.get(reason, 0) + 1
        summary = ", ".join("%s=%d" % (k, v) for k, v in sorted(reasons.items()))
        lines.append("skipped: %s" % summary)
    return "\n".join(lines)


def render_json(result: ScanResult) -> str:
    payload = {
        "tool": {"name": "dsh-code-quarantine", "version": result.version},
        "target": result.root,
        "mode": result.mode,
        "verdict": result.verdict(),
        "summary": {
            "severity": result.counts(),
            "category": result.category_counts(),
            "scanned_files": len(result.scanned),
            "skipped_files": len(result.skipped),
            "duration_ms": result.duration_ms,
        },
        "capabilities": result.capabilities,
        "notes": result.notes,
        "error": result.error or None,
        "findings": [f.to_dict() for f in result.sorted_findings()],
        "scanned": result.scanned,
        "skipped": [{"file": p, "reason": r} for p, r in result.skipped],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def render_markdown(result: ScanResult) -> str:
    counts = result.counts()
    verdict = result.verdict()
    icon = {"BLOCK": "🛑", "REVIEW": "⚠️", "SAFE": "✅", "ERROR": "💥"}.get(verdict, "")
    lines = [
        "# dsh-code-quarantine 报告",
        "",
        "- **判定**: %s %s" % (icon, verdict),
        "- **模式**: `%s`" % result.mode,
        "- **目标**: `%s`" % result.root,
        "- **扫描文件**: %d（跳过 %d）" % (len(result.scanned), len(result.skipped)),
        "- **统计**: CRITICAL %d / WARNING %d / INFO %d" % (
            counts.get("CRITICAL", 0), counts.get("WARNING", 0), counts.get("INFO", 0)),
        "",
    ]
    if result.error:
        lines.insert(4, "- **错误**: %s" % result.error)
    if not result.findings:
        lines.append("未发现问题。" if not result.error else "扫描未完成，未产生任何结论。")
        return "\n".join(lines)

    lines.append("| # | 级别 | 规则 | 位置 | 分类 | 说明 |")
    lines.append("|---|------|------|------|------|------|")
    for i, f in enumerate(result.sorted_findings(), 1):
        lines.append("| %d | %s | `%s` | `%s:%d` | %s | %s |" % (
            i, f.severity, f.rule_id, f.path, f.line, f.category,
            (f.message or "").replace("|", "\\|")))
    lines.append("")
    lines.append("## 详情")
    for i, f in enumerate(result.sorted_findings(), 1):
        lines.append("")
        lines.append("### %d. `%s` %s:%d" % (i, f.rule_id, f.path, f.line))
        if f.message:
            lines.append("- 原因: %s" % f.message)
        if f.evidence:
            lines.append("- 证据: `%s`" % f.evidence.replace("\n", " ")[:300])
        if f.suggestion:
            lines.append("- 修复: %s" % f.suggestion)
        lines.append("- 置信度: %s" % f.confidence)
    return "\n".join(lines)


def render_sarif(result: ScanResult) -> str:
    rules = {}
    results = []
    for f in result.sorted_findings():
        rules.setdefault(f.rule_id, {
            "id": f.rule_id,
            "name": f.rule_id,
            "shortDescription": {"text": f.message or f.rule_id},
            "help": {"text": f.suggestion or ""},
            "properties": {"category": f.category, "severity": f.severity},
        })
        results.append({
            "ruleId": f.rule_id,
            "level": {"CRITICAL": "error", "WARNING": "warning", "INFO": "note"}.get(f.severity, "warning"),
            "message": {"text": f.message or f.rule_id},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.path.replace("\\", "/")},
                    "region": {"startLine": max(1, f.line), "startColumn": max(1, f.column)},
                }
            }],
            "partialFingerprints": {"dshRuleLine": "%s:%s:%s" % (f.rule_id, f.path, f.line)},
        })
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "dsh-code-quarantine",
                "version": result.version,
                "informationUri": "https://github.com/dsh/dsh-code-quarantine",
                "rules": list(rules.values()),
            }},
            "results": results,
            "properties": {"verdict": result.verdict()},
        }],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def render(result: ScanResult, fmt: str, color: bool = False) -> str:
    fmt = (fmt or "text").lower()
    if fmt == "json":
        return render_json(result)
    if fmt == "md" or fmt == "markdown":
        return render_markdown(result)
    if fmt == "sarif":
        return render_sarif(result)
    return render_text(result, color=color)
