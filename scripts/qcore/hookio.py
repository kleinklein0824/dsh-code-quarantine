"""Shared plumbing for the hook entry points (PreToolUse / PostToolUse)."""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple

PANEL_INFO = ".dsh-quarantine-panel.json"
MAX_HOOK_BYTES = 2 * 1024 * 1024   # 单次写入内容上限，超出只告警不扫描


def notify_panel(root: str, payload: Dict) -> bool:
    """把拦截事件推给正在运行的控制面板；面板没开就静默跳过。

    绝不能因为推送失败影响 hook 本身的判定与退出码。
    """
    path = os.path.join(root, PANEL_INFO)
    if not os.path.isfile(path):
        return False
    try:
        with open(path, "r", encoding="utf-8") as fh:
            info = json.load(fh)
        if time.time() - float(info.get("started") or 0) > 86400:
            return False
        url = "http://127.0.0.1:%d/api/event" % int(info["port"])
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            url, data=body,
            headers={"Content-Type": "application/json", "X-Panel-Token": str(info.get("token") or "")},
        )
        urllib.request.urlopen(req, timeout=0.3).read()
        return True
    except urllib.error.URLError as exc:
        # 面板被强杀时信息文件会残留；连接被拒绝就顺手清掉，避免每次 hook 都白等
        if "refused" in str(getattr(exc, "reason", exc)).lower():
            try:
                os.unlink(path)
            except OSError:
                pass
        return False
    except Exception:
        return False


def read_payload(stream=None) -> Dict:
    stream = stream or sys.stdin
    raw = stream.read()
    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except ValueError:
        return {}


def _abs(path: str, cwd: str) -> str:
    return path if os.path.isabs(path) else os.path.join(cwd, path)


def extract_edits(payload: Dict) -> List[Tuple[str, str, str]]:
    """Return [(abs_path, text, kind)] where kind is write | fragment."""
    cwd = payload.get("cwd") or os.getcwd()
    tool = str(payload.get("tool_name") or "")
    data = payload.get("tool_input") or {}
    out: List[Tuple[str, str, str]] = []

    path = data.get("file_path") or data.get("path") or data.get("notebook_path")
    if not path:
        return out
    path = _abs(str(path), cwd)

    if isinstance(data.get("content"), str):
        out.append((path, data["content"], "write"))
    for key in ("new_string", "new_source", "new_str"):
        if isinstance(data.get(key), str):
            out.append((path, data[key], "fragment"))
    edits = data.get("edits")
    if isinstance(edits, list):
        for edit in edits:
            if isinstance(edit, dict) and isinstance(edit.get("new_string"), str):
                out.append((path, edit["new_string"], "fragment"))
    return out


def format_findings(result, limit: int = 6) -> str:
    counts = result.counts()
    lines = [
        "[dsh-code-quarantine] %s  CRITICAL %d | WARNING %d | INFO %d"
        % (result.verdict(), counts["CRITICAL"], counts["WARNING"], counts["INFO"])
    ]
    for finding in result.sorted_findings()[:limit]:
        lines.append(
            "- %s %s:%d [%s] %s" % (
                finding.severity, finding.path, finding.line, finding.rule_id, finding.message
            )
        )
        if finding.evidence:
            lines.append("    evidence: %s" % finding.evidence.replace("\n", " ")[:200])
        if finding.suggestion:
            lines.append("    fix: %s" % finding.suggestion)
    remaining = len(result.findings) - limit
    if remaining > 0:
        lines.append("- ... 另有 %d 条发现，运行 dsh-code-quarantine 查看完整报告" % remaining)
    return "\n".join(lines)


def emit_block(message: str, payload: Dict) -> int:
    """Exit code 2 + stderr is understood by Claude Code / WorkBuddy hooks."""
    print(message, file=sys.stderr)
    if payload.get("hook_event_name") == "PreToolUse":
        print(
            "请先修复上述 CRITICAL 问题，再重新写入该文件；"
            "如确认是误报，在项目根目录的 .dsh-quarantine-ignore 中按 rule_id + 路径登记豁免。",
            file=sys.stderr,
        )
    return 2


def filter_by_fragment(result, fragment: str):
    """Keep findings that sit on lines covered by the edited fragment."""
    if not fragment.strip():
        return result
    wanted = [line.strip() for line in fragment.split("\n") if line.strip()]
    if not wanted:
        return result
    first, last = wanted[0], wanted[-1]
    keep = []
    for finding in result.findings:
        evidence = (finding.evidence or "").strip()
        if evidence and any(evidence.startswith(w[:40]) or w[:40] in evidence for w in wanted):
            keep.append(finding)
    result.findings = keep
    return result


def load_config_for(path: str, rules_dir: str, cwd: Optional[str] = None):
    from qcore.config import Config

    root = os.path.dirname(os.path.abspath(path))
    found = False
    cur = root
    for _ in range(8):
        if os.path.isfile(os.path.join(cur, ".dsh-quarantine.yml")) or os.path.isfile(
            os.path.join(cur, ".dsh-quarantine-ignore")
        ):
            root = cur
            found = True
            break
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    if not found and cwd:
        cwd_abs = os.path.abspath(cwd)
        if os.path.abspath(path).startswith(cwd_abs + os.sep):
            root = cwd_abs
    return Config(rules_dir, root)


def rel_for(path: str, cfg) -> str:
    try:
        return os.path.relpath(path, cfg.project_root).replace("\\", "/")
    except ValueError:
        return os.path.basename(path)
