#!/usr/bin/env python3
"""PostToolUse hook: audit what was just written (fallback for Bash / MCP edits).

The file already exists on disk at this point, so this hook cannot block the
write; it exits 2 so the host feeds the findings back to the agent, which then
has to fix them in the next turn.

Exit codes: 0 nothing to report, 2 findings that must be addressed.
"""

from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_ROOT = os.path.dirname(HERE)
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from qcore import hookio  # noqa: E402
from qcore.lexer import detect_language  # noqa: E402
from qcore.scan import scan_text  # noqa: E402

RULES = os.environ.get("DSH_QUARANTINE_RULES", os.path.join(SKILL_ROOT, "rules"))


def main() -> int:
    # 某些宿主以 pythonw 启动 hook，此时 sys.stdout/stderr 为 None
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    payload = hookio.read_payload()
    data = payload.get("tool_input") or {}
    cwd = payload.get("cwd") or os.getcwd()
    raw_path = data.get("file_path") or data.get("path")
    if not raw_path:
        return 0
    path = raw_path if os.path.isabs(str(raw_path)) else os.path.join(cwd, str(raw_path))
    if not os.path.isfile(path):
        return 0
    if detect_language(path) == "unknown":
        return 0

    try:
        if os.path.getsize(path) > hookio.MAX_HOOK_BYTES:
            print("[dsh-code-quarantine] 文件超过 %d 字节，跳过本次检查" % hookio.MAX_HOOK_BYTES,
                  file=sys.stderr)
            return 0
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return 0

    cfg = hookio.load_config_for(path, RULES, cwd)
    rel = hookio.rel_for(path, cfg)
    result = scan_text(text, rel, cfg)

    fragment = data.get("new_string") or data.get("content")
    if isinstance(fragment, str) and fragment.strip():
        result = hookio.filter_by_fragment(result, fragment)

    counts = result.counts()
    if not (counts["CRITICAL"] or counts["WARNING"]):
        return 0
    hookio.notify_panel(cfg.project_root, {
        "type": "post-write",
        "tool": str(payload.get("tool_name") or ""),
        "file": rel,
        "verdict": result.verdict(),
        "counts": counts,
        "findings": [f.to_dict() for f in result.sorted_findings()[:8]],
    })
    if not counts["CRITICAL"]:
        # The file already landed and nothing is blocking, so stderr would only be
        # rendered by the host as a red `Error:` on a tool call that in fact
        # succeeded. The WARNING reaches the card through `notify_panel` instead.
        return 0
    print(hookio.format_findings(result), file=sys.stderr)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as exc:  # hook 自身出错时放行，避免卡死用户的工作流
        print("[dsh-code-quarantine] hook 内部错误，本次放行：%s" % exc, file=sys.stderr)
        sys.exit(0)
