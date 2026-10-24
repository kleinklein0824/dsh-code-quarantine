#!/usr/bin/env python3
"""PreToolUse hook: gate the write before it lands on disk.

Reads the Claude Code / WorkBuddy hook payload from stdin, scans the content
that is about to be written, and exits 2 (blocking the tool call) when a
CRITICAL finding is present. WARNING is reported to stderr but allowed.

Exit codes: 0 allow, 2 block.
"""

from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_ROOT = os.path.dirname(HERE)
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from qcore import hookio  # noqa: E402
from qcore.scan import scan_text  # noqa: E402

RULES = os.environ.get("DSH_QUARANTINE_RULES", os.path.join(SKILL_ROOT, "rules"))
BLOCK_ON = os.environ.get("DSH_QUARANTINE_BLOCK_ON", "critical").lower()


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
    edits = hookio.extract_edits(payload)
    if not edits:
        return 0

    worst = 0
    messages = []
    saw_critical = False
    for path, text, kind in edits:
        if not text.strip():
            continue
        if len(text) > hookio.MAX_HOOK_BYTES:
            print("[dsh-code-quarantine] 内容超过 %d 字节，跳过本次检查（请单独跑 CLI）"
                  % hookio.MAX_HOOK_BYTES, file=sys.stderr)
            continue
        cfg = hookio.load_config_for(path, RULES, payload.get("cwd"))
        rel = hookio.rel_for(path, cfg)
        result = scan_text(text, rel, cfg)
        if result.error:
            # 规则没加载全 = 这次判断不成立。按既有策略放行，但必须说清楚，
            # 否则用户会以为"没报错就是没问题"。
            print("[dsh-code-quarantine] 检查未完成，本次放行：%s" % result.error, file=sys.stderr)
            continue
        if kind == "fragment":
            result = hookio.filter_by_fragment(result, text)
        counts = result.counts()
        if counts["CRITICAL"] or counts["WARNING"]:
            messages.append(hookio.format_findings(result))
            event = {
                "type": "pre-write",
                "tool": str(payload.get("tool_name") or ""),
                "file": rel,
                "verdict": result.verdict(),
                "counts": counts,
                "findings": [f.to_dict() for f in result.sorted_findings()[:8]],
            }
            # 推给控制面板：用户开着面板时能立刻看到"刚才这一笔被拦了"
            hookio.notify_panel(cfg.project_root, event)
            # 再写一份给包装层（DSH 插件）：它要的是计数，不是给人看的报告，
            # 走文件而不是 stderr，这样放行时屏幕上是干净的。
            hookio.write_report(event)
        if counts["CRITICAL"]:
            worst = 2
            saw_critical = True
        elif counts["WARNING"] and BLOCK_ON == "warning":
            worst = max(worst, 2)

    # Only speak when actually blocking. Hosts render *any* non-empty stderr from a
    # hook as a red `Error:` in the transcript, so reporting an allowed WARNING there
    # makes a normal write look like a failed one and sends the user hunting for a
    # problem that does not exist. The WARNING is already delivered to the card via
    # `notify_panel` — an amber icon is what "seen but not blocked" should look like.
    if worst == 2 and messages:
        print("\n\n".join(messages), file=sys.stderr)
        if BLOCK_ON == "warning" and not saw_critical:
            # 被拦的原因只是阈值，不是危险等级；不说清楚用户会以为这段代码真有毒。
            print(
                "[dsh-code-quarantine] 拦截级别被设为「CRITICAL + WARNING」：本条只有 WARNING 命中，"
                "按该级别同样被拦。把级别改回「仅 CRITICAL」即可放行这类改动。",
                file=sys.stderr,
            )
    return worst


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as exc:  # hook 自身出错时放行，避免卡死用户的工作流
        print("[dsh-code-quarantine] hook 内部错误，本次放行：%s" % exc, file=sys.stderr)
        sys.exit(0)
