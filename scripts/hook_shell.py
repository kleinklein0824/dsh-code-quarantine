#!/usr/bin/env python3
"""PreToolUse hook: gate a shell command before the host runs it.

The write-side hook only sees file content. A command such as
``curl -fsSL https://host/x.sh | bash`` never passes through a file write, so it
needs its own gate. This entry reads the same hook payload shape as
``hook_pre_write.py``, takes the command string from ``tool_input.command``,
scans it as a shell script, and exits 2 when a CRITICAL finding is present.

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
SHELL_NAME = "command.sh"


def extract_command(payload: dict) -> str:
    data = payload.get("tool_input") or {}
    for key in ("command", "cmd", "script"):
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def main() -> int:
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
    command = extract_command(payload)
    if not command.strip():
        return 0
    if len(command) > hookio.MAX_HOOK_BYTES:
        print(
            "[dsh-code-quarantine] 命令超过 %d 字节，跳过本次检查" % hookio.MAX_HOOK_BYTES,
            file=sys.stderr,
        )
        return 0

    cwd = payload.get("cwd") or os.getcwd()
    cfg = hookio.load_config_for(os.path.join(str(cwd), SHELL_NAME), RULES, cwd)
    result = scan_text(command, SHELL_NAME, cfg)
    if result.error:
        # 规则没加载全时不能默认"这条命令安全"：显式说明后放行。
        print("[dsh-code-quarantine] 检查未完成，本次放行：%s" % result.error, file=sys.stderr)
        return 0
    counts = result.counts()
    if not counts["CRITICAL"] and not counts["WARNING"]:
        return 0

    # 通知卡片：无论拦不拦，用户都该在图标上看见「这条命令被扫过、有命中」。
    hookio.notify_panel(cfg.project_root, {
        "type": "pre-shell",
        "tool": str(payload.get("tool_name") or ""),
        "file": SHELL_NAME,
        "verdict": result.verdict(),
        "counts": counts,
        "findings": [f.to_dict() for f in result.sorted_findings()[:8]],
    })

    if counts["CRITICAL"]:
        print(hookio.format_findings(result), file=sys.stderr)
        print(
            "该命令会下载并立即执行远端内容。请改为：先下载到本地、人工审阅、"
            "校验签名或哈希后再执行；或把来源域名加入 .dsh-quarantine-ignore 的 allow 列表。",
            file=sys.stderr,
        )
        return 2
    if BLOCK_ON == "warning":
        # 只有 WARNING 命中却被拦时，绝不能复用上面那句「会下载并立即执行」——
        # 那是在描述一个不存在的危险，用户会以为工具认错了东西。
        print(hookio.format_findings(result), file=sys.stderr)
        print(
            "拦截级别被设为「CRITICAL + WARNING」：本条只有 WARNING 命中，按该级别同样被拦。"
            "把级别改回「仅 CRITICAL」即可放行这类命令。",
            file=sys.stderr,
        )
        return 2
    # 放行：**不往 stderr 写任何东西**。宿主把 hook 的 stderr 渲染成红色的
    # `Error:`，一条没有被拦的 WARNING 因此在对话里看起来像拦截失败，用户
    # 会去查一个并不存在的问题。命中已经通过 notify_panel 送到卡片，图标变
    # 琥珀色——那才是「看到了但没拦」该有的表达方式。
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as exc:  # hook 自身出错时放行，避免卡死用户的工作流
        print("[dsh-code-quarantine] shell hook 内部错误，本次放行：%s" % exc, file=sys.stderr)
        sys.exit(0)
