#!/usr/bin/env python3
"""面板能力桥：把 ``panel_server.Panel`` 暴露成 stdin/stdout 上的 JSON 调用。

DeepSeek-Harness 插件的卡片要复刻浏览器面板的六个标签页（扫描 / 规则 / 白名单 /
豁免 / AI / 修复历史）。那些能力已经在 ``panel_server.Panel`` 里实现过一遍了，复制到
JavaScript 里意味着两份判定逻辑会慢慢分叉——面板里关掉的规则，卡片里还在报。

所以卡片不重新实现任何东西：它把请求交给这个脚本，脚本转给同一个 ``Panel``
对象。命令行面板、浏览器面板、Harness 卡片三条入口因此共用同一套读写实现。

用法（由插件调用，不面向人）：:

    echo '{"method":"state","target":"D:/proj"}' | python scripts/panel_bridge.py

输出永远是单行 JSON：``{"ok": true, "data": ...}`` 或
``{"ok": false, "error": "..."}``。错误写进 JSON 而不是抛栈，因为调用方是插件，
它要的是能给用户看的一句话，不是 traceback。
"""

from __future__ import annotations

import json
import os
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from panel_server import DEFAULT_RULES, Panel  # noqa: E402

MAX_INPUT_BYTES = 4 * 1024 * 1024


def _ensure_utf8() -> None:
    """Force UTF-8 on stdout.

    Python writes to the console code page by default (GBK on a Chinese Windows),
    and the plugin reads the pipe as UTF-8. A single Chinese message would turn
    into a decode error on the other side and look like "the bridge is broken".
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def _dispatch(panel: Panel, method: str, args: dict, target: str):
    """Route one call to the panel object. Unknown methods are an error, not a no-op."""
    if method == "state":
        return panel.state(target)
    if method == "save":
        return panel.save(dict(args, target=target))
    if method == "scan":
        return panel.scan(dict(args, target=target))
    if method == "baseline":
        return panel.write_baseline(target)
    if method == "reveal":
        return panel.reveal(str(args.get("file") or ""), int(args.get("line") or 1), target)
    if method == "ignore":
        return panel.add_ignore(str(args.get("rule_id") or "*"), str(args.get("path") or ""), target)
    if method == "llm-test":
        return panel.llm_test(dict(args, target=target))
    if method == "line-read":
        return panel.read_line(
            str(args.get("file") or ""),
            int(args.get("line") or 1),
            int(args.get("context") or 3),
            target,
        )
    if method == "line-write":
        return panel.write_line(
            str(args.get("file") or ""),
            int(args.get("line") or 1),
            str(args.get("text") or ""),
            target,
            {"rule_id": args.get("rule_id"), "source": args.get("source") or "card"},
        )
    if method == "history":
        return panel.read_history(
            target,
            int(args.get("limit") or 50),
            verify=bool(args.get("verify")),
        )
    if method == "fix-prompt":
        return panel.fix_prompt(args, target)
    if method == "events":
        return panel.events_list()
    raise ValueError("未知的桥方法: %s" % method)


def main() -> int:
    _ensure_utf8()
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES)
    try:
        payload = json.loads(raw.decode("utf-8") or "{}")
    except (UnicodeDecodeError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": "请求不是合法 JSON: %s" % exc}))
        return 2
    method = str(payload.get("method") or "")
    args = payload.get("args") if isinstance(payload.get("args"), dict) else {}
    target = str(payload.get("target") or args.get("target") or os.getcwd())
    try:
        panel = Panel(target, DEFAULT_RULES)
        data = _dispatch(panel, method, args, target)
        print(json.dumps({"ok": True, "data": data}, ensure_ascii=False))
        return 0
    except Exception as exc:  # noqa: BLE001 - 任何失败都要变成一句话给 UI
        # The stack goes to stderr for debugging; the caller only reads stdout,
        # which must stay valid JSON so the card can show the reason.
        traceback.print_exc()
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    sys.exit(main())
