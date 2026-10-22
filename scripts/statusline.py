#!/usr/bin/env python3
"""状态栏一行摘要：常驻显示最近一次扫描的判定。

设计成"绝不拖慢界面"：只读 .dsh-quarantine-last.json，不跑扫描。
任何异常都退化成一行占位文本，不让状态栏崩掉。

    python scripts/statusline.py --target .
    👁 BLOCK · 8C/16W · 13 文件 · 2m 前

图标默认 👁，用 --icon hiero 换成 𓂀（荷鲁斯之眼象形文字，取决于字体是否支持）。
"""

from __future__ import annotations

import argparse
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

ICONS = {"eye": "👁", "hiero": "𓂀", "plain": ""}


def _fmt_age(epoch: float) -> str:
    delta = max(0.0, time.time() - float(epoch or 0))
    if delta < 60:
        return "刚刚"
    if delta < 3600:
        return "%dm 前" % int(delta // 60)
    if delta < 86400:
        return "%dh 前" % int(delta // 3600)
    return "%dd 前" % int(delta // 86400)


def _find_target(start: str) -> str:
    """从 start 向上找带缓存文件的项目根，最多 6 层。"""
    cur = os.path.abspath(start)
    for _ in range(6):
        if os.path.isfile(os.path.join(cur, ".dsh-quarantine-last.json")):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return os.path.abspath(start)


def main(argv=None) -> int:
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

    parser = argparse.ArgumentParser(prog="statusline", description="dsh-code-quarantine 状态栏摘要")
    parser.add_argument("--target", default=os.environ.get("DSH_QUARANTINE_TARGET") or os.getcwd())
    parser.add_argument("--icon", default=os.environ.get("DSH_QUARANTINE_ICON", "eye"),
                        choices=sorted(ICONS))
    parser.add_argument("--label", default="dsh", help="无结果时的占位名")
    args = parser.parse_args(argv)

    icon = ICONS.get(args.icon, "👁")
    prefix = (icon + " ") if icon else ""

    try:
        from qcore.cache import load_summary

        data = load_summary(_find_target(args.target))
    except Exception:
        data = None

    if not data:
        print("%s%s · 未扫描" % (prefix, args.label))
        return 0

    counts = data.get("counts") or {}
    verdict = str(data.get("verdict") or "SAFE")
    parts = [
        "%s%s" % (prefix, verdict),
        "%dC/%dW" % (counts.get("CRITICAL", 0), counts.get("WARNING", 0)),
        "%d 文件" % int(data.get("files") or 0),
        _fmt_age(data.get("epoch") or 0),
    ]
    print(" · ".join(parts))
    return 0


if __name__ == "__main__":
    sys.exit(main())
