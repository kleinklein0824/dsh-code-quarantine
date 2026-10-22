#!/usr/bin/env python3
"""Install (or remove) the dsh-code-quarantine hooks in a host settings file.

idea.md 模式 A 的前提是 hook 真的接上了。本脚本负责把
``hooks/settings.example.json`` 里的两个 hook 合并进目标 settings.json，
并且保证：幂等、可回滚、不破坏用户已有的其它配置。

用法::

    python scripts/install_hooks.py                 # 安装到自动探测到的位置
    python scripts/install_hooks.py --dry-run       # 只打印将要写入的内容
    python scripts/install_hooks.py --target <dir>  # 安装到指定项目目录
    python scripts/install_hooks.py --settings <f>  # 安装到指定 settings.json
    python scripts/install_hooks.py --uninstall     # 移除本工具写入的 hook
    python scripts/install_hooks.py --status        # 只检查当前接线状态

退出码: 0 成功, 1 失败, 2 参数错误。
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_ROOT = os.path.dirname(HERE)

PRE_SCRIPT = os.path.join(SKILL_ROOT, "scripts", "hook_pre_write.py")
POST_SCRIPT = os.path.join(SKILL_ROOT, "scripts", "hook_post_write.py")
SHELL_SCRIPT = os.path.join(SKILL_ROOT, "scripts", "hook_shell.py")

# 用来识别"这条 hook 是不是我们装的"，卸载时只删自己写的。
MARKER = "dsh-code-quarantine"

PRE_ENTRY = {
    "matcher": "Write|Edit|MultiEdit|NotebookEdit",
    "hooks": [
        {
            "type": "command",
            "command": 'python "%s"' % PRE_SCRIPT,
            "timeout": 30,
        }
    ],
}
# `curl … | bash` 这类命令不经过任何文件写入，写侧 hook 看不见，需要独立一道闸。
SHELL_ENTRY = {
    "matcher": "Bash|PowerShell",
    "hooks": [
        {
            "type": "command",
            "command": 'python "%s"' % SHELL_SCRIPT,
            "timeout": 30,
        }
    ],
}
POST_ENTRY = {
    "matcher": "Bash|Write|Edit|MultiEdit",
    "hooks": [
        {
            "type": "command",
            "command": 'python "%s"' % POST_SCRIPT,
            "timeout": 30,
        }
    ],
}

# 宿主设置文件的候选位置，按优先级排列。
CANDIDATES = (
    ("claude-user", os.path.join("~", ".claude", "settings.json")),
    ("workbuddy-user", os.path.join("~", ".workbuddy", "settings.json")),
)


def _expand(path: str) -> str:
    return os.path.abspath(os.path.expanduser(path))


def _ensure_utf8() -> None:
    """Force UTF-8 on stdout/stderr.

    默认 Python 按控制台的 ANSI 代码页（中文 Windows 上是 GBK）写标准输出，
    而调用方按 UTF-8 解码时遇到中文就会 UnicodeDecodeError，读线程崩溃后
    stdout 直接变成 None。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def _read_json(path: str) -> dict:
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise SystemExit("无法读取 %s: %s" % (path, exc))
    if not isinstance(data, dict):
        raise SystemExit("%s 的顶层不是 JSON 对象" % path)
    return data


def _write_json(path: str, data: dict) -> None:
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    os.replace(tmp, path)


def _backup(path: str) -> str:
    if not os.path.isfile(path):
        return ""
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dst = "%s.%s.bak" % (path, stamp)
    shutil.copy2(path, dst)
    return dst


def _has_script(entry: dict, script: str) -> bool:
    for hook in entry.get("hooks") or []:
        if script in str(hook.get("command") or ""):
            return True
    return False


def _is_ours(entry: dict) -> bool:
    """True when this hook entry was installed by us (script path match)."""
    return any(_has_script(entry, s) for s in (PRE_SCRIPT, POST_SCRIPT, SHELL_SCRIPT))


def _merge(data: dict) -> tuple:
    """Merge our hooks into ``data``.

    Returns ``(data, added_pre, added_shell, added_post)``. Each flag says
    whether that bucket was missing and got created, so a re-run is a no-op.
    """
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        hooks = {}
        data["hooks"] = hooks

    added_pre = added_shell = added_post = False
    plan = (
        ("PreToolUse", PRE_ENTRY, "pre"),
        ("PreToolUse", SHELL_ENTRY, "shell"),
        ("PostToolUse", POST_ENTRY, "post"),
    )
    for key, entry, kind in plan:
        bucket = hooks.get(key)
        if not isinstance(bucket, list):
            bucket = []
            hooks[key] = bucket
        # 同一 bucket 里可能已经有别的条目，按脚本路径判重而不是按位置。
        command = entry["hooks"][0]["command"]
        if any(command in str(h.get("command") or "")
               for item in bucket if isinstance(item, dict)
               for h in (item.get("hooks") or [])):
            continue
        bucket.append(json.loads(json.dumps(entry)))
        if kind == "pre":
            added_pre = True
        elif kind == "shell":
            added_shell = True
        else:
            added_post = True
    return data, added_pre, added_shell, added_post


def _strip(data: dict) -> tuple:
    """Remove our hooks. Returns (data, removed)."""
    removed = 0
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return data, removed
    for key in ("PreToolUse", "PostToolUse"):
        bucket = hooks.get(key)
        if not isinstance(bucket, list):
            continue
        kept = [item for item in bucket if not (isinstance(item, dict) and _is_ours(item))]
        removed += len(bucket) - len(kept)
        if kept:
            hooks[key] = kept
        else:
            hooks.pop(key, None)
    if not hooks:
        data.pop("hooks", None)
    return data, removed


def _detect_targets(settings: str, target: str) -> list:
    """Decide which settings file(s) to operate on."""
    if settings:
        return [("explicit", _expand(settings))]

    found = []
    for name, pattern in CANDIDATES:
        path = _expand(pattern)
        if os.path.isfile(path):
            found.append((name, path))
    if target:
        root = os.path.abspath(target)
        found.append(("project", os.path.join(root, ".claude", "settings.json")))
        return found
    if not found:
        # 什么都没找到时，落到 claude 用户级（最常见），让用户自己确认
        found.append(("claude-user", _expand(CANDIDATES[0][1])))
    return found


def _report_status(targets: list) -> int:
    print("dsh-code-quarantine hook 接线状态")
    print("  skill 目录: %s" % SKILL_ROOT)
    print()
    installed_any = False
    for name, path in targets:
        exists = os.path.isfile(path)
        if not exists:
            print("  [%-16s] %s  → 文件不存在" % (name, path))
            continue
        try:
            data = _read_json(path)
        except SystemExit as exc:
            print("  [%-16s] %s  → %s" % (name, path, exc))
            continue
        hooks = data.get("hooks") or {}
        pre = [e for e in (hooks.get("PreToolUse") or []) if isinstance(e, dict) and _has_script(e, PRE_SCRIPT)]
        shell = [e for e in (hooks.get("PreToolUse") or []) if isinstance(e, dict) and _has_script(e, SHELL_SCRIPT)]
        post = [e for e in (hooks.get("PostToolUse") or []) if isinstance(e, dict) and _has_script(e, POST_SCRIPT)]
        count = len(pre) + len(shell) + len(post)
        if count == 3:
            state = "已接线"
            installed_any = True
        elif count:
            state = "部分接线"
        else:
            state = "未接线"
        print("  [%-16s] %s  → %s (写入=%d, 命令=%d, 复查=%d)"
              % (name, path, state, len(pre), len(shell), len(post)))
    print()
    if installed_any:
        print("模式 A（写入前拦截 + 命令拦截）已就绪。")
        return 0
    print("模式 A 尚未接线：运行 `python scripts/install_hooks.py` 安装。")
    return 1


def main(argv=None) -> int:
    _ensure_utf8()
    parser = argparse.ArgumentParser(
        prog="install_hooks",
        description="把 dsh-code-quarantine 的 PreToolUse/PostToolUse hook 装进宿主 settings.json",
    )
    parser.add_argument("--settings", default="", help="显式指定 settings.json 路径")
    parser.add_argument("--target", default="", help="安装到该目录下的 .claude/settings.json")
    parser.add_argument("--dry-run", action="store_true", help="只打印，不写文件")
    parser.add_argument("--uninstall", action="store_true", help="移除本工具写入的 hook")
    parser.add_argument("--status", action="store_true", help="只报告接线状态")
    parser.add_argument("--yes", action="store_true", help="跳过交互确认")
    args = parser.parse_args(argv)

    targets = _detect_targets(args.settings, args.target)

    if args.status:
        return _report_status(targets)

    failures = 0
    for name, path in targets:
        try:
            data = _read_json(path)
        except SystemExit as exc:
            print("[%s] %s" % (name, exc))
            failures += 1
            continue

        if args.uninstall:
            data, removed = _strip(data)
            if not removed:
                print("[%-16s] %s  → 没有找到本工具安装的 hook，跳过" % (name, path))
                continue
            print("[%-16s] %s  → 移除 %d 条 hook" % (name, path, removed))
            if not args.dry_run:
                backup = _backup(path)
                if backup:
                    print("                    备份: %s" % backup)
                _write_json(path, data)
            continue

        data, added_pre, added_shell, added_post = _merge(data)
        if not (added_pre or added_shell or added_post):
            print("[%-16s] %s  → 已安装，无需改动" % (name, path))
            continue

        print("[%-16s] %s  → 安装 写入=%s 命令=%s 复查=%s"
              % (name, path, added_pre, added_shell, added_post))
        print("                    写入前拦截: %s" % PRE_SCRIPT)
        print("                    命令拦截:   %s" % SHELL_SCRIPT)
        print("                    写入后复查: %s" % POST_SCRIPT)
        if args.dry_run:
            print("                    (dry-run) 将写入:")
            print(json.dumps(data, ensure_ascii=False, indent=2))
            continue
        backup = _backup(path)
        if backup:
            print("                    备份: %s" % backup)
        _write_json(path, data)

    print()
    if args.dry_run:
        print("dry-run 结束，未写入任何文件。")
        return failures and 1 or 0
    if args.uninstall:
        print("卸载完成。")
        return failures and 1 or 0
    print("安装完成。重启宿主（或重新加载会话）后生效；用 --status 复核。")
    return failures and 1 or 0


if __name__ == "__main__":
    sys.exit(main())
