"""修复历史（append-only）。

面板和卡片都能「一键修复」一行代码，但改完只剩一句 toast。用户回头想知道
「上次那条 CRITICAL 是谁改的、改成了什么、改完还剩几条、备份在哪」时，
没有任何地方可查——备份目录里只有旧内容，没有原因与结果。

这里把每次写入追加成一行 JSON。用 JSON Lines 而不是一个 JSON 数组：
追加只要 O(1) 打开文件写一行，数组方案每次都要读出全部、改、再整体写回，
修一次代码要重写整个历史；而且单行 append 中途崩溃最多丢最后一行，
数组方案崩溃会毁掉全部记录。
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional

HISTORY_NAME = ".dsh-quarantine-history.jsonl"
# 保留的条数上限。历史是给"溯源最近几次改动"用的，不是审计存档；
# 无上限增长的文件迟早会变成没人清理的垃圾。
MAX_ENTRIES = 500


def history_path(root: str) -> str:
    return os.path.join(root, HISTORY_NAME)


def append(root: str, entry: Dict[str, Any]) -> Optional[str]:
    """追加一条记录。返回文件路径；写失败返回 None（历史不是主流程）。"""
    path = history_path(root)
    record = dict(entry)
    now = time.time()
    record.setdefault("ts", now)
    record.setdefault("iso", time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now)))
    record.setdefault("clock", time.strftime("%H:%M:%S", time.localtime(now)))
    try:
        with open(path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        return None
    _trim(root)
    return path


def load(root: str, limit: int = 50) -> List[Dict[str, Any]]:
    """最近的在前。坏行跳过——一行写坏不该让整段历史读不出来。"""
    path = history_path(root)
    if not os.path.isfile(path):
        return []
    entries: List[Dict[str, Any]] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except ValueError:
                    continue
                if isinstance(item, dict):
                    entries.append(item)
    except OSError:
        return []
    entries.reverse()
    if limit and limit > 0:
        entries = entries[:limit]
    return entries


def count(root: str) -> int:
    path = history_path(root)
    if not os.path.isfile(path):
        return 0
    total = 0
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.strip():
                    total += 1
    except OSError:
        return 0
    return total


def _trim(root: str, keep: int = MAX_ENTRIES) -> None:
    """超过上限时只保留最近 keep 条。失败就下次再说，不影响写入。"""
    path = history_path(root)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = [line for line in fh if line.strip()]
    except OSError:
        return
    if len(lines) <= keep:
        return
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            fh.writelines(lines[-keep:])
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
