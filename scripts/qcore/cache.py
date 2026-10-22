"""扫描结果摘要缓存。

状态栏 / 徽标要"秒开"，不能每次都跑一遍全量扫描，所以每次扫描结束把
判定与计数落一个小文件，状态栏只读它。
"""

from __future__ import annotations

import json
import os
import time
from typing import Optional

CACHE_NAME = ".dsh-quarantine-last.json"


def cache_path(root: str) -> str:
    return os.path.join(root, CACHE_NAME)


def save_summary(root: str, result) -> Optional[str]:
    counts = result.counts()
    payload = {
        "verdict": result.verdict(),
        "counts": counts,
        "category": result.category_counts(),
        "files": len(result.scanned),
        "mode": result.mode,
        "epoch": time.time(),
        "iso": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "version": result.version,
        "top": [
            {"rule_id": f.rule_id, "file": f.path, "line": f.line, "severity": f.severity}
            for f in result.sorted_findings()[:5]
        ],
    }
    path = cache_path(root)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        return path
    except OSError:
        return None


def load_summary(root: str) -> Optional[dict]:
    path = cache_path(root)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None
