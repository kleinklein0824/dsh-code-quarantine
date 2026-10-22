"""Regression: false-positive noise on 8 real third-party libraries.

Guards idea.md's core principle "宁可漏报，不可误报": CRITICAL must stay at
zero on mainstream library code, and the WARNING/INFO noise must not regress.
"""

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CLI = os.path.join(ROOT, "scripts", "quarantine.py")

# Where the third-party packages live. Defaults to a site-packages directory on
# this interpreter's path that actually contains the packages below, so the
# script is portable; override with DSH_QUARANTINE_SITE to point elsewhere.
_PACKAGES = (
    "starlette",
    "pydantic",
    "fastapi",
    "rich",
    "sqlalchemy",
    "click",
    "httpx",
    "anyio",
)


def _find_site():
    candidates = [path for path in sys.path if path.endswith("site-packages") and os.path.isdir(path)]
    for path in candidates:
        if any(os.path.isdir(os.path.join(path, pkg)) for pkg in _PACKAGES):
            return path
    return candidates[0] if candidates else ""


BASE = os.environ.get("DSH_QUARANTINE_SITE") or _find_site()
PACKAGES = _PACKAGES

# 基线：CRITICAL 必须为 0；WARNING/INFO 不得超过这里的上限
# 2026-10 治理后实测 WARNING 36 / INFO 106，这里留 6 条余量锁住不回退。
CEILING = {
    "critical": 0,
    "warning": 42,
    "info": 120,
}


def run_package(pkg):
    target = os.path.join(BASE, pkg)
    if not os.path.isdir(target):
        return None
    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.run(
        [sys.executable, CLI, target, "--full", "--format", "json", "--no-ignore"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        timeout=900,
    )
    try:
        data = json.loads(proc.stdout)
    except ValueError:
        raise SystemExit("%s: 无法解析 JSON 输出\nstdout=%r\nstderr=%r"
                         % (pkg, proc.stdout[:2000], proc.stderr[:2000]))
    summary = data["summary"]
    return {
        "pkg": pkg,
        "verdict": data["verdict"],
        "files": summary["scanned_files"],
        "CRITICAL": summary["severity"]["CRITICAL"],
        "WARNING": summary["severity"]["WARNING"],
        "INFO": summary["severity"]["INFO"],
        "findings": data["findings"],
        "rc": proc.returncode,
    }


def _ensure_utf8() -> None:
    """Force UTF-8 on stdout/stderr.

    Windows 控制台默认按 ANSI 代码页（中文系统是 GBK）编码，报告里的 emoji
    （👁、✅）直接抛 UnicodeEncodeError；按 UTF-8 读管道的调用方也会解码失败。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def main():
    _ensure_utf8()
    if not BASE or not os.path.isdir(BASE):
        print("未找到 site-packages；设置 DSH_QUARANTINE_SITE 指向一个已安装这些包的目录。")
        return 0
    rows = []
    missing = []
    for pkg in PACKAGES:
        result = run_package(pkg)
        if result is None:
            missing.append(pkg)
            continue
        rows.append(result)

    if missing:
        print("跳过（未安装）: %s" % ", ".join(missing))

    print()
    print("%-12s %-8s %6s %9s %8s %6s" % ("pkg", "verdict", "files", "CRITICAL", "WARNING", "INFO"))
    print("-" * 58)
    total = {"CRITICAL": 0, "WARNING": 0, "INFO": 0, "files": 0}
    for row in rows:
        print("%-12s %-8s %6d %9d %8d %6d" % (
            row["pkg"], row["verdict"], row["files"],
            row["CRITICAL"], row["WARNING"], row["INFO"]))
        for key in total:
            total[key] += row[key]
    print("-" * 58)
    print("%-12s %-8s %6d %9d %8d %6d" % (
        "TOTAL", "", total["files"], total["CRITICAL"], total["WARNING"], total["INFO"]))

    print()
    print("== 剩余 WARNING 明细 ==")
    for row in rows:
        warns = [f for f in row["findings"] if f["severity"] == "WARNING"]
        if not warns:
            continue
        print("\n[%s] %d 条" % (row["pkg"], len(warns)))
        for finding in warns[:40]:
            print("  %-6s %s:%d  %s" % (
                finding["rule_id"], finding["file"], finding["line"], finding["message"][:110]))

    failures = []
    if total["CRITICAL"] > CEILING["critical"]:
        failures.append("CRITICAL 误报 %d > 上限 %d" % (total["CRITICAL"], CEILING["critical"]))
    if total["WARNING"] > CEILING["warning"]:
        failures.append("WARNING 噪音 %d > 上限 %d" % (total["WARNING"], CEILING["warning"]))
    if total["INFO"] > CEILING["info"]:
        failures.append("INFO 噪音 %d > 上限 %d" % (total["INFO"], CEILING["info"]))

    print()
    if failures:
        for failure in failures:
            print("FAIL: %s" % failure)
        return 1
    print("PASS: CRITICAL 0 / WARNING %d <= %d / INFO %d <= %d" % (
        total["WARNING"], CEILING["warning"], total["INFO"], CEILING["info"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
