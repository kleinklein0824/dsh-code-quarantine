#!/usr/bin/env python3
"""在桌面 / 开始菜单创建一个带荷鲁斯之眼图标的快捷方式。

Windows 快捷方式的中文名如果通过命令行参数传进 PowerShell 容易乱码，
所以这里把脚本写成 UTF-8 BOM 文件再用 -File 执行，绕开编码问题。

    python scripts/install_shortcut.py --target D:\\work\\myproject
    python scripts/install_shortcut.py --dry-run          # 只看会创建什么
    python scripts/install_shortcut.py --remove           # 删掉已创建的快捷方式
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_ROOT = os.path.dirname(HERE)
ICON = os.path.join(SKILL_ROOT, "assets", "eye-of-horus.ico")
PANEL = os.path.join(HERE, "panel_server.py")
DEFAULT_NAME = "荷鲁斯之眼 · 代码质检面板"


def pythonw() -> str:
    exe = sys.executable or "python.exe"
    candidate = os.path.join(os.path.dirname(exe), "pythonw.exe")
    return candidate if os.path.isfile(candidate) else exe


def _ensure_utf8() -> None:
    """Force UTF-8 on stdout/stderr.

    默认情况下 Python 用控制台的 ANSI 代码页（中文 Windows 上是 GBK）写标准输出，
    而调用方（测试、hook 宿主、管道下游）按 UTF-8 解码，遇到「荷鲁斯之眼」这类
    非 ASCII 字符就会抛 UnicodeDecodeError，读线程一崩 stdout 就变成 None。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def _ps_quote(text: str) -> str:
    return "'" + str(text).replace("'", "''") + "'"


def build_script(name: str, target: str, remove: bool) -> str:
    lines = [
        "$ErrorActionPreference = 'Stop'",
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8",
        "$shell = New-Object -ComObject WScript.Shell",
        "$desktop = [Environment]::GetFolderPath('Desktop')",
        "$startmenu = [Environment]::GetFolderPath('Programs')",
    ]
    for folder, var in (("$desktop", "desk"), ("$startmenu", "menu")):
        path = os.path.join(folder, name + ".lnk")
        if remove:
            lines.append("Remove-Item -LiteralPath (%s + %s) -ErrorAction SilentlyContinue"
                         % (folder, _ps_quote("\\" + name + ".lnk")))
        else:
            lines.append("$lnk = $shell.CreateShortcut(%s + %s)" % (folder, _ps_quote("\\" + name + ".lnk")))
            lines.append("$lnk.TargetPath = %s" % _ps_quote(pythonw()))
            lines.append("$lnk.Arguments = %s" % _ps_quote(
                '"%s" --target "%s"' % (PANEL, target)))
            lines.append("$lnk.WorkingDirectory = %s" % _ps_quote(SKILL_ROOT))
            lines.append("$lnk.IconLocation = %s" % _ps_quote(ICON + ",0"))
            lines.append("$lnk.Description = 'dsh-code-quarantine 代码输出质检面板'")
            lines.append("$lnk.WindowStyle = 1")
            lines.append("$lnk.Save()")
            lines.append("Write-Output (%s + %s)" % (folder, _ps_quote("\\" + name + ".lnk")))
    return "\n".join(lines) + "\n"


def run_ps(script: str) -> tuple:
    fd, path = tempfile.mkstemp(suffix=".ps1")
    os.close(fd)
    try:
        with open(path, "w", encoding="utf-8-sig") as fh:  # BOM 让 PS5.1 正确识别中文
            fh.write(script)
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def main(argv=None) -> int:
    _ensure_utf8()
    parser = argparse.ArgumentParser(prog="install_shortcut", description="创建带荷鲁斯之眼图标的启动快捷方式")
    parser.add_argument("--target", default=os.getcwd(), help="快捷方式默认管理的项目目录")
    parser.add_argument("--name", default=DEFAULT_NAME, help="快捷方式名称")
    parser.add_argument("--dry-run", action="store_true", help="只打印将要执行的内容")
    parser.add_argument("--remove", action="store_true", help="删除快捷方式")
    args = parser.parse_args(argv)

    if os.name != "nt":
        print("这个脚本只处理 Windows 快捷方式。macOS/Linux 请直接运行：")
        print("  python %s --target <项目目录>" % PANEL)
        return 0

    target = os.path.abspath(args.target)
    if not args.remove and not os.path.isdir(target):
        print("目标目录不存在：%s" % target, file=sys.stderr)
        return 2
    if not args.remove and not os.path.isfile(ICON):
        print("缺少图标 %s，先运行 python scripts/make_icon.py" % ICON, file=sys.stderr)
        return 2

    script = build_script(args.name, target, args.remove)
    if args.dry_run:
        print(script)
        return 0

    code, output = run_ps(script)
    if code != 0:
        print("创建失败：\n%s" % output, file=sys.stderr)
        return 1
    for line in output.splitlines():
        if line.strip():
            print(("已删除 " if args.remove else "已创建 ") + line.strip())
    if not args.remove:
        print("双击即可打开面板；右键可固定到任务栏或开始屏幕。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
