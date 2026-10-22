#!/usr/bin/env python3
"""把 assets/eye-of-horus.svg 转成 Windows 多尺寸 .ico。

用无头 Chrome/Edge 逐尺寸栅格化（矢量边缘干净），再用纯标准库打包成 ICO。
只在需要重新生成图标时跑一次，运行时不需要浏览器。

    python scripts/make_icon.py
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_ROOT = os.path.dirname(HERE)
SVG = os.path.join(SKILL_ROOT, "assets", "eye-of-horus.svg")
ICO = os.path.join(SKILL_ROOT, "assets", "eye-of-horus.ico")
SIZES = (16, 24, 32, 48, 64, 128, 256)

BROWSERS = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
]


def find_browser() -> str:
    for path in BROWSERS:
        if os.path.isfile(path):
            return path
    for name in ("google-chrome", "chromium", "chromium-browser", "msedge"):
        found = shutil.which(name)
        if found:
            return found
    raise SystemExit("找不到 Chrome/Edge，无法栅格化 SVG。请手动导出 PNG 后再打包。")


def render(browser: str, size: int, out_png: str) -> None:
    html = (
        "<!DOCTYPE html><html><head><meta charset='utf-8'><style>"
        "html,body{margin:0;padding:0;background:transparent;overflow:hidden}"
        "img{display:block;width:%dpx;height:%dpx}"
        "</style></head><body><img src='file:///%s'></body></html>"
        % (size, size, SVG.replace("\\", "/").lstrip("/"))
    )
    tmp_html = os.path.join(tempfile.gettempdir(), "dsh-eye-%d.html" % size)
    with open(tmp_html, "w", encoding="utf-8") as fh:
        fh.write(html)
    cmd = [
        browser,
        "--headless=new",
        "--disable-gpu",
        "--hide-scrollbars",
        "--force-device-scale-factor=1",
        "--default-background-color=00000000",
        "--window-size=%d,%d" % (size, size),
        "--virtual-time-budget=2000",
        "--screenshot=%s" % out_png,
        "file:///" + tmp_html.replace("\\", "/").lstrip("/"),
    ]
    subprocess.run(cmd, capture_output=True, check=False)
    os.unlink(tmp_html)
    if not os.path.isfile(out_png):
        raise SystemExit("渲染 %dpx 失败" % size)


def pack_ico(pngs, out_path: str) -> None:
    """ICO 允许直接内嵌 PNG（Vista+），不必转 BMP。"""
    entries, blobs = [], []
    offset = 6 + 16 * len(pngs)
    for size, data in pngs:
        dim = 0 if size >= 256 else size
        entries.append(struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset))
        blobs.append(data)
        offset += len(data)
    with open(out_path, "wb") as fh:
        fh.write(struct.pack("<HHH", 0, 1, len(pngs)))
        for entry in entries:
            fh.write(entry)
        for blob in blobs:
            fh.write(blob)


def main() -> int:
    # 控制台默认按 ANSI 代码页编码，中文提示会让按 UTF-8 读管道的调用方解码失败。
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    if not os.path.isfile(SVG):
        print("缺少 %s" % SVG, file=sys.stderr)
        return 2
    browser = find_browser()
    tmpdir = tempfile.mkdtemp(prefix="dsh-ico-")
    pngs = []
    try:
        for size in SIZES:
            out_png = os.path.join(tmpdir, "eye-%d.png" % size)
            render(browser, size, out_png)
            with open(out_png, "rb") as fh:
                pngs.append((size, fh.read()))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    pack_ico(pngs, ICO)
    print("已生成 %s（%s，%d 字节）" % (ICO, "/".join(str(s) for s in SIZES), os.path.getsize(ICO)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
