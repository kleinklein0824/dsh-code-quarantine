#!/usr/bin/env python3
"""极简 CDP 客户端：只依赖标准库，直接跟 Chrome DevTools Protocol 对话。

为什么不用 selenium：本机 chromedriver 与 Chrome 版本不匹配，任何导航都报
"unhandled request"。直接走 CDP 反而更快——一个浏览器进程连续抓几百帧，
每帧 ~100ms，且不需要装任何东西。

    from cdp import Chrome
    with Chrome(headless=True) as c:
        c.open("file:///.../scenes.html?n=2")
        c.evaluate("window.__setT(1.5)")
        c.shot("frame.png")
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import urllib.request
from typing import Optional

CHROME_CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
]


def find_chrome() -> str:
    for path in CHROME_CANDIDATES:
        if os.path.isfile(path):
            return path
    for name in ("google-chrome", "chromium", "chromium-browser", "msedge"):
        found = shutil.which(name)
        if found:
            return found
    raise RuntimeError("找不到 Chrome/Edge")


class WebSocket:
    """够用就好的 WebSocket 客户端（RFC6455 客户端侧）。"""

    def __init__(self, url: str, timeout: float = 30.0) -> None:
        assert url.startswith("ws://")
        rest = url[5:]
        hostport, _, path = rest.partition("/")
        host, _, port = hostport.partition(":")
        self.sock = socket.create_connection((host, int(port or 80)), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buf = b""
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            "GET /%s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: %s\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n" % (path, hostport, key)
        )
        self.sock.sendall(req.encode())
        while b"\r\n\r\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("WebSocket 握手失败")
            self.buf += chunk
        head, _, self.buf = self.buf.partition(b"\r\n\r\n")
        if b"101" not in head.split(b"\r\n")[0]:
            raise RuntimeError("WebSocket 握手被拒: %s" % head[:120])

    def _read(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.sock.recv(max(4096, n - len(self.buf)))
            if not chunk:
                raise RuntimeError("连接已关闭")
            self.buf += chunk
        data, self.buf = self.buf[:n], self.buf[n:]
        return data

    def send(self, text: str) -> None:
        payload = text.encode("utf-8")
        header = bytearray([0x81])  # FIN + text
        length = len(payload)
        if length < 126:
            header.append(0x80 | length)
        elif length < (1 << 16):
            header.append(0x80 | 126)
            header += struct.pack(">H", length)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", length)
        mask = os.urandom(4)
        header += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def recv(self) -> str:
        while True:
            b1, b2 = self._read(2)
            opcode = b1 & 0x0F
            length = b2 & 0x7F
            if length == 126:
                length = struct.unpack(">H", self._read(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self._read(8))[0]
            mask = self._read(4) if b2 & 0x80 else None
            data = self._read(length) if length else b""
            if mask:
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
            if opcode == 0x9:  # ping -> pong
                self.sock.sendall(b"\x8a\x80" + os.urandom(4))
                continue
            if opcode == 0x8:
                raise RuntimeError("对端关闭连接")
            if opcode in (0x1, 0x2, 0x0):
                return data.decode("utf-8", "replace")

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class Chrome:
    def __init__(self, headless: bool = True, width: int = 1920, height: int = 1080) -> None:
        self.exe = find_chrome()
        self.width = width
        self.height = height
        self.profile = tempfile.mkdtemp(prefix="cdp-profile-")
        args = [
            self.exe,
            "--remote-debugging-port=0",
            "--user-data-dir=%s" % self.profile,
            "--window-size=%d,%d" % (width, height),
            "--force-device-scale-factor=1",
            "--hide-scrollbars",
            "--disable-gpu",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-extensions",
            "--disable-background-networking",
            "--mute-audio",
            "about:blank",
        ]
        if headless:
            args.insert(1, "--headless=new")
        self.proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.port = self._wait_port()
        self.ws: Optional[WebSocket] = None
        self._id = 0
        self._connect()

    def _wait_port(self, timeout: float = 25.0) -> int:
        marker = os.path.join(self.profile, "DevToolsActivePort")
        deadline = time.time() + timeout
        while time.time() < deadline:
            if os.path.isfile(marker):
                try:
                    with open(marker, encoding="utf-8") as fh:
                        content = fh.read().split("\n")
                    if content and content[0].strip().isdigit():
                        return int(content[0].strip())
                except OSError:
                    pass
            time.sleep(0.1)
        raise RuntimeError("Chrome 调试端口未就绪")

    def _connect(self) -> None:
        url = "http://127.0.0.1:%d/json/list" % self.port
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(url, timeout=5) as resp:
                    targets = json.loads(resp.read().decode())
                page = next(t for t in targets if t.get("type") == "page")
                self.ws = WebSocket(page["webSocketDebuggerUrl"])
                break
            except Exception:
                time.sleep(0.25)
        if not self.ws:
            raise RuntimeError("连不上 CDP")
        self.call("Page.enable")
        self.call("Runtime.enable")
        # headless=new 的实际视口会比 --window-size 小一圈（浏览器留白），
        # 必须用设备指标覆盖钉死成 1920x1080，否则截图会被裁边。
        self.call("Emulation.setDeviceMetricsOverride", {
            "width": self.width, "height": self.height,
            "deviceScaleFactor": 1, "mobile": False,
        })

    def call(self, method: str, params: Optional[dict] = None, timeout: float = 30.0) -> dict:
        self._id += 1
        ident = self._id
        self.ws.send(json.dumps({"id": ident, "method": method, "params": params or {}}))
        deadline = time.time() + timeout
        while time.time() < deadline:
            msg = json.loads(self.ws.recv())
            if msg.get("id") == ident:
                if "error" in msg:
                    raise RuntimeError("%s 失败: %s" % (method, msg["error"]))
                return msg.get("result") or {}
        raise RuntimeError("%s 超时" % method)

    def open(self, url: str) -> None:
        self.call("Page.navigate", {"url": url})
        time.sleep(0.6)

    def evaluate(self, expression: str) -> None:
        self.call("Runtime.evaluate", {"expression": expression, "awaitPromise": False})

    def shot(self, path: str) -> str:
        result = self.call("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": False})
        data = base64.b64decode(result["data"])
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def close(self) -> None:
        if self.ws:
            self.ws.close()
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass
        shutil.rmtree(self.profile, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


if __name__ == "__main__":
    import sys

    with Chrome() as chrome:
        target = sys.argv[1] if len(sys.argv) > 1 else "about:blank"
        out = sys.argv[2] if len(sys.argv) > 2 else "cdp-test.png"
        chrome.open(target)
        time.sleep(1)
        chrome.shot(out)
        print("已保存", out)
