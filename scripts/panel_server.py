#!/usr/bin/env python3
"""dsh-code-quarantine 本地控制面板。

一个只用标准库的 HTTP 服务，把"改配置"从手写 YAML 变成点按钮：

    python scripts/panel_server.py --target /path/to/project

面板只做两件事：读当前配置、写回同一批配置文件
（``.dsh-quarantine.yml`` / ``.dsh-quarantine-ignore``）。
它不复制任何判定逻辑，扫描仍然走 qcore.scan，所以面板与 CLI 永远一致。

安全：只绑定 127.0.0.1，所有请求都要带启动时生成的随机 token，
避免同机其他进程或网页跨站打进来改配置。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_ROOT = os.path.dirname(HERE)
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from qcore import __version__, cache, history, llm  # noqa: E402
from qcore.config import IGNORE_FILE, PROJECT_CONFIG, Config  # noqa: E402
from qcore.report import render_json  # noqa: E402
from qcore.rules import arch  # noqa: E402
from qcore.scan import ScanOptions, collect_sources, run_scan  # noqa: E402

DEFAULT_RULES = os.path.join(SKILL_ROOT, "rules")
MAX_EDIT_BYTES = 5 * 1024 * 1024   # 面板读写单文件上限
MAX_REQUEST_BYTES = 4 * 1024 * 1024
PANEL_HTML = os.path.join(HERE, "panel", "index.html")
ASSETS = os.path.join(SKILL_ROOT, "assets")
STATIC = {
    "/favicon.svg": (os.path.join(ASSETS, "eye-of-horus.svg"), "image/svg+xml"),
    "/logo.svg": (os.path.join(ASSETS, "eye-of-horus.svg"), "image/svg+xml"),
    "/favicon.ico": (os.path.join(ASSETS, "eye-of-horus.ico"), "image/x-icon"),
}

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
    return ""


def open_panel(url: str, mode: str) -> str:
    """app = 独立窗口（有自己的图标，可钉任务栏）；tab = 普通标签页。"""
    if mode == "none":
        return "none"
    if mode == "app":
        exe = find_chrome()
        if exe:
            subprocess.Popen(
                [exe, "--app=" + url, "--window-size=1280,880"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            return "app"
    webbrowser.open(url)
    return "tab"

IGNORE_HEADER = (
    "# dsh-code-quarantine 豁免清单\n"
    "# 每行：rule_id 路径glob（rule_id 写 * 表示该路径下全部规则）\n"
    "# 由控制面板维护，也可以手工编辑。\n\n"
)


def _json_str(value) -> str:
    return json.dumps(str(value), ensure_ascii=False)


def _yaml_list(items) -> str:
    return "[" + ", ".join(_json_str(x) for x in items) + "]"


class Panel:
    def __init__(self, target: str, rules_dir: str) -> None:
        self.target = os.path.abspath(target)
        self.rules_dir = os.path.abspath(rules_dir)
        self._lock = threading.Lock()
        self.events = deque(maxlen=50)
        self._seq = 0
        # 拦截事件的推送条件变量：`/api/events/stream` 的读线程在这里等待，
        # `add_event` 落库后叫醒它们。轮询版本每 3 秒问一次，一次拦截最多要
        # 等满一个周期才出现在横幅上；条件变量把延迟压到「写完就通知」。
        self._event_signal = threading.Condition()
        # 修复历史长了几条。历史页靠它决定要不要重读，而不是每 4 秒开一次文件。
        self._history_rev = 0
        # 配置文件的版本号：手改 `.dsh-quarantine.yml`、或者另一块面板保存，
        # 这个进程里的 `state()` 就过期了。后台线程盯着 mtime，变了就涨版本并
        # 通知流，页面跟着重读——用户不必再按 F5 才知道规则已经被改过。
        self._config_rev = 0
        self._config_stamps: tuple = ()
        # 历史文件也可能被另一块面板（插件卡片）写入。这个进程里的 `_history_rev`
        # 只知道自己写的那几笔；不盯着文件的话，浏览器历史页会一直显示旧内容。
        self._history_stamp: tuple = ()
        self._watch_stop = threading.Event()

    # ------------------------------------------------------------- config io
    def _base_config(self) -> Config:
        return Config(self.rules_dir, self.target, config_file=os.path.join(self.rules_dir, "__none__.yml"))

    def config(self, target: str | None = None) -> Config:
        return Config(self.rules_dir, os.path.abspath(target or self.target))

    def _paths(self, target: str | None = None):
        root = os.path.abspath(target or self.target)
        return os.path.join(root, PROJECT_CONFIG), os.path.join(root, IGNORE_FILE)

    def _read_ignore(self, target: str | None = None):
        _, path = self._paths(target)
        lines = []
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as fh:
                for raw in fh:
                    text = raw.split("#", 1)[0].strip()
                    if text:
                        lines.append(text)
        return lines

    # Fields the AI tab renders. Anything else in the file's ``llm:`` block
    # (hand-written extras) is preserved untouched.
    LLM_FORM_KEYS = ("enabled", "provider", "base_url", "model", "api_key_env",
                     "timeout", "max_chars", "max_calls")

    def _merge_llm_block(self, root: str, incoming: dict) -> dict:
        """Overlay the panel's AI form onto the file's existing ``llm:`` block.

        The form is a partial view. It never renders ``api_key`` (a secret must not
        round-trip through the browser), and older versions did not render
        ``timeout`` / ``max_calls`` at all. Writing only what the form knows
        silently erased the rest — saving the *rules* tab wiped an ``api_key_env``
        the user had set by hand, and the endpoint stopped working. So: start from
        what is on disk, let the submitted fields win, and keep everything the form
        cannot see.
        """
        merged = dict(self.config(root).project_data.get("llm") or {})
        for key in self.LLM_FORM_KEYS:
            if key in incoming:
                merged[key] = incoming[key]
        if incoming.get("api_key"):
            merged["api_key"] = incoming["api_key"]
        return merged

    # ---------------------------------------------------------------- state
    def state(self, target: str | None = None) -> dict:
        root = os.path.abspath(target or self.target)
        base = self._base_config()
        current = self.config(root)
        rules = []
        for rid in sorted(current.rules):
            rule = current.rules[rid]
            default = base.rules.get(rid, rule)
            rules.append({
                "id": rid,
                "title": rule.get("title", ""),
                "category": rule.get("category", ""),
                "severity": rule["severity"],
                "default_severity": default["severity"],
                "enabled": bool(rule.get("enabled", True)),
                "default_enabled": bool(default.get("enabled", True)),
                "message": rule.get("message", ""),
                "suggestion": rule.get("suggestion", ""),
            })
        allow = current.allow
        cfg_path, ignore_path = self._paths(root)
        llm_cfg = llm.resolve(current.project_data)
        return {
            "version": __version__,
            "target": root,
            "rules": rules,
            "llm": llm_cfg.public(),
            "allow": {
                "domains": [str(x) for x in allow.get("domains", [])],
                "blocked_domains": [str(x) for x in allow.get("blocked_domains", [])],
                "registries": [str(x) for x in allow.get("registries", [])],
                "cdn_domains": [str(x) for x in (current.data("AD005").get("cdn_domains") or [])],
            },
            "ignore": self._read_ignore(root),
            "files": {
                "config": cfg_path,
                "config_exists": os.path.isfile(cfg_path),
                "ignore": ignore_path,
                "ignore_exists": os.path.isfile(ignore_path),
            },
            "warnings": list(current.warnings),
        }

    # ----------------------------------------------------------------- save
    def save(self, payload: dict) -> dict:
        target = payload.get("target") or self.target
        root = os.path.abspath(target)
        if not os.path.isdir(root):
            raise ValueError("目标目录不存在: %s" % root)

        base = self._base_config()
        severity: dict = {}
        disabled = []
        for rid, item in (payload.get("rules") or {}).items():
            if rid not in base.rules:
                continue
            default = base.rules[rid]
            if not item.get("enabled", True):
                disabled.append(rid)
            sev = str(item.get("severity") or default["severity"]).upper()
            if sev != default["severity"]:
                severity[rid] = sev

        allow = payload.get("allow") or {}
        base_allow = base.allow
        base_cdn = {str(x) for x in (base.data("AD005").get("cdn_domains") or [])}

        def delta(key, base_values):
            seen, out = set(base_values), []
            for item in allow.get(key) or []:
                text = str(item).strip()
                if text and text not in seen:
                    seen.add(text)
                    out.append(text)
            return out

        # 只写"项目新增"的部分：基础白名单仍然由 rules/allowlist.yaml 维护，
        # 否则项目配置会把几十条内置域名抄一遍，后续升级规则就对不上了。
        domains = delta("domains", {str(x) for x in base_allow.get("domains", [])})
        blocked = delta("blocked_domains", {str(x) for x in base_allow.get("blocked_domains", [])})
        registries = delta("registries", {str(x) for x in base_allow.get("registries", [])})
        cdn = delta("cdn_domains", base_cdn)

        lines = [
            "# 由 dsh-code-quarantine 控制面板生成",
            "# 手改也可以，面板会按当前内容重新渲染本文件",
            "",
        ]
        if severity:
            lines.append("severity:")
            for rid in sorted(severity):
                lines.append("  %s: %s" % (rid, severity[rid]))
            lines.append("")
        if disabled:
            lines.append("disable:")
            for rid in sorted(disabled):
                lines.append("  - %s" % rid)
            lines.append("")
        if cdn:
            lines.append("data:")
            lines.append("  AD005:")
            lines.append("    cdn_domains: %s" % _yaml_list(cdn))
            lines.append("")
        if domains or blocked or registries:
            lines.append("allow:")
            if domains:
                lines.append("  domains: %s" % _yaml_list(domains))
            if blocked:
                lines.append("  blocked_domains: %s" % _yaml_list(blocked))
            if registries:
                lines.append("  registries: %s" % _yaml_list(registries))
            lines.append("")

        llm_block = self._merge_llm_block(root, payload.get("llm") or {})
        if llm_block:
            lines.append("llm:")
            if "enabled" in llm_block:
                lines.append("  enabled: %s" % ("true" if llm_block.get("enabled") else "false"))
            for key in ("provider", "base_url", "model", "api_key_env"):
                value = str(llm_block.get(key) or "").strip()
                if value:
                    lines.append("  %s: %s" % (key, _json_str(value)))
            for key in ("timeout", "max_chars", "max_calls"):
                if llm_block.get(key) not in (None, ""):
                    try:
                        lines.append("  %s: %d" % (key, int(llm_block[key])))
                    except (TypeError, ValueError):
                        pass
            if llm_block.get("api_key"):
                lines.append("  # 明文密钥仅建议在本机临时使用，长期请改用 api_key_env")
                lines.append("  api_key: %s" % _json_str(str(llm_block["api_key"])))
            lines.append("")

        cfg_path, _ = self._paths(root)
        with self._lock:
            self._atomic_write(cfg_path, "\n".join(lines).rstrip() + "\n")

        # 只有载荷**明确带了** ignore 才重写豁免文件。缺失与空列表是两回事：
        # 前者是「这次保存不涉及豁免」，后者才是「豁免清空」。把两者都当空列表，
        # 等于任何一个只保存规则或白名单的调用方都会把用户的豁免清单抹掉 ——
        # 而那份清单是手写积累的，抹掉没有任何提示。
        if "ignore" in payload:
            ignore_lines = [str(x).strip() for x in (payload.get("ignore") or []) if str(x).strip()]
            self.write_ignore(ignore_lines, root)

        # 保存后立即回读，确认写出去的东西能被自己解析（否则配置静默失效）
        check = self.config(root)
        warnings = list(check.warnings)
        if llm_block.get("api_key"):
            # 写明文密钥这件事本身不能"静悄悄成功"：文件可能被提交、被同步、被备份。
            warnings.append(
                "AI 密钥已以明文写入 %s。请确认该文件不会被提交（.gitignore 已默认忽略），"
                "长期建议改用 api_key_env 指向环境变量。" % PROJECT_CONFIG
            )
        return {
            "ok": True,
            "config": cfg_path,
            "rules_loaded": len(check.rules),
            "severity_overrides": severity,
            "disabled": disabled,
            "warnings": warnings,
        }

    def write_ignore(self, lines, root: str | None = None) -> str:
        _, path = self._paths(root)
        cleaned, seen = [], set()
        for line in lines:
            text = " ".join(str(line).split())
            if not text or text in seen:
                continue
            parts = text.split(" ")
            if len(parts) == 1:
                text = "* " + parts[0]
            seen.add(text)
            cleaned.append(text)
        body = IGNORE_HEADER + ("\n".join(cleaned) + "\n" if cleaned else "")
        with self._lock:
            self._atomic_write(path, body)
        return path

    def add_ignore(self, rule_id: str, path: str, target: str | None = None) -> dict:
        root = os.path.abspath(target or self.target)
        existing = self._read_ignore(root)
        entry = "%s %s" % (rule_id or "*", path)
        if entry not in existing:
            existing.append(entry)
        self.write_ignore(existing, root)
        return {"ok": True, "ignore": existing}

    # ----------------------------------------------------------------- scan
    def scan(self, payload: dict) -> dict:
        root = os.path.abspath(payload.get("target") or self.target)
        if not os.path.isdir(root):
            raise ValueError("目标目录不存在: %s" % root)
        cfg = self.config(root)
        mode = str(payload.get("mode") or "full")
        llm_cfg = None
        warnings = []
        if payload.get("use_llm"):
            llm_cfg = llm.resolve(cfg.project_data)
            if payload.get("llm_model"):
                llm_cfg.model = str(payload["llm_model"])
            # 与 CLI 同一条信任门禁。面板原先直接 resolve 项目配置，等于绕过了
            # 「克隆来的仓库不能把源码发到第三方」这条线：打开别人的仓库点一下
            # 「开始扫描」，源码就出去了，而前端还会因为 ready 自动勾上 AI 复核。
            if llm_cfg.source == "project" and os.environ.get("DSH_QUARANTINE_LLM_TRUST_PROJECT") != "1":
                warnings.append(
                    "项目配置里指定了 AI 端点（%s），未自动启用。克隆来的仓库可能借此把源码"
                    "发到第三方；确认可信后设置 DSH_QUARANTINE_LLM_TRUST_PROJECT=1，"
                    "或在面板「AI 复核」页手动填写端点。" % (llm_cfg.base_url or "?")
                )
                llm_cfg = None
        opts = ScanOptions(
            mode=mode if mode in ("full", "incremental") else "full",
            include_tests=bool(payload.get("include_tests")),
            write_state=False,
            llm=llm_cfg,
            llm_deep=bool(payload.get("llm_deep")),
        )
        result = run_scan(root, cfg, opts)
        cache.save_summary(root, result)
        data = json.loads(render_json(result))
        if warnings:
            data.setdefault("notes", []).extend(warnings)
            data["warnings"] = warnings
        return data

    # ------------------------------------------------------------------ AI
    def llm_test(self, payload: dict) -> dict:
        """用面板里填的参数测一次连通性，不落盘。"""
        root = os.path.abspath(payload.get("target") or self.target)
        base_cfg = self.config(root)
        data = dict(base_cfg.project_data or {})
        overrides = payload.get("llm") or {}
        if overrides:
            merged = dict(data.get("llm") or {})
            merged.update({k: v for k, v in overrides.items() if v not in (None, "")})
            data["llm"] = merged
        cfg = llm.resolve(data)
        info = cfg.public()
        if cfg.error:
            return {"ok": False, "error": "端点无效：%s" % cfg.error, "config": info}
        # "测试连接" answers "can this endpoint be reached with these values?", not
        # "will scans use it?". A user who turned the layer off in the form is
        # still allowed to validate the endpoint before turning it back on.
        cfg.enabled = True
        if not cfg.ready:
            missing = [k for k in ("base_url", "model", "api_key") if not getattr(cfg, k)]
            return {"ok": False, "error": "缺少 %s" % " / ".join(missing), "config": info}
        started = time.time()
        try:
            reply = llm.chat(cfg, "只回复两个字：可用")
        except Exception as exc:
            return {"ok": False, "error": str(exc), "config": info}
        return {
            "ok": True,
            "reply": (reply or "").strip()[:80],
            "latency_ms": int((time.time() - started) * 1000),
            "config": info,
        }

    def write_baseline(self, target: str | None = None) -> dict:
        root = os.path.abspath(target or self.target)
        cfg = self.config(root)
        opts = ScanOptions(mode="full", write_state=False)
        sources = collect_sources(root, cfg, opts)
        data = arch.build_baseline(sources)
        path = os.path.join(root, ".dsh-quarantine-baseline.json")
        arch.save_baseline(path, data)
        return {"ok": True, "path": path, "files": len(data.get("files") or {})}

    # ------------------------------------------------------- 定位 / 编辑 / 交办
    def _resolve(self, path: str, target: str | None = None) -> str:
        """把请求里的路径解析成目标目录内的真实文件路径。

        两道防线：
        1. realpath 解析符号链接，防止 `link -> /etc/passwd` 这类逃逸；
        2. normcase 统一大小写，避免 Windows 上 C:\\ 与 c:\\ 被误判为越界。
        """
        root = os.path.realpath(os.path.abspath(target or self.target))
        raw = path if os.path.isabs(path) else os.path.join(root, path)
        raw_abs = os.path.abspath(raw)
        if os.path.islink(raw_abs):
            raise ValueError("拒绝跟随符号链接: %s" % path)
        abs_path = os.path.realpath(raw_abs)
        if os.path.normcase(os.path.commonpath([root, abs_path])) != os.path.normcase(root):
            raise ValueError("文件不在目标目录内: %s" % path)
        if not os.path.isfile(abs_path):
            raise ValueError("文件不存在: %s" % path)
        return abs_path

    @staticmethod
    def _read_text(abs_path: str, limit: int = MAX_EDIT_BYTES) -> str:
        """读文件并卡上限，避免面板被超大文件拖死。"""
        try:
            size = os.path.getsize(abs_path)
        except OSError as exc:
            raise ValueError("无法读取文件: %s" % exc)
        if size > limit:
            raise ValueError("文件过大（%d 字节，上限 %d），请用编辑器打开" % (size, limit))
        with open(abs_path, "r", encoding="utf-8", errors="replace", newline="") as fh:
            return fh.read()

    @staticmethod
    def _atomic_write(abs_path: str, text: str) -> None:
        """先写同目录临时文件再 os.replace，避免写一半崩溃把原文件毁掉。"""
        folder = os.path.dirname(abs_path)
        fd, tmp = tempfile.mkstemp(prefix=".dsh-tmp-", dir=folder)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
                fh.write(text)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, abs_path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def reveal(self, path: str, line: int = 1, target: str | None = None) -> dict:
        """在编辑器里跳到 file:line。优先 code --goto，退化为资源管理器定位。"""
        abs_path = self._resolve(path, target)
        line = max(1, int(line or 1))
        cmd = ["code", "--goto", "%s:%d:1" % (abs_path, line)]
        if os.environ.get("DSH_QUARANTINE_NO_LAUNCH"):
            return {"ok": True, "method": "dry-run", "command": cmd}
        exe = shutil.which("code") or shutil.which("code.cmd") or shutil.which("codium")
        if exe:
            try:
                subprocess.Popen([exe, "--goto", "%s:%d:1" % (abs_path, line)],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return {"ok": True, "method": "vscode", "command": cmd}
            except OSError:
                pass
        if os.name == "nt":
            subprocess.Popen(["explorer", "/select,", abs_path])
            return {"ok": True, "method": "explorer",
                    "hint": "已用资源管理器定位；装 VS Code 并加入 PATH 后可直接跳到第 %d 行" % line}
        subprocess.Popen(["xdg-open", os.path.dirname(abs_path)])
        return {"ok": True, "method": "file-manager"}

    def read_line(self, path: str, line: int, context: int = 3, target: str | None = None) -> dict:
        abs_path = self._resolve(path, target)
        lines = self._read_text(abs_path).split("\n")
        line = min(max(1, int(line or 1)), len(lines))
        lo, hi = max(1, line - context), min(len(lines), line + context)
        return {
            "path": os.path.relpath(abs_path, os.path.abspath(target or self.target)).replace("\\", "/"),
            "line": line,
            "text": lines[line - 1].rstrip("\r"),
            "before": [{"n": n, "text": lines[n - 1].rstrip("\r")} for n in range(lo, line)],
            "after": [{"n": n, "text": lines[n - 1].rstrip("\r")} for n in range(line + 1, hi + 1)],
            "total": len(lines),
        }

    def write_line(self, path: str, line: int, text: str, target: str | None = None,
                   context: dict | None = None) -> dict:
        """就地改一行：先备份，再写回，然后只重扫这个文件。

        整个「读-改-写」必须串行：面板的「一键修复」是按钮，用户连点两下就是两个
        并发请求，两次都基于同一份旧内容算出新内容，后写的覆盖先写的；更糟的是
        Windows 上两个 os.replace 抢同一个目标会抛 PermissionError 变成 500。

        `context` 是可选的溯源信息（`rule_id` / `source`），会连同改动内容一起
        写进历史。没有它，历史里只剩「某文件某行被改过」，用户无法回答
        「这次改动是为了消掉哪条规则」。
        """
        with self._lock:
            return self._write_line_locked(path, line, text, target, context)

    def _write_line_locked(self, path: str, line: int, text: str, target: str | None = None,
                           context: dict | None = None) -> dict:
        root = os.path.realpath(os.path.abspath(target or self.target))
        abs_path = self._resolve(path, root)
        raw = self._read_text(abs_path)
        lines = raw.split("\n")
        idx = max(0, min(int(line or 1) - 1, len(lines) - 1))
        old = lines[idx]
        cr = "\r" if old.endswith("\r") else ""
        if old.rstrip("\r") == text.rstrip("\r"):
            return {"ok": True, "changed": False, "path": path, "line": idx + 1}

        backup_dir = os.path.join(root, ".dsh-quarantine-backup")
        os.makedirs(backup_dir, exist_ok=True)
        rel = os.path.relpath(abs_path, root).replace("\\", "/")
        # 秒级时间戳在同一秒内的两次修改会撞名，第二次 shutil.copy2 直接覆盖掉
        # 第一次的备份——"一键修复"连点两下就只剩一个还原点。
        base = os.path.join(backup_dir, "%s.%s" % (rel.replace("/", "__"), time.strftime("%Y%m%d-%H%M%S")))
        backup = base + ".bak"
        suffix = 1
        while os.path.exists(backup):
            backup = "%s-%d.bak" % (base, suffix)
            suffix += 1
        shutil.copy2(abs_path, backup)

        lines[idx] = text.rstrip("\n").rstrip("\r") + cr
        self._atomic_write(abs_path, "\n".join(lines))

        # 只重扫改动文件，确认这处是否真的消掉了
        cfg = self.config(root)
        with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
            body = fh.read()
        from qcore.scan import scan_text as _scan_text

        after = _scan_text(body, rel, cfg)
        remaining = [f.to_dict() for f in after.findings]
        backup_rel = os.path.relpath(backup, root).replace("\\", "/")
        self._record_fix(root, rel, idx + 1, old.rstrip("\r"), text, backup_rel, remaining, context)
        return {
            "ok": True,
            "changed": True,
            "path": rel,
            "line": idx + 1,
            "before": old.rstrip("\r"),
            "after": text,
            "backup": backup_rel,
            "remaining": remaining,
        }

    def _record_fix(self, root: str, rel: str, line: int, before: str, after: str,
                    backup: str, remaining: list, context: dict | None) -> None:
        """把这次改动追加进历史。写历史失败不能让修复本身看起来失败。"""
        ctx = context or {}
        entry = {
            "kind": "fix",
            "file": rel,
            "line": line,
            "before": before,
            "after": after,
            "backup": backup,
            "rule_id": str(ctx.get("rule_id") or ""),
            "source": str(ctx.get("source") or "panel"),
            "remaining": len(remaining),
            "remaining_ids": sorted({str(f.get("rule_id") or "") for f in remaining if f.get("rule_id")}),
        }
        try:
            written = history.append(root, entry)
        except Exception:  # noqa: BLE001 - 历史是旁路，任何异常都不能影响写入结果
            return
        # `history.append` 用返回值而不是异常表示写失败（它自己吞掉 OSError）。
        # 不检查返回值就会在没写进去时也涨版本号，页面重读一次仍然是旧内容。
        if not written:
            return
        # 这一笔是本进程写的，记下新指纹，避免监听线程把它当外部改动再推一帧。
        if os.path.normcase(os.path.realpath(root)) == os.path.normcase(os.path.realpath(self.target)):
            self._history_stamp = self._file_stamp(history.history_path(root))
        # 只有真的写进去了才涨版本号：写失败时重读也读不到东西。
        with self._event_signal:
            self._history_rev += 1
            self._event_signal.notify_all()

    def read_history(self, target: str | None = None, limit: int = 50,
                     verify: bool = False) -> dict:
        """最近的改动，最新的在前。

        ``verify=True`` 时逐条回读磁盘，标出这一处**现在**是什么状态：

        - ``current``：文件当前内容与 ``after`` 一致 —— 改动还在
        - ``reverted``：内容回到了 ``before`` 或备份的内容 —— 有人撤了/换了写法
        - ``stale``：文件被改成第三种样子 —— 记录已经不能代表现状
        - ``gone``：文件不在了

        历史是写入时的快照，而代码会继续变。不标注的话，一条三天前的记录看起来
        和刚写的一样可信，用户会拿着一个已经不存在的改动去排查当前问题。
        """
        root = os.path.realpath(os.path.abspath(target or self.target))
        entries = history.load(root, limit=limit)
        if verify:
            for entry in entries:
                entry["status"] = self._entry_status(root, entry)
        return {
            "path": os.path.relpath(history.history_path(root), root).replace("\\", "/"),
            "total": history.count(root),
            "entries": entries,
        }

    def _entry_status(self, root: str, entry: dict) -> str:
        """这条历史记录还能不能代表文件现状。"""
        rel = str(entry.get("file") or "")
        line = int(entry.get("line") or 0)
        if not rel or line < 1:
            return "unknown"
        try:
            abs_path = self._resolve(rel, root)
        except ValueError:
            return "gone"
        if not os.path.isfile(abs_path):
            return "gone"
        try:
            with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().split("\n")
        except OSError:
            return "unknown"
        if line > len(lines):
            return "stale"
        current = lines[line - 1].rstrip("\r")
        after = str(entry.get("after") or "").rstrip("\r")
        before = str(entry.get("before") or "").rstrip("\r")
        if current == after:
            return "current"
        if current == before:
            return "reverted"
        return "stale"

    def fix_prompt(self, payload: dict, target: str | None = None) -> dict:
        """生成一段可以直接粘给 AI 的修复指令。"""
        rule_id = str(payload.get("rule_id") or "")
        path = str(payload.get("path") or "")
        line = payload.get("line") or 0
        evidence = str(payload.get("evidence") or "").strip()
        message = str(payload.get("message") or "").strip()
        suggestion = str(payload.get("suggestion") or "").strip()
        root = os.path.abspath(target or self.target)
        scan_cmd = 'python scripts/quarantine.py "%s" --files "%s"' % (root, path)
        lines = [
            "请修复 dsh-code-quarantine 命中的这一个问题，只改这一处，不要顺手重构其它代码。",
            "",
            "- 规则：%s" % rule_id,
            "- 位置：%s:%s" % (path, line),
            "- 现象：%s" % (message or "见证据"),
            "- 证据：`%s`" % (evidence or "（无）"),
            "- 修复方向：%s" % (suggestion or "按规则说明处理"),
            "",
            "改完后请复验到无该规则命中：",
            "```bash",
            scan_cmd,
            "```",
            "如果确认这是误报，不要改代码，改为在 .dsh-quarantine-ignore 中登记 `%s %s`。" % (rule_id or "*", path),
        ]
        return {"prompt": "\n".join(lines), "path": path, "line": line, "rule_id": rule_id}

    # ------------------------------------------------------------- 事件推送
    def add_event(self, payload: dict) -> dict:
        self._seq += 1
        event = {
            "id": self._seq,
            "ts": time.time(),
            "clock": time.strftime("%H:%M:%S"),
            "type": str(payload.get("type") or "hook"),
            "tool": str(payload.get("tool") or ""),
            "file": str(payload.get("file") or ""),
            "verdict": str(payload.get("verdict") or ""),
            "counts": payload.get("counts") or {},
            "findings": (payload.get("findings") or [])[:8],
        }
        self.events.appendleft(event)
        with self._event_signal:
            self._event_signal.notify_all()
        return {"ok": True, "id": self._seq}

    def events_list(self) -> dict:
        return {"seq": self._seq, "events": list(self.events)}

    # ----------------------------------------------------------- 面板信息
    def write_info(self, port: int, token: str) -> str:
        path = os.path.join(self.target, ".dsh-quarantine-panel.json")
        payload = {
            "port": port,
            "token": token,
            "url": "http://127.0.0.1:%d/" % port,
            "pid": os.getpid(),
            "started": time.time(),
        }
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False)
            return path
        except OSError:
            return ""

    def clear_info(self) -> None:
        try:
            os.unlink(os.path.join(self.target, ".dsh-quarantine-panel.json"))
        except OSError:
            pass

    # ------------------------------------------------------- 配置变更监听
    @staticmethod
    def _file_stamp(path: str) -> tuple:
        """`(mtime_ns, size)`，文件不存在时返回 `(0, 0)`。"""
        try:
            info = os.stat(path)
            return (int(info.st_mtime_ns), info.st_size)
        except OSError:
            return (0, 0)

    def _config_stamp(self) -> tuple:
        """当前配置文件的 (mtime, size) 指纹。

        只看这两项而不是内容哈希：配置文件很小，但哈希要每次开文件读一遍；
        mtime+size 对「有人手改了一下」足够敏感，而假阳性只会多刷一次页面。
        """
        root = os.path.realpath(os.path.abspath(self.target))
        stamp = []
        for name in (PROJECT_CONFIG, IGNORE_FILE):
            try:
                info = os.stat(os.path.join(root, name))
                stamp.append((name, int(info.st_mtime_ns), info.st_size))
            except OSError:
                stamp.append((name, 0, 0))
        return tuple(stamp)

    def _watch_configs(self, interval: float = 2.0) -> None:
        """后台盯着配置与历史文件，变了就涨版本并叫醒所有打开的页面。

        手改 `.dsh-quarantine.yml` 是常态（那本来就是个给人写的文件），而面板
        的规则页只在打开时读一次。没有这个监听，用户改完文件得自己按 F5 才
        知道生效了没有——而「以为生效了」比「知道没生效」危险得多。

        历史文件也要盯：插件卡片的「一键修复」写的是同一份 JSONL，浏览器面板
        不知道它什么时候长了一行。只看 `_history_rev` 会漏掉另一半入口。
        """
        # `_config_stamp()` returns a tuple of `(name, mtime, size)` triples. It is
        # compared, never looked up by key, so it stays a tuple: `dict()` on it
        # raises "dictionary update sequence element #0 has length 3; 2 is required",
        # which killed this watcher on its first statement and left the panel
        # silently showing stale config.
        self._config_stamps = self._config_stamp()
        self._history_stamp = self._file_stamp(history.history_path(self.target))
        while not self._watch_stop.wait(interval):
            changed = False
            try:
                current = self._config_stamp()
            except Exception:  # noqa: BLE001 - 监听线程不能因为一次 stat 失败就死
                current = self._config_stamps
            if current != self._config_stamps:
                self._config_stamps = current
                self._config_rev += 1
                changed = True
            try:
                history_now = self._file_stamp(history.history_path(self.target))
            except Exception:  # noqa: BLE001
                history_now = self._history_stamp
            if history_now != self._history_stamp:
                self._history_stamp = history_now
                self._history_rev += 1
                changed = True
            if not changed:
                continue
            with self._event_signal:
                self._event_signal.notify_all()

    def start_config_watch(self, interval: float = 2.0) -> None:
        worker = threading.Thread(target=self._watch_configs, args=(interval,), daemon=True)
        worker.start()

    def stop_config_watch(self) -> None:
        self._watch_stop.set()


class Handler(BaseHTTPRequestHandler):
    server_version = "dsh-quarantine-panel/" + __version__
    panel: Panel
    token: str

    def log_message(self, fmt, *args):  # 安静一点，只留错误
        if str(args[1] if len(args) > 1 else "").startswith("4"):
            # 请求行里带着 ?t=<token>，原样写日志等于把凭据落进终端历史与日志文件。
            line = fmt % args
            line = re.sub(r"([?&]t=)[^&\s\"]+", r"\1***", line)
            line = re.sub(r"(X-Panel-Token:\s*)\S+", r"\1***", line, flags=re.I)
            sys.stderr.write("[panel] " + line + "\n")

    # ------------------------------------------------------------- helpers
    def _authorized(self, query) -> bool:
        token = (query.get("t") or [""])[0] or self.headers.get("X-Panel-Token", "")
        # compare_digest 对含非 ASCII 的 str 直接抛 TypeError，一次带中文的
        # 探测请求就能让连接断在半路（curl 52 / 空响应），所以先转成字节比较。
        try:
            return secrets.compare_digest(
                str(token).encode("utf-8", "surrogatepass"),
                self.token.encode("utf-8", "surrogatepass"),
            )
        except (UnicodeError, TypeError):
            return False

    def _send(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        if ctype.startswith("text/html"):
            # 面板不需要任何外部资源；限制 connect-src 可以挡住 XSS 后的外传
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; "
                "script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'",
            )
        self.end_headers()
        self.wfile.write(body)

    def _json(self, data, status: int = 200) -> None:
        self._send(status, json.dumps(data, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _stream_events(self) -> None:
        """把拦截事件和修复历史的变化推给浏览器，而不是让浏览器定时来问。

        `ThreadingHTTPServer` 每个连接一个线程，所以这条长连接只占一个线程；
        `seq` 作为 SSE 的 `id:` 字段，浏览器断线重连时带 `Last-Event-ID` 回来，
        这里据此补发漏掉的事件——轮询版本靠 `LAST_EVENT` 自己记，一刷新就丢。

        一帧里同时带 `history`（修复历史版本号）：历史页原来每 4 秒开一次
        JSONL 文件，而「历史长了」这件事恰恰是写入方自己知道的，没必要轮询。
        """
        try:
            last = int(self.headers.get("Last-Event-ID") or 0)
        except ValueError:
            last = 0
        seen_history = self.panel._history_rev
        seen_config = self.panel._config_rev
        first_sent = False
        sent_once = False
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store, no-transform")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        try:
            self.wfile.write(b"retry: 3000\n\n")
            self.wfile.flush()
            while True:
                # 首帧立刻发，别等第一个事件：页面刚打开时横幅区域要是空的，
                # 用户没法判断是「还没发生拦截」还是「连接根本没建起来」。
                # 之后的每一帧都是真变化。
                with self.panel._event_signal:
                    if not first_sent:
                        first_sent = True
                    else:
                        self.panel._event_signal.wait(timeout=20)
                seq = self.panel._seq
                hist = self.panel._history_rev
                conf = self.panel._config_rev
                if seq == last and hist == seen_history and conf == seen_config and sent_once:
                    # 20 秒没有变化：写一行注释保活。客户端会忽略注释行，
                    # 但代理和操作系统都需要看到字节流动，否则会掐掉连接。
                    self.wfile.write(b": keep-alive\n\n")
                    self.wfile.flush()
                    continue
                pending = []
                # `events` 是 appendleft 的，所以列表本身是新的在前。补发要按
                # 时间正序，但筛选条件是「比 Last-Event-ID 新」——在正序上遇到
                # 第一条旧的不能 break，后面还有更新的（重连时漏的正是中间那段）。
                for event in list(self.panel.events):
                    if event["id"] <= last:
                        continue
                    pending.append(event)
                pending.reverse()
                # 没有新拦截但有新修复/新配置时也要发一帧：只带版本号，不带事件。
                for event in pending or [None]:
                    body = json.dumps(
                        {"seq": seq, "history": hist, "config": conf, "event": event},
                        ensure_ascii=False,
                    )
                    frame_id = event["id"] if event else last
                    self.wfile.write(("id: %d\ndata: %s\n\n" % (frame_id, body)).encode("utf-8"))
                    if event:
                        last = event["id"]
                seen_history = hist
                seen_config = conf
                sent_once = True
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            # 用户关掉页面：正常收场，不打印堆栈。
            return

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        if length > MAX_REQUEST_BYTES:
            raise ValueError("请求体过大")
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except ValueError as exc:
            raise ValueError("请求体不是合法 JSON: %s" % exc)

    # ------------------------------------------------------------- routing
    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path in STATIC:
            # 图标是公开静态资源，不带 token 也能取（否则窗口/任务栏图标会空白）
            path, ctype = STATIC[parsed.path]
            try:
                with open(path, "rb") as fh:
                    body = fh.read()
            except OSError:
                self._send(404, b"missing", "text/plain")
                return
            self._send(200, body, ctype)
            return
        if parsed.path in ("/", "/index.html"):
            if not self._authorized(query):
                self._send(403, "token 无效".encode("utf-8"), "text/plain; charset=utf-8")
                return
            try:
                with open(PANEL_HTML, "rb") as fh:
                    html = fh.read()
            except OSError:
                self._send(500, "面板页面缺失".encode("utf-8"), "text/plain; charset=utf-8")
                return
            html = html.replace(b"__PANEL_TOKEN__", self.token.encode("utf-8"))
            self._send(200, html, "text/html; charset=utf-8")
            return
        if parsed.path == "/api/state":
            if not self._authorized(query):
                self._json({"error": "token 无效"}, 403)
                return
            target = (query.get("target") or [None])[0]
            try:
                self._json(self.panel.state(target))
            except Exception as exc:
                self._json({"error": str(exc)}, 400)
            return
        if parsed.path == "/api/events":
            if not self._authorized(query):
                self._json({"error": "token 无效"}, 403)
                return
            self._json(self.panel.events_list())
            return
        if parsed.path == "/api/events/stream":
            if not self._authorized(query):
                self._json({"error": "token 无效"}, 403)
                return
            self._stream_events()
            return
        if parsed.path == "/api/history":
            if not self._authorized(query):
                self._json({"error": "token 无效"}, 403)
                return
            try:
                limit = int((query.get("limit") or ["50"])[0])
            except ValueError:
                limit = 50
            # `verify=1` 让服务端逐条回读磁盘，标出每条记录「现在还算不算数」。
            # 默认关闭：历史面板可能被反复轮询，而核对要开文件。
            verify = (query.get("verify") or ["0"])[0].lower() in ("1", "true", "yes", "on")
            self._json(self.panel.read_history((query.get("target") or [None])[0], limit, verify=verify))
            return
        if parsed.path == "/api/line":
            if not self._authorized(query):
                self._json({"error": "token 无效"}, 403)
                return
            try:
                self._json(self.panel.read_line(
                    (query.get("file") or [""])[0],
                    int((query.get("line") or ["1"])[0]),
                    int((query.get("context") or ["3"])[0]),
                    (query.get("target") or [None])[0],
                ))
            except (ValueError, OSError) as exc:
                self._json({"error": str(exc)}, 400)
            return
        self._json({"error": "not found"}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        if not self._authorized(parse_qs(parsed.query)):
            self._json({"error": "token 无效"}, 403)
            return
        try:
            payload = self._body()
            if parsed.path == "/api/scan":
                self._json(self.panel.scan(payload))
            elif parsed.path == "/api/save":
                self._json(self.panel.save(payload))
            elif parsed.path == "/api/ignore":
                self._json(self.panel.add_ignore(
                    str(payload.get("rule_id") or "*"),
                    str(payload.get("path") or ""),
                    payload.get("target"),
                ))
            elif parsed.path == "/api/baseline":
                self._json(self.panel.write_baseline(payload.get("target")))
            elif parsed.path == "/api/reveal":
                self._json(self.panel.reveal(
                    str(payload.get("file") or ""), payload.get("line") or 1, payload.get("target")))
            elif parsed.path == "/api/line":
                self._json(self.panel.write_line(
                    str(payload.get("file") or ""), payload.get("line") or 1,
                    str(payload.get("text") or ""), payload.get("target"),
                    {"rule_id": payload.get("rule_id"), "source": "panel"}))
            elif parsed.path == "/api/fix-prompt":
                self._json(self.panel.fix_prompt(payload, payload.get("target")))
            elif parsed.path == "/api/event":
                self._json(self.panel.add_event(payload))
            elif parsed.path == "/api/llm/test":
                self._json(self.panel.llm_test(payload))
            else:
                self._json({"error": "not found"}, 404)
        except ValueError as exc:
            self._json({"error": str(exc)}, 400)
        except Exception as exc:  # 面板不能因为一次异常就挂掉
            self._json({"error": "%s: %s" % (type(exc).__name__, exc)}, 500)


def main(argv=None) -> int:
    # pythonw.exe 下 sys.stdout/stderr 是 None，print 会直接抛异常把快捷方式弄崩
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")
    # 控制台默认按 ANSI 代码页（中文 Windows 是 GBK）编码，日志里的中文会让
    # 按 UTF-8 读管道的调用方解码失败。
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    parser = argparse.ArgumentParser(prog="panel_server", description="dsh-code-quarantine 控制面板")
    parser.add_argument("--target", default=".", help="要管理的项目目录（默认当前目录）")
    parser.add_argument("--rules", default=DEFAULT_RULES, help="规则目录")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--browser", choices=["app", "tab", "none"], default="app",
                        help="app=独立窗口（默认，可钉任务栏） / tab=浏览器标签页 / none=不打开")
    args = parser.parse_args(argv)

    target = os.path.abspath(args.target)
    if not os.path.isdir(target):
        print("目标目录不存在: %s" % target, file=sys.stderr)
        return 2

    token = secrets.token_urlsafe(18)
    Handler.panel = Panel(target, args.rules)
    Handler.token = token

    httpd = None
    for port in range(args.port, args.port + 12):
        try:
            httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
            break
        except OSError:
            continue
    if httpd is None:
        print("端口 %d~%d 都被占用" % (args.port, args.port + 11), file=sys.stderr)
        return 2

    url = "http://127.0.0.1:%d/?t=%s" % (httpd.server_address[1], token)
    info = Handler.panel.write_info(httpd.server_address[1], token)
    print("dsh-code-quarantine 控制面板", flush=True)
    print("  目标 : %s" % target, flush=True)
    print("  地址 : %s" % url, flush=True)
    print("  退出 : Ctrl+C", flush=True)
    if info:
        print("  hook 会通过 %s 把拦截事件推到这里" % os.path.basename(info), flush=True)

    def _launch():
        mode = open_panel(url, args.browser)
        if mode == "tab":
            print("  （未找到 Chrome/Edge，已用默认浏览器打开；想要独立窗口请装 Chrome）", flush=True)

    threading.Timer(0.5, _launch).start()
    # 手改配置文件是常态，而页面只在打开时读一次。没有这个监听，用户改完
    # 得自己按 F5 才知道生效了没有。
    Handler.panel.start_config_watch()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n已退出")
    finally:
        Handler.panel.stop_config_watch()
        Handler.panel.clear_info()
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
