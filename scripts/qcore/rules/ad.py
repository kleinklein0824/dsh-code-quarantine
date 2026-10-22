"""Layer 1: ad / promotional injection detection.

Design notes
------------
A bare URL is never enough. Every hit needs a structural anchor:

* AD001 - promotional verb co-occurring with a non-allowlisted link
* AD002 - a hardcoded URL in a code string that no network/link API consumes
* AD003 - domain matched against blocked / suspicious-domain patterns
* AD004 - contact handles inside code strings (not comments)
* AD005 - external script / iframe / worker / dynamic import

Comments and docstrings are treated separately from executable strings: a
`# see https://github.com/...` is not the same signal as
`requests.get("https://relay-xyz.top/status")`.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from .. import emit, pyutil
from ..model import Finding

URL_RE = re.compile(r"(?:https?|wss?)://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]+", re.I)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

# 裸域名（不带 scheme）。中文推广话术几乎从不写 `https://`：
# 「访问 relay-hub.com 领取额度」在真实中转站页面里比带 scheme 的写法更常见。
# 但裸域名在正常代码里也到处都有（`api.example.com` 当配置默认值），所以它
# **只**能作为 AD001 的共现锚点，绝不单独产出 AD002 —— 这一条是精度底线。
BARE_DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9._%+\-@/])((?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+"
    r"(?:com|net|org|io|dev|app|xyz|top|site|online|shop|vip|cc|me|co|cn|ru|info|biz|club|live|pro|link|store|tech|cloud|fun|space|website|icu|cyou|monster|rest|bar|buzz|click))\b",
    re.I,
)

DATA_LANGS = {"json", "yaml", "toml", "ini", "dotenv", "requirements", "markdown", "text", "sql"}
NON_SOURCE_LANGS = DATA_LANGS | {"unknown"}

SCRIPT_SRC_RES = [
    re.compile(r"<script[^>]*\bsrc\s*=\s*[\"']?(https?://[^\"'\s>]+)", re.I),
    re.compile(r"<iframe[^>]*\bsrc\s*=\s*[\"']?(https?://[^\"'\s>]+)", re.I),
    re.compile(r"<link[^>]*\bhref\s*=\s*[\"']?(https?://[^\"'\s>]+)", re.I),
    re.compile(r"new\s+Worker\s*\(\s*[\"'](https?://[^\"']+)", re.I),
    re.compile(r"importScripts\s*\(\s*[\"'](https?://[^\"']+)", re.I),
    re.compile(r"\bimport\s*\(\s*[\"'](https?://[^\"']+)", re.I),
    re.compile(r"\bfrom\s+[\"'](https?://[^\"']+)", re.I),
]

ASSIGN_RE = re.compile(
    r"^\s*(?:export\s+)?(?:const|let|var|final|val|public|private|static)?\s*"
    r"([A-Za-z_$][\w$]*)\s*(?::\s*[^=]+)?=\s*[\"'`]",
)
URLISH_NAME_RE = re.compile(
    r"(?i)(url|uri|endpoint|host|base|api|proxy|registry|webhook|redirect|cdn|mirror|server|origin)"
)
# XML 命名空间 / JSON Schema 标识符：是常量标识，不是网络端点
IDENTIFIER_ASSIGN_RE = re.compile(
    r"(?i)\b[\w$]*(schema|namespace|xmlns|dtd|doctype|ns)[\w$]*\s*[:=]"
)


def _clean_url(raw: str) -> str:
    url = raw
    while url and url[-1] in ".,;:!?)]}\"'":
        if url[-1] == ")" and url.count("(") >= url.count(")"):
            break
        url = url[:-1]
    return url


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


# 文档/示例里常见的占位主机名。它们不是"外链"，而是语法示例的一部分：
#   ``https://user:pass@host:port/path``  -> host
#   ``https://foo.com,bar.com/path``      -> foo.com / bar.com
#   ``http://exam_ple.com``               -> 含下划线，不是合法域名
# 把它们当注入报告只会淹没真实信号。
_PLACEHOLDER_LABELS = {
    "example", "examples", "foo", "bar", "baz", "qux", "host", "hostname",
    "port", "path", "query", "fragment", "user", "pass", "password", "domain",
    "domainname", "tld", "punycode", "your-domain", "yourdomain", "your-site",
    "yoursite", "xxx", "abc", "test", "placeholder", "sample", "dummy",
}
_PLACEHOLDER_TLDS = {"example", "test", "invalid", "local", "localhost", "com-", "tld"}


def _plausible_host(host: str) -> bool:
    """Reject hosts that are syntactic placeholders rather than real domains."""
    if not host or "." not in host:
        return False
    if "_" in host:
        return False
    labels = host.split(".")
    if any(not label for label in labels):
        return False
    tld = labels[-1]
    if len(tld) < 2:
        return False
    if tld in _PLACEHOLDER_TLDS:
        return False
    # xn-- 开头的 punycode 示例（www.xn--80ak6aa92e.com）也是文档演示
    if tld.startswith("xn--"):
        return False
    for label in labels:
        if label in _PLACEHOLDER_LABELS:
            return False
        if label.startswith("xn--"):
            return False
    return True


def _url_hits(source, cfg) -> List[Tuple[int, str, str, str, bool]]:
    """(offset, url, host, region, bare) for every link-like literal in the file.

    ``bare`` marks a domain written without a scheme (``relay-hub.com``). Those
    are only ever used as the *co-occurrence anchor* for AD001 — never reported
    on their own. Rationale: ``api.example.com`` as a config default is ordinary
    code, but 「访问 relay-hub.com 领取额度」 is exactly how Chinese relay sites
    phrase their ad, and it never carries ``https://``. Restricting bare hits to
    AD001 keeps the false-positive budget intact: a bare domain still needs a
    promotional phrase next to it before anything is reported.
    """
    hits = []
    for match in URL_RE.finditer(source.text):
        url = _clean_url(match.group(0))
        if len(url) < 10:
            continue
        host = _host(url)
        if not host:
            continue
        if not _plausible_host(host):
            continue
        hits.append((match.start(), url, host, source.region(match.start()), False))
    for match in BARE_DOMAIN_RE.finditer(source.text):
        host = match.group(1).lower()
        if not _plausible_host(host):
            continue
        # 裸域名只在文本区（注释 / 文档字符串 / 字符串字面量）里算线索。
        # 代码区里 `rect.top`、`el.width`、`obj.value` 这类属性访问天然长成
        # `xxx.top` / `xxx.cc` 的形状，把它们当域名收进来只会给 AD001 送噪音。
        region = source.region(match.start())
        if region not in ("comment", "docstring", "string"):
            continue
        # 已经被带 scheme 的 URL 覆盖过的位置不要重复计一遍
        if any(start <= match.start() < start + 200 and h == host for start, _, h, _, _ in hits):
            continue
        hits.append((match.start(), match.group(1), host, region, True))
    hits.sort()
    return hits


def _scan_blocked_hosts(source, rel_path: str, cfg, findings: List[Finding]) -> None:
    """Report every mention of a blocked host, in **any** file type.

    The rest of the ad rules only run on source code, because a promo sentence in
    a README is normal writing. A blocked domain is different: the whole point of
    the list is "this address is known bad, wherever it appears". Relay endpoints
    live in `.env`, `config.yaml` and `settings.json` far more often than in
    Python — those files used to be skipped wholesale by the ``is_data`` early
    return, so swapping ``OPENAI_BASE_URL`` in a dotfile was invisible.

    Only *blocked* hosts are swept here. Suspicious-looking TLDs stay out: a
    `.top` domain in a data file has too many legitimate reasons to be there, and
    idea.md's false-positive budget does not allow reporting it without context.
    """
    if not cfg.enabled("AD003"):
        return
    # 本工具自己的配置文件里当然写着黑名单本身；报它就是自己举报自己。
    base_name = rel_path.replace("\\", "/").split("/")[-1].lower()
    if base_name in (".dsh-quarantine.yml", ".dsh-quarantine-ignore"):
        return
    blocked = {str(d).lower().strip(".") for d in cfg.allow.get("blocked_domains", [])}
    if not blocked:
        return
    def _blocked(host: str) -> bool:
        return any(host == entry or host.endswith("." + entry) for entry in blocked)

    covered = []  # (start, end) of every URL match, so bare domains inside them skip
    for match in URL_RE.finditer(source.text):
        url = _clean_url(match.group(0))
        host = _host(match.group(0))
        if not host:
            continue
        covered.append((match.start(), match.end()))
        if not _blocked(host):
            continue
        findings.append(
            emit.make(
                cfg,
                "AD003",
                source,
                rel_path,
                match.start(),
                message="外部域名命中风险特征（blocked）: %s" % host,
                severity="CRITICAL",
                extra={"url": url, "host": host, "region": source.region(match.start())},
            )
        )
    # 裸域名：配置里常写成 `OPENAI_BASE_URL=api.relay.example`（无 scheme）。
    # 只认 blocked 列表里的完整主机名，不做任何模糊匹配——这里不是 AD001 的
    # 共现锚点，而是「已知恶意地址出现在任何地方都要报」。
    for match in BARE_DOMAIN_RE.finditer(source.text):
        host = match.group(1).lower()
        if not _blocked(host):
            continue
        if any(start <= match.start() < end for start, end in covered):
            continue
        findings.append(
            emit.make(
                cfg,
                "AD003",
                source,
                rel_path,
                match.start(),
                message="外部域名命中风险特征（blocked）: %s" % host,
                severity="CRITICAL",
                extra={"url": host, "host": host, "region": source.region(match.start())},
            )
        )


def _aux_text_by_line(source) -> Dict[int, str]:
    """Per-line text coming only from comments / docstrings / strings."""
    cache: Dict[int, str] = {}
    for span in source.spans:
        if span.kind not in ("comment", "docstring", "string"):
            continue
        chunk = source.text[span.start:span.end]
        base_line = source.line_of(span.start)
        for i, piece in enumerate(chunk.split("\n")):
            cache.setdefault(base_line + i, "")
            cache[base_line + i] += " " + piece
    return cache


def _line_used_by_network(source, name: str, tokens: List[str]) -> bool:
    pattern = re.compile(r"\b" + re.escape(name) + r"\b")
    masked = source.masked
    for match in pattern.finditer(masked):
        line = source.line_of(match.start())
        text = source.masked_line(line)
        low = text.lower()
        if any(tok.lower() in low for tok in tokens):
            return True
    return False


def _looks_like_comment_line(source, offset: int) -> bool:
    """True when the URL sits on a `#` / `//` comment-looking line inside a string.

    Handles text templates such as ``HEADER = \"\"\"# generated file\\n# http://...\"\"\"``
    where the content is documentation rather than an executable URL.
    """
    line_start = source.offset_of(source.line_of(offset), 0)
    prefix = source.text[line_start:offset].strip()
    return bool(prefix) and prefix[:2] in ("# ", "##", "//") or prefix in ("#", "//")


def _is_ascii_word(ch: str) -> bool:
    """True for an ASCII letter/digit, i.e. something that can extend an identifier.

    Chinese characters are ``str.isalnum()`` in Python, so a naive
    ``ch.isalnum()`` boundary check rejects every Chinese handle outright:
    ``扫码进群`` would be skipped because the next character (``进``) is "alnum".
    Identifier boundaries only exist between ASCII word characters.
    """
    return bool(ch) and ch.isascii() and ch.isalnum()


def _handle_offset(low: str, handle: str) -> int:
    """Position of a promo handle in a lowercased string, or -1.

    Handles are written as bare words (``telegram``) but must not match inside
    identifiers: ``"telegram_oauth": False`` is a config key, not an invitation
    to join a channel, and matching it turned every telemetry/Telegram SDK
    integration into an AD004 hit.
    """
    if not handle:
        return -1
    start = 0
    while True:
        idx = low.find(handle, start)
        if idx < 0:
            return -1
        before = low[idx - 1] if idx > 0 else ""
        after = low[idx + len(handle)] if idx + len(handle) < len(low) else ""
        if _is_ascii_word(handle[-1]) and (after == "_" or _is_ascii_word(after)):
            start = idx + 1
            continue
        if _is_ascii_word(handle[0]) and (before == "_" or _is_ascii_word(before)):
            start = idx + 1
            continue
        return idx


def _contact_hits(text: str, handles: List[str], want_email: bool):
    """Promo handles / e-mail addresses inside one piece of text.

    Returns ``[(offset, kind, value)]`` with ``kind`` in ``{"handle", "email"}``.
    Only the first handle per text run is reported: a single promotional block
    mentioning three channels is one signal, not three.
    """
    hits = []
    low = text.lower()
    for handle in handles:
        idx = _handle_offset(low, handle)
        if idx >= 0:
            hits.append((idx, "handle", handle))
            break
    else:
        if want_email:
            emails = list(EMAIL_RE.finditer(text))
            if 0 < len(emails) <= 2:
                address = emails[0].group(0)
                # `dp@x-force.example.com` 是文档里的示例地址，不是真实联系方式：
                # 与 URL 判定同一条规则——占位域名不构成信号。
                if _plausible_host(address.rsplit("@", 1)[-1].lower()):
                    hits.append((emails[0].start(), "email", address))
    return hits


# 引用式写法：文档字符串里"提到某个资料"而不是"引导你去用某个服务"。
# idea.md 锚点 1 的原话是"单纯的 URL 不足为据"，所以这里只降级、不丢弃：
# 真正的推广注入会被 AD001（话术 + 外链共现）先命中并保持 WARNING。
_CITATION_BEFORE_RE = re.compile(
    r"(?i)(?:^|[\[\(`\s])(?:based\s+on|see\s+also|see|ref|references?|source|sources|"
    r"more|taken\s+from|documented\s+at|documentation|docs?|read\s+more|further|cf\.?|"
    r"per|from|via|e\.g\.?|example|generated\s+with|generated\s+by|"
    r"conformance\s+with|according\s+to|described\s+(?:in|at)|adapted\s+from|"
    r"used\s+by|used\s+in|provided\s+by|available\s+at|quoted\s+from|"
    r"originally\s+from|borrowed\s+from|credit|credits)"
    # 关键字后面只允许空白/冒号，不能跟 `= "` 这类赋值语法：
    # 否则 `DOC = "https://..."` 里的标识符 DOC 会被当成 "docs" 关键字。
    r"\s*[:：]?\s*$"
)
_CITATION_LEAD_RE = re.compile(
    r"(?i)^\s*(?:[#/*>]|-\s|\.\.|[\"']{3}|[\"'])?\s*(?:based\s+on|see\s+also|see|ref|"
    r"source|more|taken\s+from|documented\s+at|reference|according\s+to|"
    r"described\s+(?:in|at)|used\s+by|from)\b"
)
# markdown 引用式链接定义：`[epoch]: https://...`
_MD_REF_DEF_RE = re.compile(r"^\s*\[[^\]\n]+\]:\s*$")


def _is_citation(source, offset: int, url: str) -> bool:
    """True when the URL is a bibliographic reference rather than a call to action."""
    line_no = source.line_of(offset)
    line = source.line_text(line_no)
    line_start = source.offset_of(line_no, 0)
    col = offset - line_start
    tail = line[col + len(url):col + len(url) + 3]

    # markdown 链接 / 图片：[text](url)  ![alt](url)
    if col >= 2 and line[max(0, col - 2):col] == "](":
        return True
    # markdown 引用式定义：[epoch]: https://...
    if _MD_REF_DEF_RE.match(line[:col]):
        return True
    # RST 外链：`text <url>`_
    if "`" in line[:col] and tail.startswith(">`"):
        return True
    # doctest 示例：>>> requests.get("https://...")
    if line.lstrip().startswith(">>>"):
        return True

    if _CITATION_BEFORE_RE.search(line[max(0, col - 60):col]):
        return True
    if _CITATION_LEAD_RE.search(line[:col]):
        return True
    return False



def _py_context(source, url: str) -> Optional[List[Tuple[str, str]]]:
    """Return [(kind, name)] for the call/assignment chain around a URL literal."""
    tree = pyutil.parse(source)
    if tree is None:
        return None
    parents = pyutil.parent_map(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or node.value != url:
            continue
        chain: List[Tuple[str, str]] = []
        cur = parents.get(node)
        while cur is not None:
            if isinstance(cur, ast.Call):
                chain.append(("call", pyutil.dotted_name(cur.func)))
            elif isinstance(cur, ast.Assign):
                for target in cur.targets:
                    chain.append(("assign", pyutil.dotted_name(target)))
            elif isinstance(cur, ast.AnnAssign):
                chain.append(("assign", pyutil.dotted_name(cur.target)))
            elif isinstance(cur, ast.keyword) and cur.arg:
                chain.append(("kwarg", cur.arg))
            cur = parents.get(cur)
        return chain
    return None


def _is_functional(source, url: str, offset: int, cfg) -> bool:
    data = cfg.data("AD002")
    tokens = [str(t) for t in (data.get("network_tokens") or [])]
    config_sinks = [str(t) for t in (data.get("config_sinks") or [])]
    line = source.line_of(offset)
    masked = source.masked_line(line)
    visible = source.nocomment_line(line)
    low = visible.lower()
    if any(tok.lower() in low for tok in tokens):
        return True
    if any(tok.lower() in low for tok in config_sinks):
        return True
    if IDENTIFIER_ASSIGN_RE.search(masked):
        return True
    match = ASSIGN_RE.match(masked)
    if match:
        name = match.group(1)
        if URLISH_NAME_RE.search(name):
            return True
        if _line_used_by_network(source, name, tokens):
            return True
    if source.lang == "python":
        chain = _py_context(source, url)
        if chain is not None:
            for kind, name in chain:
                lname = name.lower()
                if kind == "call" and any(
                    t and (t.lower().rstrip("(").rstrip(".") in lname) for t in tokens + config_sinks
                ):
                    return True
                if kind in ("assign", "kwarg") and URLISH_NAME_RE.search(name):
                    return True
            return False
    return False


def scan(source, rel_path: str, cfg) -> List[Finding]:
    findings: List[Finding] = []
    if source.lang in ("unknown",):
        return findings

    is_doc = cfg.in_doc_path(rel_path)
    is_test = cfg.in_test_path(rel_path)
    is_data = source.lang in DATA_LANGS
    # 黑名单域名不受文件类型限制：`OPENAI_BASE_URL=https://relay.top/v1` 写在
    # .env / config.yaml / settings.json 里的概率远高于写在 .py 里，而这些文件
    # 下面会整体早退。先扫一遍再走常规流程，否则「换个 dotfile 就查不出来」。
    _scan_blocked_hosts(source, rel_path, cfg, findings)
    # 文档/示例目录、纯配置文件不参与注入判定：
    # 前者出现外链是正常写作，后者由 SC109 等供应链规则负责
    if is_doc or is_data:
        return findings
    hits = _url_hits(source, cfg)
    aux = _aux_text_by_line(source) if hits else {}

    ad001 = cfg.data("AD001")
    window = int(ad001.get("window_lines") or 3)
    strong = [str(v) for v in (ad001.get("strong_verbs") or [])]
    weak = [str(v) for v in (ad001.get("weak_verbs") or [])]
    strong_patterns = []
    for raw in (ad001.get("strong_patterns") or []):
        try:
            strong_patterns.append(re.compile(str(raw)))
        except re.error:
            continue

    handled_offsets = set()
    manifest = rel_path.replace("\\", "/").split("/")[-1].lower() in {
        "package.json", "requirements.txt", ".npmrc", "package-lock.json", "yarn.lock", "poetry.lock",
    }

    for offset, url, host, region, bare in hits:
        status = cfg.host_status(host)

        # 项目自己在 package.json / pyproject.toml / README 里声明的站点，
        # 属于"自述文档"而不是被夹带的外链（idea.md 锚点 2 的白名单语义）。
        own_host = cfg.is_own_host(host)

        # --- AD003: blocked / suspicious domain (registry URLs in manifests are
        # handled by SC109 instead, so we do not double-report them here)
        reported = False
        if status in ("blocked", "suspicious") and not manifest:
            if cfg.enabled("AD003"):
                escalate = bool(cfg.data("AD003").get("escalate_in_code", True))
                severity = None
                if status == "blocked" and escalate and region in ("code", "string"):
                    severity = "CRITICAL"
                elif region == "docstring":
                    # 文档字符串里的示例域名属于说明性内容，降级为 INFO
                    severity = "INFO"
                findings.append(
                    emit.make(
                        cfg,
                        "AD003",
                        source,
                        rel_path,
                        offset,
                        message="外部域名命中风险特征（%s）: %s" % (status, host),
                        severity=severity,
                        extra={"url": url, "host": host, "region": region},
                    )
                )
                reported = True

        if status in ("allowed", "reserved"):
            continue
        if is_doc or is_data:
            continue
        if own_host:
            # 自述文档域名：不做注入判定（AD003 已单独处理风险域名）
            continue

        line = source.line_of(offset)

        # --- AD001: promo verb + link proximity
        verb_hit = None
        verb_strength = None
        for delta in range(-window, window + 1):
            text = aux.get(line + delta)
            if not text:
                continue
            low = text.lower()
            for v in strong:
                if v.lower() in low:
                    verb_hit, verb_strength = v, "strong"
                    break
            if verb_hit:
                break
            for phrase in strong_patterns:
                if phrase.search(text):
                    verb_hit, verb_strength = phrase.pattern, "strong"
                    break
            if verb_hit:
                break
            for v in weak:
                if re.search(r"(?<![A-Za-z])" + re.escape(v.lower()) + r"(?![A-Za-z])", low):
                    verb_hit, verb_strength = v, "weak"
                    break
            if verb_hit:
                break

        if cfg.enabled("AD001") and verb_hit and not is_test:
            if verb_strength == "strong" or status == "suspicious":
                findings.append(
                    emit.make(
                        cfg,
                        "AD001",
                        source,
                        rel_path,
                        offset,
                        message="推广话术「%s」与外链共现: %s" % (verb_hit, host),
                        evidence=source.line_text(line).strip(),
                        extra={"url": url, "host": host, "verb": verb_hit, "verb_line": line},
                    )
                )
                reported = True

        if reported or offset in handled_offsets:
            continue

        # 裸域名只做 AD001 的共现锚点，绝不单独成案：`api.example.com` 作为
        # 配置默认值是正常代码，只有旁边站着推广话术时它才是广告。
        if bare:
            continue

        # --- AD002: URL not consumed by any network / link API
        if not cfg.enabled("AD002"):
            continue
        if region in ("comment", "docstring"):
            sev = str(cfg.data("AD002").get("comment_severity") or "info").upper()
            if is_test:
                continue
            citation = _is_citation(source, offset, url)
            if citation and sev == "WARNING":
                # 引用式链接（[docs](url)、Based on: url、`name <url>`_ …）说明的是
                # "这个知识来自哪里"，不是"请你去这个站点"。idea.md 锚点 1 要求
                # 单纯 URL 不足为据，所以保留为 INFO 供人工查看，不升级为告警。
                sev = str(cfg.data("AD002").get("citation_severity") or "INFO").upper()
            findings.append(
                emit.make(
                    cfg,
                    "AD002",
                    source,
                    rel_path,
                    offset,
                    message="注释中出现外部链接（非白名单域名）: %s" % host,
                    severity=sev,
                    confidence="medium",
                    extra={"url": url, "host": host, "region": region, "citation": citation},
                )
            )
        elif region == "string":
            if is_test:
                continue
            if _looks_like_comment_line(source, offset):
                findings.append(
                    emit.make(
                        cfg,
                        "AD002",
                        source,
                        rel_path,
                        offset,
                        message="文本模板中以注释形式出现的外部链接: %s" % host,
                        severity="INFO",
                        confidence="medium",
                        extra={"url": url, "host": host, "region": "template-comment"},
                    )
                )
                continue
            if _is_functional(source, url, offset, cfg):
                continue
            if _is_citation(source, offset, url):
                # 字符串里的引用式链接（多行文档、markdown 表格、>>> 示例）
                # 与注释里的同类写法一视同仁：保留 INFO 供人工查看。
                findings.append(
                    emit.make(
                        cfg,
                        "AD002",
                        source,
                        rel_path,
                        offset,
                        message="文档字符串中的引用式外链: %s" % host,
                        severity=str(cfg.data("AD002").get("citation_severity") or "INFO").upper(),
                        confidence="medium",
                        extra={"url": url, "host": host, "region": region, "citation": True},
                    )
                )
                continue
            findings.append(
                emit.make(
                    cfg,
                    "AD002",
                    source,
                    rel_path,
                    offset,
                    message="代码字符串中的硬编码外链未被网络/链接 API 使用: %s" % host,
                    confidence="medium",
                    extra={"url": url, "host": host, "region": region},
                )
            )

    # --- AD004: contact handles in code strings (WARNING) and in comments (INFO)
    #
    # idea.md 锚点 4 的 WARNING 只针对「代码逻辑区」：写进变量、写进请求体、
    # 写进日志模板的联系方式会真的被发出去。注释不参与执行，`# 有问题联系
    # support@example.com` 是常见的维护说明，直接报 WARNING 会在真实库里刷屏
    # （实测 starlette / fastapi 的 docstring 就有）。所以注释区降一级到 INFO，
    # 但不再像以前那样彻底沉默——「# 售后群：t.me/…」「# 加QQ群 123456789」
    # 这类引导语必须看得见，否则中文推广整类漏检。
    if cfg.enabled("AD004") and not is_doc and not is_test:
        handles = [str(h).lower() for h in (cfg.data("AD004").get("promo_handles") or [])]
        want_email = source.lang not in ("json", "yaml")
        code_sev = str(cfg.data("AD004").get("email_severity") or "WARNING").upper()
        comment_sev = str(cfg.data("AD004").get("comment_severity") or "INFO").upper()
        for span in source.spans_of(("string", "comment", "docstring")):
            text = source.text[span.start:span.end]
            in_code = source.region(span.start) == "string"
            for idx, kind, value in _contact_hits(text, handles, want_email):
                if kind == "handle":
                    message = ("代码逻辑区出现推广性联系方式: %s" % value) if in_code \
                        else ("注释中出现推广性联系方式: %s" % value)
                    extra = {"handle": value, "in_code": in_code}
                else:
                    message = ("代码逻辑区硬编码邮箱地址: %s" % value) if in_code \
                        else ("注释中出现邮箱地址: %s" % value)
                    extra = {"email": value, "in_code": in_code}
                findings.append(
                    emit.make(
                        cfg,
                        "AD004",
                        source,
                        rel_path,
                        span.start + idx,
                        message=message,
                        severity=code_sev if in_code else comment_sev,
                        confidence="medium" if kind == "email" else "high",
                        extra=extra,
                    )
                )

    # --- AD005: external script / iframe / worker injection
    #
    # Test paths are exempt for the same reason AD001/AD002/AD004 exempt them:
    # a security tool's own fixtures are *made of* malicious samples. Reporting
    # them turns every fixture into a CRITICAL and, worse, blocks the agent from
    # writing the very test that proves the rule works. Real pages are unaffected
    # — `in_test_path` only matches tests/ fixtures/ *_test.py and friends.
    if cfg.enabled("AD005") and not is_doc and not is_test:
        cdn = {str(d).lower() for d in (cfg.data("AD005").get("cdn_domains") or [])}
        seen = set()
        for pattern in SCRIPT_SRC_RES:
            for match in pattern.finditer(source.text):
                if source.region(match.start()) == "comment":
                    continue  # 注释掉的标签不是真实加载
                url = _clean_url(match.group(1))
                host = _host(url)
                if not host or host in seen:
                    continue
                status = cfg.host_status(host)
                if status in ("allowed", "reserved"):
                    continue
                seen.add(host)
                severity = "WARNING" if host in cdn else "CRITICAL"
                findings.append(
                    emit.make(
                        cfg,
                        "AD005",
                        source,
                        rel_path,
                        match.start(),
                        message="引入未受信外部资源: %s" % host,
                        severity=severity,
                        extra={"url": url, "host": host},
                    )
                )

    # AD003 与 AD001/AD005 命中同一行时只保留信息量更高的那条，避免同一处外链报三次
    covered = {(f.path, f.line) for f in findings if f.rule_id != "AD003"}
    findings = [
        f for f in findings if not (f.rule_id == "AD003" and (f.path, f.line) in covered)
    ]

    return findings
