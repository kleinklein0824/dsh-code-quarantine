"""Layer 2: supply-chain poisoning / malicious code features.

Covers dynamic execution, remote shell pipes, credential exfiltration,
obfuscated payloads, dependency manifest poisoning and TLS downgrades.
"""

from __future__ import annotations

import ast
import json
import os
import re
from typing import Dict, List, Optional, Tuple

from .. import emit, payload, pyutil
from ..model import Finding

NETWORK_HINT = re.compile(
    r"(requests\.|httpx\.|urllib|urlopen|socket\.|aiohttp|fetch\(|axios|http\.request"
    r"|net\.connect|WebClient|HttpClient|curl\s|wget\s)",
    re.I,
)

DEP_FILES = {
    "package.json",
    "requirements.txt",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "pipfile",
    "npmrc",
    ".npmrc",
    ".yarnrc",
    ".yarnrc.yml",
    ".pypirc",
    "pip.conf",
    "package-lock.json",
    "yarn.lock",
    "poetry.lock",
}


def _levenshtein(a: str, b: str, cap: int = 3) -> int:
    if a == b:
        return 0
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
        if min(prev) > cap:
            return cap + 1
    return prev[-1]


# "轻量污点"启发式：动态执行的参数是否直接来自外部输入
TAINT_ARG_RE = re.compile(
    r"(?i)(input\s*\(|stdin|argv|environ|getenv|request|\.body|\.decode\s*\(|\.read\s*\("
    r"|\.recv\s*\(|payload|query|socket\.)"
)


def _is_tainted_arg(node) -> bool:
    if node is None:
        return False
    try:
        expr = ast.unparse(node)
    except Exception:
        return False
    return bool(TAINT_ARG_RE.search(expr))


def _function_text(source, node) -> str:
    start_line = getattr(node, "lineno", 1)
    end_line = getattr(node, "end_lineno", start_line)
    start = source.offset_of(start_line, 0)
    end = source.offset_of(end_line, len(source.line_text(end_line)))
    return source.masked[start:end]


def _scan_dynamic_exec(source, rel_path, cfg, findings) -> None:
    if not cfg.enabled("SC101"):
        return
    data = cfg.data("SC101")
    py_calls = {str(c) for c in (data.get("python_calls") or [])}
    # 属性形式的危险调用：os.system / os.popen 等。它们不是 ast.Name，
    # 早先只判 isinstance(call.func, ast.Name) 导致这类调用被整体漏掉。
    py_attr_calls = {str(c).lower() for c in (data.get("python_attr_calls") or [])}

    if source.lang == "python":
        tree = pyutil.parse(source)
        if tree is None:
            return
        for call, name in pyutil.iter_calls(tree):
            base = name.split(".")[-1]
            is_attr_call = "." in name and name.lower() in py_attr_calls
            if base in py_calls and isinstance(call.func, ast.Name):
                arg = call.args[0] if call.args else None
                literal = isinstance(arg, ast.Constant)
                # compile() 是常规 API（正则/模板编译），动态参数也只作提示
                if base == "compile":
                    severity = "INFO"
                elif literal:
                    severity = "INFO"
                elif _is_tainted_arg(arg):
                    severity = cfg.severity("SC101")
                else:
                    severity = "INFO"
                findings.append(
                    emit.make(
                        cfg,
                        "SC101",
                        source,
                        rel_path,
                        source.offset_of(call.lineno, call.col_offset),
                        message="动态执行调用 %s(%s)" % (
                            base,
                            "字面量" if literal else ("动态参数·来自不可信输入" if severity != "INFO" else "动态参数"),
                        ),
                        severity=severity,
                        confidence="high" if not literal else "medium",
                        extra={"call": base},
                    )
                )
            elif is_attr_call:
                # os.system / os.popen：参数是 shell 命令行本身。
                # 字面量命令行只作 INFO 提示；动态拼接/外部输入的命令是真实风险。
                arg = call.args[0] if call.args else None
                literal = isinstance(arg, ast.Constant)
                severity = "INFO" if literal else cfg.severity("SC101")
                findings.append(
                    emit.make(
                        cfg,
                        "SC101",
                        source,
                        rel_path,
                        source.offset_of(call.lineno, call.col_offset),
                        message="命令执行调用 %s(%s)" % (
                            name,
                            "字面量命令" if literal else "动态命令参数",
                        ),
                        severity=severity,
                        confidence="high",
                        extra={"call": name},
                    )
                )
            elif name.startswith("subprocess."):
                for kw in call.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        findings.append(
                            emit.make(
                                cfg,
                                "SC101",
                                source,
                                rel_path,
                                source.offset_of(call.lineno, call.col_offset),
                                message="subprocess 调用开启 shell=True: %s" % name,
                                extra={"call": name},
                            )
                        )
        return

    js_calls = [str(c) for c in (data.get("js_calls") or [])]
    patterns = []
    if source.lang in ("javascript", "typescript", "vue", "svelte"):
        patterns = [r"\beval\s*\(", r"\bnew\s+Function\s*\(", r"child_process\.exec", r"execSync\s*\("]
        patterns += [re.escape(c) + r"\s*\(" for c in js_calls if c not in ("eval", "Function")]
    elif source.lang in ("shell", "powershell"):
        patterns = [r"\beval\s+"]
    elif source.lang in ("php",):
        patterns = [r"\beval\s*\(", r"\bassert\s*\(", r"\bsystem\s*\(", r"\bpassthru\s*\("]
    for pattern in patterns:
        for match in re.finditer(pattern, source.masked):
            findings.append(
                emit.make(
                    cfg,
                    "SC101",
                    source,
                    rel_path,
                    match.start(),
                    message="动态执行/命令执行调用",
                    confidence="medium",
                )
            )


def _scan_shell_pipes(source, rel_path, cfg, findings) -> None:
    if not cfg.enabled("SC102"):
        return
    for raw in (cfg.data("SC102").get("patterns") or []):
        try:
            pattern = re.compile(str(raw), re.I)
        except re.error:
            continue
        for match in pattern.finditer(source.nocomment):
            findings.append(
                emit.make(
                    cfg,
                    "SC102",
                    source,
                    rel_path,
                    match.start(),
                    message="远程下载后管道执行 / 反弹 shell 特征",
                    evidence=source.line_text(source.line_of(match.start())).strip(),
                )
            )


def _scan_exfil(source, rel_path, cfg, findings) -> None:
    data = cfg.data("SC103")
    sensitive = [str(p) for p in (data.get("sensitive_paths") or [])]
    secret_env = [str(p) for p in (data.get("secret_env") or [])]
    network_sinks = [str(p) for p in (data.get("network_sinks") or [])]

    masked = source.masked
    has_network = any(sink.lower() in masked.lower() for sink in network_sinks)
    if not has_network:
        return

    if cfg.enabled("SC103"):
        for path_token in sensitive:
            # 需要词边界：`.env` 是 `.environ` / `.environment` 的前缀，
            # 裸 re.escape 会把 `os.environ` 当成读 `.env` 文件。
            token_re = re.compile(
                r"(?<![A-Za-z0-9_])" + re.escape(path_token) + r"(?![A-Za-z0-9_])"
                if path_token.startswith(".")
                else re.escape(path_token) + r"(?![A-Za-z0-9_])"
            )
            for match in token_re.finditer(source.nocomment):
                line = source.line_of(match.start())
                # require a network sink in the same function (python) or within 30 lines
                scope_text = None
                if source.lang == "python":
                    tree = pyutil.parse(source)
                    if tree is not None:
                        parents = pyutil.parent_map(tree)
                        node = _node_at(tree, match.start(), source)
                        if node is not None:
                            fn = pyutil.enclosing(node, parents, (ast.FunctionDef, ast.AsyncFunctionDef))
                            if fn is not None:
                                scope_text = _function_text(source, fn)
                if scope_text is None:
                    lo = max(1, line - 30)
                    hi = min(len(source.lines), line + 30)
                    scope_text = source.masked[
                        source.offset_of(lo, 0) : source.offset_of(hi, len(source.line_text(hi)))
                    ]
                if any(sink.lower() in scope_text.lower() for sink in network_sinks):
                    findings.append(
                        emit.make(
                            cfg,
                            "SC103",
                            source,
                            rel_path,
                            match.start(),
                            message="读取凭据类路径「%s」并存在出站请求" % path_token,
                        )
                    )
                    break

        for name in secret_env:
            pattern = re.compile(
                r"(?:environ(?:\.get)?\s*[\[(]\s*[\"']" + re.escape(name) + r"[\"']"
                r"|getenv\s*\(\s*[\"']" + re.escape(name) + r"[\"']"
                r"|process\.env\.\s*" + re.escape(name) + r"\b"
                r"|process\.env\s*\[\s*[\"']" + re.escape(name) + r"[\"']\s*\])",
            )
            for match in pattern.finditer(source.text):
                if _secret_reaches_network(source, match.start(), name, network_sinks):
                    findings.append(
                        emit.make(
                            cfg,
                            "SC103",
                            source,
                            rel_path,
                            match.start(),
                            message="密钥环境变量 %s 经网络请求外发" % name,
                            severity="WARNING",
                            extra={"env": name},
                        )
                    )
                    break

    if cfg.enabled("SC104"):
        for token in (cfg.data("SC104").get("env_dump_tokens") or []):
            token = str(token)
            for match in re.finditer(re.escape(token), source.nocomment):
                line = source.line_of(match.start())
                lo = max(1, line - 15)
                hi = min(len(source.lines), line + 15)
                scope = source.masked[
                    source.offset_of(lo, 0) : source.offset_of(hi, len(source.line_text(hi)))
                ]
                if NETWORK_HINT.search(scope):
                    findings.append(
                        emit.make(
                            cfg,
                            "SC104",
                            source,
                            rel_path,
                            match.start(),
                            message="完整环境变量集合被序列化后外发",
                        )
                    )
                    break


def _node_at(tree, offset: int, source):
    """Find the deepest AST node whose source range contains `offset`."""
    best = None
    best_size = None
    for node in ast.walk(tree):
        if not hasattr(node, "lineno"):
            continue
        start = source.offset_of(node.lineno, node.col_offset)
        end_line = getattr(node, "end_lineno", node.lineno)
        end_col = getattr(node, "end_col_offset", 0)
        end = source.offset_of(end_line, end_col)
        if start <= offset < end:
            size = end - start
            if best_size is None or size < best_size:
                best, best_size = node, size
    return best


def _sink_matches(dotted: str, network_sinks: List[str]) -> bool:
    low = (dotted or "").lower()
    for sink in network_sinks:
        token = sink.lower().rstrip("(").rstrip(".").strip()
        if token and token in low:
            return True
    return False


def _bound_names(node, parents) -> List[str]:
    """Names this expression is assigned to, walking out through Assign/AnnAssign."""
    names: List[str] = []
    cur = parents.get(node)
    while cur is not None:
        if isinstance(cur, ast.Assign):
            for target in cur.targets:
                if isinstance(target, ast.Name):
                    names.append(target.id)
                elif isinstance(target, ast.Attribute):
                    names.append(target.attr)
        elif isinstance(cur, (ast.AnnAssign, ast.NamedExpr)):
            target = getattr(cur, "target", None)
            if isinstance(target, ast.Name):
                names.append(target.id)
        elif isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
            break
        cur = parents.get(cur)
    return names


def _secret_reaches_network(source, offset: int, name: str, network_sinks: List[str]) -> bool:
    """True when a secret env read flows into an outbound network call.

    idea.md asks for the read and the send to be linked "within the same
    function", not "on the same line". A single-line test misses the common
    ``tok = os.environ[...]`` / ``requests.get(..., headers={"A": tok})`` shape,
    so we resolve the assignment target and look for it inside every network
    call in the enclosing scope.
    """
    line = source.line_of(offset)
    if NETWORK_HINT.search(source.masked_line(line)):
        return True

    if source.lang == "python":
        tree = pyutil.parse(source)
        if tree is not None:
            parents = pyutil.parent_map(tree)
            node = _node_at(tree, offset, source)
            if node is not None:
                fn = pyutil.enclosing(
                    node, parents, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                )
                scope = fn if fn is not None else tree
                bound = set(_bound_names(node, parents))
                for call, dotted in pyutil.iter_calls(scope):
                    if not _sink_matches(dotted, network_sinks):
                        continue
                    start = source.offset_of(call.lineno, call.col_offset)
                    end = source.offset_of(
                        getattr(call, "end_lineno", call.lineno),
                        getattr(call, "end_col_offset", call.col_offset),
                    )
                    if start <= offset < end:
                        return True
                    if not bound:
                        continue
                    for inner in ast.walk(call):
                        if isinstance(inner, ast.Name) and inner.id in bound:
                            return True
                        if isinstance(inner, ast.Attribute) and inner.attr in bound:
                            return True
                return False

    # Non-Python (or unparseable): fall back to a scope window, but still
    # require the assigned variable to appear on a line that sends data out.
    scope_start = max(1, line - 30)
    scope_end = min(len(source.lines), line + 30)
    masked_lines = [
        source.masked_line(i) for i in range(scope_start, scope_end + 1)
    ]
    if not any(NETWORK_HINT.search(text) for text in masked_lines):
        return False
    assigned = re.match(r"\s*(?:const|let|var|final|val)?\s*([A-Za-z_$][\w$]*)\s*=", source.masked_line(line))
    if not assigned:
        return False
    var = assigned.group(1)
    for text in masked_lines:
        if NETWORK_HINT.search(text) and re.search(r"\b" + re.escape(var) + r"\b", text):
            return True
    return False


def _scan_payloads(source, rel_path, cfg, findings) -> None:
    if not cfg.enabled("SC105"):
        return
    data = cfg.data("SC105")
    min_len = int(data.get("min_blob_len") or 40)
    max_depth = int(data.get("max_depth") or 2)
    for item in payload.find_payloads(source.text, min_len=min_len, max_depth=max_depth):
        line = source.line_of(item.start)
        evidence = source.line_text(line).strip()
        findings.append(
            emit.make(
                cfg,
                "SC105",
                source,
                rel_path,
                item.start,
                message="%s 编码载荷解码后包含: %s" % (item.kind, item.summary()),
                evidence=evidence,
                extra={"decoded_preview": item.decoded[:200], "signals": item.summary()},
            )
        )


def _scan_tls(source, rel_path, cfg, findings) -> None:
    if not cfg.enabled("SC110"):
        return
    for raw in (cfg.data("SC110").get("patterns") or []):
        try:
            pattern = re.compile(str(raw), re.I)
        except re.error:
            continue
        for match in pattern.finditer(source.nocomment):
            findings.append(
                emit.make(
                    cfg,
                    "SC110",
                    source,
                    rel_path,
                    match.start(),
                    message="显式关闭 TLS 证书校验",
                )
            )


def _scan_chmod_exec(source, rel_path, cfg, findings) -> None:
    """chmod +x followed by running that very file (idea.md §87).

    `curl | bash` is only one way to run remote code; the equivalent
    "download, chmod, execute" sequence leaves no pipe for SC102 to catch.
    """
    if not cfg.enabled("SC111"):
        return
    data = cfg.data("SC111")
    try:
        chmod_re = re.compile(str(data.get("chmod_pattern") or ""), re.I)
    except re.error:
        return
    window = int(data.get("window_lines") or 2)
    if not chmod_re.pattern:
        return

    lines = source.lines
    for match in chmod_re.finditer(source.nocomment):
        target = (match.group(1) or "").strip().strip("\"'")
        if not target or target.startswith("-"):
            continue
        base = os.path.basename(target.rstrip("/")) or target
        line_no = source.line_of(match.start())
        hi = min(len(lines), line_no + window)
        for probe in range(line_no + 1, hi + 1):
            text = source.nocomment_line(probe).strip()
            if not text or text.startswith("#"):
                continue
            if not _line_executes(text, target, base):
                continue
            findings.append(
                emit.make(
                    cfg,
                    "SC111",
                    source,
                    rel_path,
                    match.start(),
                    message="对 %s 赋予可执行权限后立即执行" % base,
                    evidence=source.line_text(line_no).strip(),
                    extra={"target": base, "exec_line": probe},
                )
            )
            break


def _line_executes(text: str, target: str, base: str) -> bool:
    """Does this shell line run `target` (the file just chmod'ed)?"""
    stripped = text.lstrip()
    for prefix in ("./", "sh ", "bash ", "zsh ", "sudo ", "env ", "source ", ". "):
        if stripped.startswith(prefix):
            stripped = stripped[len(prefix):].lstrip()
            break
    # the executed command must be the chmod'ed file itself
    candidate = stripped.split()[0] if stripped.split() else ""
    candidate = candidate.strip("\"'")
    if not candidate:
        return False
    return candidate == target or candidate == base or os.path.basename(candidate) == base


def _scan_js_dynamic_require(source, rel_path, cfg, findings) -> None:
    """require()/import() with a non-literal specifier (idea.md §86)."""
    if not cfg.enabled("SC112"):
        return
    if source.lang not in ("javascript", "typescript", "vue", "svelte", "jsx", "tsx"):
        return
    data = cfg.data("SC112")
    try:
        patterns = [re.compile(str(p)) for p in (data.get("patterns") or [])]
    except re.error:
        return
    for pattern in patterns:
        for match in pattern.finditer(source.nocomment):
            inner = match.group(1) if match.groups() else ""
            if _is_literal_specifier(inner):
                continue
            findings.append(
                emit.make(
                    cfg,
                    "SC112",
                    source,
                    rel_path,
                    match.start(),
                    message="模块加载使用动态变量拼接: %s" % match.group(0).strip()[:80],
                    evidence=source.line_text(source.line_of(match.start())).strip(),
                    extra={"expr": inner.strip()[:120]},
                )
            )


def _is_literal_specifier(inner: str) -> bool:
    """True for require("fs") / import('x') - a plain, statically known string."""
    text = (inner or "").strip()
    if len(text) < 2:
        return False
    if text[0] not in "\"'`" or text[-1] != text[0]:
        return False
    body = text[1:-1]
    if text[0] == "`" and "${" in body:
        return False
    return "+" not in body


# ------------------------------------------------------------- dependencies
def _read_json(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        return json.loads(text)
    except (OSError, ValueError):
        return None


def _scan_package_json(abs_path, rel_path, source, cfg, findings) -> None:
    data = None
    if source is not None and getattr(source, "text", "").strip():
        try:
            data = json.loads(source.text)
        except ValueError:
            data = None
    if not isinstance(data, dict):
        data = _read_json(abs_path)
    if not isinstance(data, dict):
        return
    deps: Dict[str, str] = {}
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        section = data.get(key)
        if isinstance(section, dict):
            deps.update({str(k): str(v) for k, v in section.items()})

    unpinned = {str(t) for t in (cfg.data("SC106").get("unpinned_tokens") or [])}
    if cfg.enabled("SC106"):
        for name, version in deps.items():
            if version.strip() in unpinned:
                findings.append(
                    _dep_finding(
                        cfg, "SC106", source, rel_path, name,
                        "依赖 %s 未锁定版本 (%s)" % (name, version),
                        offset_text='"%s"' % name,
                    )
                )

    if cfg.enabled("SC107"):
        hooks = {str(k) for k in (cfg.data("SC107").get("hook_keys") or [])}
        tokens = [str(t) for t in (cfg.data("SC107").get("suspicious_tokens") or [])]
        scripts = data.get("scripts") or {}
        if isinstance(scripts, dict):
            for key, value in scripts.items():
                if str(key) not in hooks:
                    continue
                text = str(value)
                if any(tok in text for tok in tokens):
                    findings.append(
                        _dep_finding(
                            cfg, "SC107", source, rel_path, str(key),
                            "安装钩子 %s 含下载/执行动作: %s" % (key, text[:120]),
                            offset_text=text,
                        )
                    )

    if cfg.enabled("SC109"):
        registry = None
        publish = data.get("publishConfig")
        if isinstance(publish, dict):
            registry = publish.get("registry")
        if registry:
            host = _host_of(str(registry))
            if host and not cfg.registry_allowed(host):
                findings.append(
                    _dep_finding(
                        cfg, "SC109", source, rel_path, "publishConfig.registry",
                        "发布目标指向非官方 registry: %s" % host, offset_text=str(registry),
                    )
                )

    if cfg.enabled("SC108"):
        _scan_typosquat(deps, source, rel_path, cfg, findings)


def _host_of(url: str) -> str:
    try:
        from urllib.parse import urlsplit

        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _dep_finding(cfg, rule_id, source, rel_path, name, message, offset_text=None) -> Finding:
    line = 1
    if offset_text:
        for i, text in enumerate(source.lines, 1):
            if offset_text[:40] and offset_text[:40] in text:
                line = i
                break
    offset = source.offset_of(line, 0)
    return emit.make(
        cfg,
        rule_id,
        source,
        rel_path,
        offset,
        message=message,
        evidence=source.line_text(line).strip(),
        extra={"dependency": name},
    )


def _scan_typosquat(deps, source, rel_path, cfg, findings) -> None:
    popular = set(cfg.popular_packages())
    cap = int(cfg.data("SC108").get("max_distance") or 2)
    for name in deps:
        low = name.lower()
        if low in popular or low.startswith("@") or "/" in low or ":" in low:
            continue
        for target in popular:
            if abs(len(low) - len(target)) > cap:
                continue
            dist = _levenshtein(low, target, cap)
            if 1 <= dist <= cap and not cfg.known_similar(low, target):
                findings.append(
                    _dep_finding(
                        cfg, "SC108", source, rel_path, name,
                        "依赖名 %s 与知名包 %s 编辑距离 %d，疑似仿冒" % (name, target, dist),
                        offset_text=name,
                    )
                )
                break


def _scan_requirements(abs_path, rel_path, source, cfg, findings) -> None:
    unpinned = {str(t) for t in (cfg.data("SC106").get("unpinned_tokens") or [])}
    for lineno, line in enumerate(source.lines, 1):
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        if text.startswith(("-i ", "--index-url", "--extra-index-url")):
            url = text.split(None, 1)[1] if " " in text else ""
            host = _host_of(url)
            if host and not cfg.registry_allowed(host) and cfg.enabled("SC109"):
                findings.append(
                    emit.make(
                        cfg, "SC109", source, rel_path, source.offset_of(lineno, 0),
                        message="索引源指向非官方 registry: %s" % host,
                        evidence=text,
                    )
                )
            continue
        if text.startswith("-"):
            continue
        name = re.split(r"[<>=!~\[; ]", text, maxsplit=1)[0].strip()
        if not name:
            continue
        if cfg.enabled("SC106"):
            spec = text[len(name):]
            if spec.strip() in ("",) or spec.strip() in unpinned or spec.strip().startswith(">="):
                findings.append(
                    emit.make(
                        cfg, "SC106", source, rel_path, source.offset_of(lineno, 0),
                        message="依赖 %s 未精确锁定版本 (%s)" % (name, spec.strip() or "无版本约束"),
                        evidence=text,
                        severity="INFO",
                    )
                )
        if cfg.enabled("SC108"):
            low = name.lower()
            popular = set(cfg.popular_packages())
            cap = int(cfg.data("SC108").get("max_distance") or 2)
            if low not in popular and "/" not in low:
                for target in popular:
                    if abs(len(low) - len(target)) > cap:
                        continue
                    dist = _levenshtein(low, target, cap)
                    if 1 <= dist <= cap and not cfg.known_similar(low, target):
                        findings.append(
                            emit.make(
                                cfg, "SC108", source, rel_path, source.offset_of(lineno, 0),
                                message="依赖名 %s 与知名包 %s 编辑距离 %d，疑似仿冒" % (name, target, dist),
                                evidence=text,
                            )
                        )
                        break


def _scan_setup_py(source, rel_path, cfg, findings) -> None:
    if not cfg.enabled("SC107"):
        return
    text = source.nocomment
    if "cmdclass" not in text and "install_requires" not in text:
        return
    for token in ("os.system", "subprocess.", "urlopen", "requests.", "eval(", "exec("):
        for match in re.finditer(re.escape(token), text):
            findings.append(
                emit.make(
                    cfg, "SC107", source, rel_path, match.start(),
                    message="setup.py 安装期出现命令/网络调用: %s" % token,
                )
            )


# npm / yarn / pip 的 registry 配置键。同一个文件里可能混用 `key=url`、
# `key = url`、`key "url"`、`key: url` 四种写法，统一按"键 + 分隔符 + 值"处理。
REGISTRY_KEYS = (
    "registry",
    "index-url",
    "extra-index-url",
    "npmRegistryServer",
    "@scope:registry",
)

REGISTRY_FILES = {
    ".npmrc",
    "npmrc",
    ".yarnrc",
    ".yarnrc.yml",
    ".pypirc",
    "pip.conf",
}


def _scan_registry_file(source, rel_path, cfg, findings) -> None:
    """.npmrc / .yarnrc / .yarnrc.yml / .pypirc / pip.conf 里的 registry 指向。

    这些文件都没有扩展名，靠 FILENAME_LANG 识别成 ini/yaml 才能进到这里；
    曾经因为被判成 unknown-language 整个跳过，导致 SC109 在真实项目上完全失效。
    """
    if not cfg.enabled("SC109"):
        return
    key_re = "|".join(re.escape(k) for k in REGISTRY_KEYS)
    pattern = re.compile(r'^\s*(?:@[A-Za-z0-9._-]+:)?(%s)\s*[=:]?\s*["\']?(\S+?)["\']?\s*$'
                         % key_re, re.IGNORECASE)
    for lineno, line in enumerate(source.lines, 1):
        if line.lstrip().startswith(("#", ";")):
            continue
        match = pattern.match(line)
        if not match:
            continue
        value = match.group(2)
        if not value.lower().startswith(("http://", "https://")):
            continue
        host = _host_of(value)
        if host and not cfg.registry_allowed(host):
            findings.append(
                emit.make(
                    cfg, "SC109", source, rel_path, source.offset_of(lineno, 0),
                    message="%s 将 registry 指向非官方源: %s"
                            % (os.path.basename(rel_path), host),
                    evidence=line.strip(),
                )
            )


def _scan_lockfile(source, rel_path, cfg, findings) -> None:
    if not cfg.enabled("SC109"):
        return
    hosts = set()
    for match in re.finditer(r"https?://([A-Za-z0-9.\-]+)", source.text):
        host = match.group(1).lower()
        if host.endswith("npmjs.org") or host.endswith("yarnpkg.com") or host.endswith("npmjs.com"):
            continue
        if host.endswith("github.com") or host.endswith("codeload.github.com"):
            continue
        hosts.add(host)
    for host in sorted(hosts)[:5]:
        line = 1
        for i, text in enumerate(source.lines, 1):
            if host in text:
                line = i
                break
        findings.append(
            emit.make(
                cfg, "SC109", source, rel_path, source.offset_of(line, 0),
                message="lockfile 中存在非官方 registry 地址: %s" % host,
                evidence=source.line_text(line).strip()[:200],
                severity="WARNING",
            )
        )


def scan(source, rel_path: str, cfg) -> List[Finding]:
    findings: List[Finding] = []
    base = os.path.basename(rel_path).lower()

    is_manifest = base in DEP_FILES
    # 依赖清单优先：requirements.txt 会被 **/*.txt 这类文档 glob 命中，不能因此跳过
    if not is_manifest:
        # 文档里的示例命令（curl | bash 之类）属于说明性内容，不是可执行链路
        if cfg.in_doc_path(rel_path) or source.lang in ("markdown", "text"):
            return findings
        # 纯配置/数据文件不承载可执行逻辑，只做依赖清单检查
        if source.lang in ("yaml", "toml", "ini", "dotenv", "json"):
            return findings

    _scan_shell_pipes(source, rel_path, cfg, findings)
    _scan_chmod_exec(source, rel_path, cfg, findings)
    _scan_dynamic_exec(source, rel_path, cfg, findings)
    _scan_js_dynamic_require(source, rel_path, cfg, findings)
    _scan_exfil(source, rel_path, cfg, findings)
    _scan_payloads(source, rel_path, cfg, findings)
    _scan_tls(source, rel_path, cfg, findings)

    if base == "package.json":
        _scan_package_json(source.path, rel_path, source, cfg, findings)
    elif base == "requirements.txt":
        _scan_requirements(source.path, rel_path, source, cfg, findings)
    elif base == "setup.py":
        _scan_setup_py(source, rel_path, cfg, findings)
    elif base in REGISTRY_FILES:
        _scan_registry_file(source, rel_path, cfg, findings)
    elif base in ("package-lock.json", "yarn.lock", "poetry.lock"):
        _scan_lockfile(source, rel_path, cfg, findings)

    return findings
