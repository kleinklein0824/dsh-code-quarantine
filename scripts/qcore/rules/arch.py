"""Layer 3: normalisation / architecture-deviation detection.

This layer only runs where a real syntax tree is available. Python uses the
stdlib `ast`; other languages require the optional tree-sitter backend. When a
parser is missing we say so in `capabilities` and skip the structural checks
rather than pretending regex output is an AST verdict.
"""

from __future__ import annotations

import ast
import json
import os
import re
from typing import Dict, List, Optional, Set

from .. import emit, pyutil
from ..model import Finding

IO_NET = ("requests.", "httpx.", "urlopen", "socket.create_connection", "subprocess.", "os.system", "os.popen")


def _layer_for(rel_path: str, cfg) -> Optional[List[str]]:
    from ..config import path_matches

    for layer in (cfg.data("AR001").get("layers") or []):
        if not isinstance(layer, dict):
            continue
        glob = str(layer.get("glob") or "")
        if glob and path_matches(rel_path, glob):
            return [str(x) for x in (layer.get("forbid") or [])]
    return None


def _scan_layering(source, rel_path, cfg, findings) -> None:
    if not cfg.enabled("AR001") or source.lang != "python":
        return
    forbid = _layer_for(rel_path, cfg)
    if not forbid:
        return
    tree = pyutil.parse(source)
    if tree is None:
        return
    hits = []
    for module, lineno in pyutil.module_imports(tree):
        root = module.split(".")[0].lower()
        if root in {f.lower() for f in forbid}:
            hits.append((module, lineno))
    if not hits:
        return
    modules = ", ".join(sorted({m for m, _ in hits}))
    first_line = min(line for _, line in hits)
    findings.append(
        emit.make(
            cfg,
            "AR001",
            source,
            rel_path,
            source.offset_of(first_line, 0),
            message="分层违规：该层文件直接导入了外部实现依赖（%s）" % modules,
            extra={"imports": [m for m, _ in hits], "lines": [line for _, line in hits]},
        )
    )


def _is_main_guard(node: ast.AST) -> bool:
    if not isinstance(node, ast.If):
        return False
    test = node.test
    return isinstance(test, ast.Compare) and "__name__" in ast.unparse(test)


def _module_level_calls(tree) -> List[ast.Call]:
    calls: List[ast.Call] = []

    def visit(stmt):
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return
        if _is_main_guard(stmt):
            return
        if isinstance(stmt, ast.If):
            for sub in stmt.body + stmt.orelse:
                visit(sub)
            return
        if isinstance(stmt, ast.Try):
            for sub in stmt.body + stmt.orelse + stmt.finalbody:
                visit(sub)
            for handler in stmt.handlers:
                for sub in handler.body:
                    visit(sub)
            return
        for node in ast.walk(stmt):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(node, ast.Call):
                calls.append(node)

    for stmt in tree.body:
        visit(stmt)
    return calls


def _scan_module_side_effects(source, rel_path, cfg, findings) -> None:
    if not cfg.enabled("AR002") or source.lang != "python":
        return
    tree = pyutil.parse(source)
    if tree is None:
        return
    targets = [str(t) for t in (cfg.data("AR002").get("side_effect_calls") or [])]
    write_modes = {str(m) for m in (cfg.data("AR002").get("file_write_modes") or [])}
    for call in _module_level_calls(tree):
        name = pyutil.dotted_name(call.func)
        hit = next((t for t in targets if name == t or name.startswith(t + ".")), None)
        if not hit and name in ("open", "io.open"):
            for arg in list(call.args[1:2]) + [kw.value for kw in call.keywords if kw.arg == "mode"]:
                if isinstance(arg, ast.Constant) and str(arg.value) in write_modes:
                    hit = "open(..., mode=%s)" % arg.value
                    break
        if hit:
            findings.append(
                emit.make(
                    cfg,
                    "AR002",
                    source,
                    rel_path,
                    source.offset_of(call.lineno, call.col_offset),
                    message="模块导入即产生副作用: %s" % hit,
                    extra={"call": hit},
                )
            )


def _scan_suspicious_names(source, rel_path, cfg, findings) -> None:
    if not cfg.enabled("AR003") or source.lang != "python":
        return
    tree = pyutil.parse(source)
    if tree is None:
        return
    patterns = []
    for raw in (cfg.data("AR003").get("name_patterns") or []):
        try:
            patterns.append(re.compile(str(raw)))
        except re.error:
            continue
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for pattern in patterns:
            if pattern.search(node.name):
                findings.append(
                    emit.make(
                        cfg,
                        "AR003",
                        source,
                        rel_path,
                        source.offset_of(node.lineno, node.col_offset),
                        message="可疑命名「%s」：与后门/绕过语义高度相关" % node.name,
                        extra={"symbol": node.name},
                    )
                )
                break


def _scan_io_in_ctor(source, rel_path, cfg, findings) -> None:
    if not cfg.enabled("AR006") or source.lang != "python":
        return
    tree = pyutil.parse(source)
    if tree is None:
        return
    io_calls = [str(t) for t in (cfg.data("AR006").get("io_calls") or [])]
    write_modes = {"w", "wb", "a", "ab", "x", "xb"}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        is_prop = any(
            pyutil.dotted_name(getattr(d, "func", d)) == "property" for d in node.decorator_list
        )
        if node.name != "__init__" and not is_prop:
            continue
        for call, name in pyutil.iter_calls(node):
            hit = next((t for t in io_calls if name == t or name.startswith(t + ".")), None)
            if hit == "open":
                modes = [kw.value for kw in call.keywords if kw.arg == "mode"]
                modes += list(call.args[1:2])
                if not any(isinstance(m, ast.Constant) and str(m.value) in write_modes for m in modes):
                    continue
            if hit:
                findings.append(
                    emit.make(
                        cfg,
                        "AR006",
                        source,
                        rel_path,
                        source.offset_of(call.lineno, call.col_offset),
                        message="%s 中执行 I/O: %s" % (
                            "__init__" if node.name == "__init__" else "@property " + node.name,
                            hit,
                        ),
                        extra={"call": hit},
                    )
                )
                break


# --------------------------------------------------------------- baseline
def _public_symbols(tree) -> Dict[str, object]:
    out: Dict[str, object] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and pyutil.is_public(node.name):
            out[node.name] = pyutil.signature(node)
        elif isinstance(node, ast.ClassDef) and pyutil.is_public(node.name):
            methods = {}
            for sub in node.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
                    pyutil.is_public(sub.name) or sub.name == "__init__"
                ):
                    methods[sub.name] = pyutil.signature(sub)
            out[node.name] = methods
    return out


def build_baseline(sources) -> Dict[str, object]:
    files: Dict[str, object] = {}
    for source in sources:
        if source.lang != "python":
            continue
        tree = pyutil.parse(source)
        if tree is None:
            continue
        files[source.rel_path] = _public_symbols(tree)
    return {"version": 1, "generated_by": "dsh-code-quarantine", "files": files}


def _drift_suffix(tests_changed: Optional[bool]) -> str:
    """How to phrase the "test not updated" clause, honestly.

    The rule message promises "且未见对应测试更新", but a full scan has no idea
    what changed since the baseline was written — every test file is present and
    "present" is not "updated". Claiming a missing test update there would be
    exactly the inference idea.md forbids. Only the incremental path knows.
    """
    if tests_changed is False:
        return "，且未见对应测试更新"
    return ""


def _scan_baseline_drift(source, rel_path, cfg, findings, baseline, tests_changed: Optional[bool] = None) -> None:
    if not cfg.enabled("AR004") or source.lang != "python" or not baseline:
        return
    # A signature change is expected when the tests moved with it. Suppressing
    # here is the whole point of the clause: otherwise AR004 fires on every
    # deliberate refactor and the rule gets switched off.
    if tests_changed is True:
        return
    suffix = _drift_suffix(tests_changed)
    expected = (baseline.get("files") or {}).get(rel_path)
    if expected is None:
        return
    tree = pyutil.parse(source)
    if tree is None:
        return
    current = _public_symbols(tree)
    line_by_name = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            line_by_name[node.name] = source.offset_of(node.lineno, node.col_offset)

    for name, old in expected.items():
        new = current.get(name)
        if new is None:
            findings.append(
                emit.make(
                    cfg,
                    "AR004",
                    source,
                    rel_path,
                    source.offset_of(1, 0),
                    message="公共符号「%s」在变更后被删除或不再导出" % name + suffix,
                    confidence="medium",
                    extra={"symbol": name, "change": "removed"},
                )
            )
            continue
        if isinstance(old, str) and isinstance(new, str):
            if old != new:
                findings.append(
                    emit.make(
                        cfg,
                        "AR004",
                        source,
                        rel_path,
                        line_by_name.get(name, 0),
                        message="公共函数「%s」签名变更: %s -> %s" % (name, old, new) + suffix,
                        extra={"symbol": name, "change": "signature", "before": old, "after": new},
                    )
                )
        elif isinstance(old, dict) and isinstance(new, dict):
            for method, old_sig in old.items():
                new_sig = new.get(method)
                if new_sig is None:
                    findings.append(
                        emit.make(
                            cfg,
                            "AR004",
                            source,
                            rel_path,
                            line_by_name.get(name, 0),
                            message="公共方法「%s.%s」被移除" % (name, method) + suffix,
                            confidence="medium",
                            extra={"symbol": name + "." + method, "change": "removed"},
                        )
                    )
                elif old_sig != new_sig:
                    findings.append(
                        emit.make(
                            cfg,
                            "AR004",
                            source,
                            rel_path,
                            line_by_name.get(name, 0),
                            message="公共方法「%s.%s」签名变更: %s -> %s" % (name, method, old_sig, new_sig) + suffix,
                            extra={"symbol": name + "." + method, "change": "signature"},
                        )
                    )


# ---------------------------------------------------------------- cycles
def _module_name(rel_path: str) -> str:
    path = rel_path.replace("\\", "/")
    for prefix in ("src/", "lib/", "app/"):
        if path.startswith(prefix):
            path = path[len(prefix):]
            break
    if path.endswith(".py"):
        path = path[:-3]
    if path.endswith("/__init__"):
        path = path[: -len("/__init__")]
    return path.replace("/", ".")


def scan_project(sources, cfg, changed: Optional[Set[str]] = None) -> List[Finding]:
    """Cross-file checks (import cycles). Called once per scan run."""
    findings: List[Finding] = []
    if not cfg.enabled("AR005"):
        return findings
    py_sources = [s for s in sources if s.lang == "python" and s.tree is not None]
    if len(py_sources) < 2:
        return findings
    names = {_module_name(s.rel_path): s for s in py_sources}
    graph: Dict[str, Set[str]] = {}
    for source in py_sources:
        mod = _module_name(source.rel_path)
        edges: Set[str] = set()
        for module, _ in pyutil.module_imports(source.tree):
            if module in names and module != mod:
                edges.add(module)
            for known in names:
                if module.startswith(known + ".") and known != mod:
                    edges.add(known)
        graph[mod] = edges

    max_len = int(cfg.data("AR005").get("max_cycle_len") or 6)
    reported: Set[frozenset] = set()
    cycles = []
    for start in graph:
        stack = [(start, [start])]
        while stack:
            node, path = stack.pop()
            if len(path) > max_len:
                continue
            for nxt in graph.get(node, ()):
                if nxt == start and len(path) >= 2:
                    key = frozenset(path)
                    if key in reported:
                        continue
                    reported.add(key)
                    cycles.append(path)
                elif nxt not in path:
                    stack.append((nxt, path + [nxt]))

    # 全量模式下无法判断"新增"，只作提示；有变更范围时才升级为告警
    severity = "WARNING" if changed else "INFO"
    limit = 20
    for path in cycles[:limit]:
        involved = [names[m] for m in path if m in names]
        if not involved:
            continue
        if changed is not None and not any(s.rel_path in changed for s in involved):
            continue
        source = involved[0]
        findings.append(
            emit.make(
                cfg,
                "AR005",
                source,
                source.rel_path,
                source.offset_of(1, 0),
                message="循环依赖: %s" % " -> ".join(path + [path[0]]),
                severity=severity,
                confidence="medium",
                extra={"cycle": path + [path[0]]},
            )
        )
    return findings


def scan(source, rel_path, cfg, baseline=None, tests_changed: Optional[bool] = None) -> List[Finding]:
    findings: List[Finding] = []
    _scan_layering(source, rel_path, cfg, findings)
    _scan_module_side_effects(source, rel_path, cfg, findings)
    _scan_suspicious_names(source, rel_path, cfg, findings)
    _scan_io_in_ctor(source, rel_path, cfg, findings)
    _scan_baseline_drift(source, rel_path, cfg, findings, baseline, tests_changed)
    return findings


def load_baseline(path: str) -> Optional[dict]:
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def save_baseline(path: str, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
