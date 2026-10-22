"""Scan orchestration: file collection, batching, per-file and project rules."""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from . import __version__
from . import emit
from .config import Config
from .lexer import AST_LANGS_BUILTIN, Source, detect_language
from .model import Finding, ScanResult
from .rules import ad, arch, supply

DEFAULT_EXCLUDES = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "bower_components",
    "vendor",
    "dist",
    "build",
    "out",
    "target",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".next",
    ".nuxt",
    ".svelte-kit",
    "site-packages",
    "coverage",
    ".idea",
    ".vscode",
    "Pods",
    ".gradle",
    ".terraform",
    ".workbuddy-ai",
}

BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".svgz",
    ".pdf", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war",
    ".exe", ".dll", ".so", ".dylib", ".a", ".lib", ".o", ".obj", ".class", ".pyc",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".mov", ".avi",
    ".db", ".sqlite", ".sqlite3", ".bin", ".dat", ".parquet", ".pkl", ".h5",
}

STATE_FILE = ".dsh-quarantine-state.json"
MAX_BYTES_DEFAULT = 512 * 1024

# 「这个文件把应用指向了某个服务器」。用于把没有规则命中、但改了端点配置的文件
# 也送进 AI 复核——端点替换天然不触发任何模式（中转站就是个普通 .com），
# 规则层看不见它，只能靠语义判断。
ENDPOINT_ASSIGN_RE = re.compile(
    r"""(?ix)
    (?:base[_-]?url | baseURL | api[_-]?base | apiBase | endpoint | azure[_-]endpoint
     | openai[_-]?base[_-]?url | anthropic[_-]?base[_-]?url | proxy[_-]?url)
    \s*[:=]\s*
    [\'"`]?(?:https?://)?([A-Za-z0-9.\-]+)
    """
)


class ScanOptions:
    def __init__(
        self,
        mode: str = "full",
        files: Optional[Sequence[str]] = None,
        since: Optional[str] = None,
        include_tests: bool = False,
        max_file_size: int = MAX_BYTES_DEFAULT,
        batch_size: int = 40,
        write_state: bool = True,
        baseline: Optional[dict] = None,
        llm=None,
        llm_deep: bool = False,
    ) -> None:
        self.mode = mode
        self.files = list(files or [])
        self.since = since
        self.include_tests = include_tests
        self.max_file_size = max_file_size
        self.batch_size = batch_size
        self.write_state = write_state
        self.baseline = baseline
        self.llm = llm
        self.llm_deep = llm_deep


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data[:4096]


class GitError(RuntimeError):
    """A git operation failed for a reason the caller must not silently ignore."""


def _git_run(root: str, args: List[str]) -> Optional[List[str]]:
    try:
        proc = subprocess.run(
            ["git", "-C", root] + args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def _git_changed(root: str, since: Optional[str]) -> Optional[List[str]]:
    """Changed files since a ref, or None when the target is not a git repo.

    A bad ref must never degrade into "no files changed": that turns a broken
    audit into a green SAFE verdict. We raise GitError so the caller can fail
    loudly instead of reporting an empty, clean result.
    """
    if _git_run(root, ["rev-parse", "--is-inside-work-tree"]) is None:
        return None
    target = since or "HEAD"
    if since:
        if _git_run(root, ["rev-parse", "--verify", "--quiet", "%s^{commit}" % since]) is None:
            raise GitError("无法解析的 git 引用: %s" % since)
    diff = _git_run(root, ["diff", "--name-only", "--diff-filter=ACMR", target])
    if diff is None:
        raise GitError("git diff 失败: %s" % target)
    untracked = _git_run(root, ["ls-files", "--others", "--exclude-standard"])
    if untracked is None:
        raise GitError("git ls-files 失败")
    return sorted(set(diff) | set(untracked))


def _state_path(root: str) -> str:
    return os.path.join(root, STATE_FILE)


def _load_state(root: str) -> dict:
    try:
        with open(_state_path(root), "r", encoding="utf-8") as fh:
            return json.load(fh) or {}
    except (OSError, ValueError):
        return {}


def _save_state(root: str, payload: dict) -> None:
    try:
        with open(_state_path(root), "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
    except OSError:
        pass


def collect_files(root: str, cfg: Config, opts: ScanOptions) -> Tuple[List[str], List[Tuple[str, str]]]:
    """Return (relative file paths, [(rel_path, skip_reason)])."""
    selected: List[str] = []
    skipped: List[Tuple[str, str]] = []

    if opts.mode == "files" and opts.files:
        for item in opts.files:
            rel = os.path.relpath(item, root) if os.path.isabs(item) else item
            rel = rel.replace("\\", "/")
            abs_path = os.path.join(root, rel)
            if not os.path.isfile(abs_path):
                skipped.append((rel, "not-found"))
                continue
            selected.append(rel)
        return sorted(set(selected)), skipped

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames if d not in DEFAULT_EXCLUDES and not d.startswith(".git")
        )
        for name in sorted(filenames):
            abs_path = os.path.join(dirpath, name)
            rel = os.path.relpath(abs_path, root).replace("\\", "/")
            ext = os.path.splitext(name)[1].lower()
            if name in (STATE_FILE, ".dsh-quarantine-baseline.json", ".dsh-quarantine-last.json",
                        ".dsh-quarantine-panel.json"):
                skipped.append((rel, "tool-artifact"))
                continue
            if ext in BINARY_EXTS:
                skipped.append((rel, "binary"))
                continue
            if ".min." in name or name.endswith(".map"):
                skipped.append((rel, "minified"))
                continue
            try:
                size = os.path.getsize(abs_path)
            except OSError:
                skipped.append((rel, "unreadable"))
                continue
            if size > opts.max_file_size:
                skipped.append((rel, "too-large"))
                continue
            lang = detect_language(rel)
            if lang == "unknown":
                skipped.append((rel, "unknown-language"))
                continue
            selected.append(rel)

    if not opts.include_tests:
        kept = []
        for rel in selected:
            if cfg.in_test_path(rel):
                skipped.append((rel, "test-path"))
                continue
            kept.append(rel)
        selected = kept

    return sorted(set(selected)), skipped


def _read_source(root: str, rel: str) -> Optional[Source]:
    abs_path = os.path.join(root, rel)
    try:
        with open(abs_path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return None
    if _is_binary(raw):
        return None
    text = raw.decode("utf-8", errors="replace")
    source = Source(abs_path, text)
    source.rel_path = rel
    return source


def scan_source(
    source: Source,
    cfg: Config,
    baseline: Optional[dict] = None,
    tests_changed: Optional[bool] = None,
) -> List[Finding]:
    rel = source.rel_path
    findings: List[Finding] = []
    findings.extend(ad.scan(source, rel, cfg))
    findings.extend(supply.scan(source, rel, cfg))
    findings.extend(arch.scan(source, rel, cfg, baseline, tests_changed))
    return findings


def collect_sources(root: str, cfg: Config, opts: ScanOptions) -> List[Source]:
    """Read every in-scope file into a Source (used for baseline generation)."""
    files, _ = collect_files(os.path.abspath(root), cfg, opts)
    sources: List[Source] = []
    for rel in files:
        source = _read_source(os.path.abspath(root), rel)
        if source is not None:
            sources.append(source)
    return sources


def _capabilities(sources: Iterable[Source]) -> Dict[str, object]:
    langs = sorted({s.lang for s in sources})
    ast_langs = sorted(set(langs) & AST_LANGS_BUILTIN)
    lexical_only = sorted(set(langs) - AST_LANGS_BUILTIN)
    return {
        "languages": langs,
        "ast_available": ast_langs,
        "lexical_only": lexical_only,
        "architecture_checks": bool(ast_langs),
        "tree_sitter": False,
        "note": "架构级检查仅对具备语法树的语言启用；其余语言只做词法层检测。",
    }


def _mentions_an_endpoint(source) -> bool:
    """Whether the file assigns an API endpoint / base URL at all.

    The review loop skips files with no rule hits, which is right for cost: most
    files have nothing to say. But endpoint replacement is invisible to the rules
    by construction — swapping ``base_url`` to an ordinary-looking ``.com`` trips
    no pattern, and that is precisely the move a poisoned relay makes. So this
    cheap prefilter widens the gate by exactly one class of file: the ones that
    point the app at a server.

    Deliberately narrow. A broad "contains a URL" test would send every file with
    a doc link to the model and burn the call budget on READMEs.
    """
    return bool(ENDPOINT_ASSIGN_RE.search(source.nocomment))


def _apply_llm_review(root: str, opts: ScanOptions, sources, findings, notes, blocked=None) -> dict:
    """把规则结果交给模型复核；任何异常都只降级，不影响结论。

    ``blocked`` 是黑名单主机名列表，原样传给模型做逐字比对。规则层已经能在
    任何文件类型里抓到黑名单地址（AD003），AI 这一层的价值在于抓**规则看不出来
    的端点替换**——`base_url` 被赋成一个普通的、不在任何可疑 TLD 列表里的域名。
    """
    from . import llm as llm_mod
    from .model import Finding

    cfg = opts.llm
    stats = {"enabled": True, "ready": bool(getattr(cfg, "ready", False)),
             "model": getattr(cfg, "model", ""), "calls": 0, "suppressed": 0,
             "added": 0, "cached": 0, "errors": []}
    if not getattr(cfg, "ready", False):
        stats["enabled"] = False
        notes.append(
            "AI 复核未启用：缺少 base_url / model / api_key（检测到的对话模型：%s）"
            % (getattr(cfg, "host_model", "") or "未知")
        )
        return stats

    cache = llm_mod.load_cache(root)
    by_path = {}
    for finding in findings:
        by_path.setdefault(finding.path, []).append(finding)

    drop = []
    for source in sources:
        file_findings = by_path.get(source.rel_path, [])
        if not file_findings and not opts.llm_deep and not _mentions_an_endpoint(source):
            continue
        if stats["calls"] >= cfg.max_calls:
            stats["errors"].append("达到单次扫描调用上限 %d" % cfg.max_calls)
            break
        result = llm_mod.review_file(cfg, source, file_findings, cache, blocked=blocked)
        stats["calls"] += 1
        if result.get("cached"):
            stats["cached"] += 1
        if result["error"]:
            stats["errors"].append("%s: %s" % (source.rel_path, result["error"]))
            continue

        rejected = set()
        for key, verdict in result["verdicts"].items():
            if verdict.get("keep", True):
                continue
            rule_id, _, line = key.partition(":")
            try:
                rejected.add((rule_id.strip(), int(line)))
            except ValueError:
                continue
        for finding in file_findings:
            if (finding.rule_id, finding.line) not in rejected:
                continue
            # 模型不能推翻 CRITICAL：被注入的代码可能诱导模型把真问题判成误报
            if finding.severity == "CRITICAL":
                stats.setdefault("refused", 0)
                stats["refused"] += 1
                continue
            verdict = result["verdicts"].get("%s:%d" % (finding.rule_id, finding.line), {})
            confidence = verdict.get("confidence")
            if isinstance(confidence, (int, float)) and confidence < 0.6:
                stats.setdefault("refused", 0)
                stats["refused"] += 1
                continue
            finding.extra["ai_verdict"] = "suppressed"
            drop.append(finding)

        for item in result["missed"]:
            line = int(item.get("line") or 0)
            if line < 1 or line > len(source.lines):
                continue
            severity = item.get("severity") or "WARNING"
            if severity not in ("CRITICAL", "WARNING", "INFO"):
                severity = "WARNING"
            # 模型是这条链路上唯一"可被说服"的组件：中转站被投毒、仓库里藏了诱导
            # 提示词，都可能让它凭空补一条 CRITICAL 出来。而 CRITICAL 会直接阻塞
            # 写入、翻转退出码。所以 AI001 最高只到 WARNING——补漏可以，判定权不行。
            if severity == "CRITICAL":
                severity = "WARNING"
            findings.append(Finding(
                rule_id="AI001",
                severity=severity,
                category="ai_review",
                path=source.rel_path,
                line=line,
                column=1,
                message=item.get("reason") or "AI 复核发现语义级问题",
                evidence=source.line_text(line).strip(),
                suggestion=item.get("suggestion") or "",
                confidence="medium",
                extra={"source": "llm", "model": cfg.model},
            ))
            stats["added"] += 1

    if drop:
        keep = [f for f in findings if f not in drop]
        stats["suppressed"] = len(drop)
        findings[:] = keep

    if stats["errors"]:
        notes.append("AI 复核部分失败：%s" % "；".join(stats["errors"][:3]))
    if stats["calls"]:
        notes.append(
            "AI 复核（%s）：调用 %d 次，排除误报 %d 条，补漏 %d 条%s"
            % (cfg.model, stats["calls"], stats["suppressed"], stats["added"],
               "，拒绝推翻 %d 条 CRITICAL/低置信度结论" % stats["refused"] if stats.get("refused") else "")
        )
    llm_mod.save_cache(root, cache)
    return stats


def run_scan(root: str, cfg: Config, opts: ScanOptions) -> ScanResult:
    started = time.time()
    root = os.path.abspath(root)
    result = ScanResult(root=root, mode=opts.mode, version=__version__)

    # 规则目录配错时，扫描器"扫了但没规则可判"看起来和"扫了没发现问题"一模一样。
    # 一次空跑被读成 SAFE 比直接报错危险得多，所以这里直接判为未完成。
    if cfg.rules_missing:
        result.error = "规则未完整加载：%s" % "、".join(cfg.rules_missing)
        result.notes.extend(cfg.warnings)
        result.duration_ms = int((time.time() - started) * 1000)
        return result

    changed: Optional[Set[str]] = None
    if opts.mode in ("incremental", "since"):
        try:
            git_files = _git_changed(root, opts.since)
        except GitError as exc:
            # 引用解析失败时不能退化成"没有变更"：那会把一次坏审计伪装成 SAFE。
            result.error = str(exc)
            result.notes.append("增量范围解析失败：%s" % exc)
            result.duration_ms = int((time.time() - started) * 1000)
            return result
        if git_files is not None:
            changed = set(git_files)
            result.notes.append("增量范围来自 git diff（%d 个文件）" % len(changed))
        else:
            state = _load_state(root)
            last = state.get("last_scan_epoch") or 0
            changed = set()
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if d not in DEFAULT_EXCLUDES]
                for name in filenames:
                    abs_path = os.path.join(dirpath, name)
                    try:
                        if os.path.getmtime(abs_path) > last:
                            changed.add(os.path.relpath(abs_path, root).replace("\\", "/"))
                    except OSError:
                        continue
            result.notes.append(
                "未检测到 git 仓库，增量范围回退为「上次扫描后修改的文件」（%d 个）" % len(changed)
            )

    files, skipped = collect_files(root, cfg, opts)
    if changed is not None:
        files = [f for f in files if f in changed]
    result.skipped = skipped

    # AR004 promises "且未见对应测试更新". Only the incremental path can honour
    # that: there `changed` is the exact set of touched files, so a test file in
    # it means the author moved the tests with the signature. In a full scan
    # every test file is present, and "present" is not "updated" — claiming
    # otherwise would be the inference idea.md forbids, so it stays None and the
    # message simply does not make the claim.
    tests_changed: Optional[bool] = None
    if changed is not None:
        tests_changed = any(cfg.in_test_path(rel) for rel in changed)

    sources: List[Source] = []
    batch_size = max(1, opts.batch_size)
    for index in range(0, len(files), batch_size):
        batch = files[index : index + batch_size]
        for rel in batch:
            source = _read_source(root, rel)
            if source is None:
                result.skipped.append((rel, "unreadable"))
                continue
            sources.append(source)
            result.scanned.append(rel)
            result.findings.extend(scan_source(source, cfg, opts.baseline, tests_changed))

    result.findings.extend(arch.scan_project(sources, cfg, changed))

    llm_stats = {}
    if opts.llm is not None:
        blocked_hosts = [str(d).lower() for d in (cfg.allow.get("blocked_domains") or [])]
        llm_stats = _apply_llm_review(root, opts, sources, result.findings, result.notes, blocked_hosts)

    # exemptions, disabled rules, dedupe
    kept: List[Finding] = []
    for finding in result.findings:
        if not cfg.enabled(finding.rule_id):
            continue
        if cfg.is_ignored(finding.rule_id, finding.path):
            continue
        kept.append(finding)
    result.findings = emit.dedupe(kept)
    result.findings.sort(key=lambda f: (-f.rank, f.category, f.path, f.line, f.rule_id))
    result.capabilities = _capabilities(sources)
    if llm_stats:
        result.capabilities["llm"] = llm_stats
    result.duration_ms = int((time.time() - started) * 1000)

    if opts.write_state and opts.mode in ("full", "incremental", "since", "files"):
        _save_state(
            root,
            {
                "last_scan_epoch": time.time(),
                "last_scan_iso": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "scanned_files": len(result.scanned),
                "version": __version__,
            },
        )
    return result


def scan_text(text: str, rel_path: str, cfg: Config, baseline: Optional[dict] = None) -> ScanResult:
    """Snippet mode: scan a single in-memory buffer (hook / pre-write gate)."""
    started = time.time()
    result = ScanResult(root=os.path.dirname(rel_path) or ".", mode="snippet", version=__version__)
    if cfg.rules_missing:
        # 规则没加载全时 hook 也不能说"这段代码没问题"。
        result.error = "规则未完整加载：%s" % "、".join(cfg.rules_missing)
        result.notes.extend(cfg.warnings)
        result.duration_ms = int((time.time() - started) * 1000)
        return result
    source = Source(rel_path, text)
    source.rel_path = rel_path
    result.scanned.append(rel_path)
    findings = scan_source(source, cfg, baseline)
    kept = [
        f
        for f in findings
        if cfg.enabled(f.rule_id) and not cfg.is_ignored(f.rule_id, rel_path)
    ]
    result.findings = sorted(
        emit.dedupe(kept), key=lambda f: (-f.rank, f.category, f.path, f.line, f.rule_id)
    )
    result.capabilities = _capabilities([source])
    result.duration_ms = int((time.time() - started) * 1000)
    return result
