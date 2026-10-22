"""Rule/allowlist configuration loading and exemption handling."""

from __future__ import annotations

import fnmatch
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import yamlite
from .model import normalize_severity

RULE_FILES = ("ad_injection.yaml", "supply_chain.yaml", "architecture.yaml", "ai_review.yaml")
ALLOW_FILE = "allowlist.yaml"
PROJECT_CONFIG = ".dsh-quarantine.yml"
IGNORE_FILE = ".dsh-quarantine-ignore"

# 项目自身元数据里声明的 URL：这些域名是"自述文档"，不是被夹带的推广外链
META_FILES = (
    "package.json",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "Cargo.toml",
    "composer.json",
    "pubspec.yaml",
    "go.mod",
    "README.md",
    "readme.md",
)
META_URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]+")

# 元数据里出现的这些域名只说明"包托管在哪"，不代表项目自己的站点
_GENERIC_META_HOSTS = {
    "github.com", "gitlab.com", "bitbucket.org", "pypi.org", "files.pythonhosted.org",
    "npmjs.com", "npmjs.org", "yarnpkg.com", "crates.io", "pkg.go.dev", "golang.org",
    "python.org", "readthedocs.org", "readthedocs.io", "opensource.org", "spdx.org",
    "apache.org", "gnu.org", "w3.org", "json-schema.org", "schemas.io",
}


def _host_of(url: str) -> str:
    try:
        from urllib.parse import urlsplit

        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def path_matches(path: str, pattern: str) -> bool:
    """fnmatch with `**/` support for repo-relative posix paths."""
    p = path.replace("\\", "/").lstrip("./")
    pat = pattern.replace("\\", "/").strip()
    if not pat:
        return False
    candidates = [pat]
    if pat.startswith("**/"):
        candidates.append(pat[3:])
    if pat.endswith("/**"):
        candidates.append(pat[:-3])
    for cand in candidates:
        if fnmatch.fnmatchcase(p, cand):
            return True
        if "/" not in cand and fnmatch.fnmatchcase(os.path.basename(p), cand):
            return True
    return False


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


class Config:
    def __init__(
        self,
        rules_dir: str,
        project_root: str = ".",
        config_file: Optional[str] = None,
        ignore_file: Optional[str] = None,
        use_ignore: bool = True,
    ) -> None:
        self.rules_dir = os.path.abspath(rules_dir)
        self.project_root = os.path.abspath(project_root)
        self.rules: Dict[str, Dict[str, Any]] = {}
        self.categories: Dict[str, str] = {}
        self.allow: Dict[str, Any] = {}
        self.ignore_rules: List[Tuple[str, str]] = []
        self.warnings: List[str] = []
        # 缺失/损坏的规则文件。扫描器"什么都没找到"和"根本没有规则"必须能区分，
        # 否则规则目录配错时一次空扫描会被读成 SAFE。
        self.rules_missing: List[str] = []
        self.project_data: Dict[str, Any] = {}
        self._load_rules()
        self._load_allow()
        self._load_project_config(config_file)
        if use_ignore:
            self._load_ignore(ignore_file)
        self.own_hosts: set = set()
        self._load_own_hosts()

    # ------------------------------------------------------- project identity
    def _own_host_candidates(self) -> List[str]:
        """Files that describe the project itself (its own site / docs links).

        Only structured metadata counts: the package's ``Home-page`` /
        ``Project-URL`` headers, ``package.json`` homepage/repository fields,
        ``pyproject.toml`` ``[project.urls]``, and ``setup.py`` ``url=``.
        README is deliberately excluded - it is full of badge and CI links that
        belong to third parties, and a README is trivially editable by whoever
        is trying to smuggle a link in.
        """
        out: List[str] = []
        root = self.project_root
        if not root or not os.path.isdir(root):
            return out
        for name in ("package.json", "pyproject.toml", "setup.py", "setup.cfg"):
            path = os.path.join(root, name)
            if os.path.isfile(path):
                out.append(path)

        # 安装态包目录：同级目录里有 <pkg>-<ver>.dist-info/METADATA
        pkg = os.path.basename(os.path.normpath(root)).lower()
        parent = os.path.dirname(os.path.normpath(root))
        if pkg and parent and os.path.isdir(parent):
            try:
                entries = sorted(os.listdir(parent))
            except OSError:
                return out
            for entry in entries:
                low = entry.lower()
                if not (low.endswith(".dist-info") or low.endswith(".egg-info")):
                    continue
                stem = low.split("-", 1)[0]
                if stem != pkg and not stem.startswith(pkg + "_"):
                    continue
                for meta in ("METADATA", "PKG-INFO"):
                    path = os.path.join(parent, entry, meta)
                    if os.path.isfile(path):
                        out.append(path)
                break
        return out

    @staticmethod
    def _meta_urls(path: str) -> List[str]:
        """Extract only the project's own declared URLs from one metadata file."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read(256 * 1024)
        except OSError:
            return []
        name = os.path.basename(path).lower()
        urls: List[str] = []

        if name in ("metadata", "pkg-info"):
            # RFC 822 headers: Home-page: ... / Project-URL: Label, https://...
            for line in text.splitlines():
                if not line.strip():
                    break  # end of headers, body starts
                key, sep, value = line.partition(":")
                if not sep:
                    continue
                key = key.strip().lower()
                if key == "home-page":
                    urls.append(value.strip())
                elif key == "project-url":
                    _, _, tail = value.partition(",")
                    urls.append((tail or value).strip())
            return urls

        if name == "package.json":
            for field in ("homepage", "repository", "bugs"):
                match = re.search(
                    r'"%s"\s*:\s*(?:"([^"]+)"|\{[^}]*?"url"\s*:\s*"([^"]+)")' % field, text
                )
                if match:
                    urls.append(match.group(1) or match.group(2) or "")
            return urls

        if name in ("pyproject.toml", "setup.cfg"):
            # [project.urls] / [metadata] url = ... / project_urls 下的每一行
            for match in re.finditer(
                r"(?m)^\s*(?:homepage|documentation|repository|source|url|changelog|"
                r"project[_-]?urls?)\s*[=:]\s*(.+)$",
                text,
            ):
                urls.append(match.group(1).strip())
            for match in re.finditer(r"(?m)^\s*[A-Za-z][\w .-]*\s*=\s*[\"']?(https?://\S+)[\"']?\s*$", text):
                urls.append(match.group(1).strip())
            return urls

        if name == "setup.py":
            for match in re.finditer(r"\burl\s*=\s*[\"']([^\"']+)[\"']", text):
                urls.append(match.group(1).strip())
            return urls

        return urls

    def _load_own_hosts(self) -> None:
        """Hosts declared by the scanned project itself (package metadata).

        idea.md 锚点 2 only escalates a link when it is *not* part of the
        project's own dependency or configuration baseline. A library that
        documents its own site (see ``own_hosts`` below) is not injecting
        an ad, and flagging it is exactly the kind of false positive that makes
        teams switch the whole skill off.
        """
        for path in self._own_host_candidates():
            for raw in self._meta_urls(path):
                for match in META_URL_RE.finditer(raw):
                    host = _host_of(match.group(0))
                    if not host or host in _GENERIC_META_HOSTS:
                        continue
                    self.own_hosts.add(host)
                    # 同一个站点的子域也算自述文档（docs./www./api.）
                    parts = host.split(".")
                    for i in range(1, len(parts) - 1):
                        candidate = ".".join(parts[i:])
                        if candidate not in _GENERIC_META_HOSTS and "." in candidate:
                            self.own_hosts.add(candidate)

    def is_own_host(self, host: str) -> bool:
        h = (host or "").lower().strip(".")
        if not h:
            return False
        for own in self.own_hosts:
            if h == own or h.endswith("." + own) or own.endswith("." + h):
                return True
        return False

    # ---------------------------------------------------------------- loading
    def _load_rules(self) -> None:
        for name in RULE_FILES:
            path = os.path.join(self.rules_dir, name)
            if not os.path.isfile(path):
                self.warnings.append("规则文件缺失: %s" % path)
                self.rules_missing.append(name)
                continue
            try:
                data = yamlite.load_file(path) or {}
            except Exception as exc:
                self.warnings.append("规则文件解析失败 %s: %s" % (name, exc))
                self.rules_missing.append(name)
                continue
            category = data.get("category") or name.replace(".yaml", "")
            loaded = 0
            for rule in data.get("rules") or []:
                if not isinstance(rule, dict) or not rule.get("id"):
                    continue
                rid = str(rule["id"])
                rule = dict(rule)
                rule["category"] = category
                rule["severity"] = normalize_severity(rule.get("severity"), "WARNING")
                rule["enabled"] = bool(rule.get("enabled", True))
                rule.setdefault("data", {})
                if not isinstance(rule["data"], dict):
                    rule["data"] = {}
                self.rules[rid] = rule
                self.categories[rid] = category
                loaded += 1
            # 文件在但一条规则都没读到，和文件缺失等价：多半是格式写错了。
            if not loaded:
                self.warnings.append("规则文件没有可用规则: %s" % path)
                self.rules_missing.append(name)

    def _load_allow(self) -> None:
        path = os.path.join(self.rules_dir, ALLOW_FILE)
        if os.path.isfile(path):
            try:
                self.allow = yamlite.load_file(path) or {}
            except Exception as exc:
                self.warnings.append("白名单解析失败: %s" % exc)
                self.allow = {}
        for key in (
            "domains",
            "reserved_domains",
            "blocked_domains",
            "suspicious_domain_patterns",
            "registries",
            "similar_packages",
            "popular_packages",
            "doc_path_globs",
            "test_path_globs",
        ):
            self.allow[key] = _as_list(self.allow.get(key))
        self._domain_set = {str(d).lower().lstrip(".") for d in self.allow["domains"]}
        self._reserved = {str(d).lower() for d in self.allow["reserved_domains"]}
        self._blocked = {str(d).lower() for d in self.allow["blocked_domains"]}
        self._suspicious = [
            re.compile(str(p), re.I) for p in self.allow["suspicious_domain_patterns"]
        ]

    def _load_project_config(self, config_file: Optional[str]) -> None:
        candidates = []
        if config_file:
            candidates.append(config_file)
        else:
            for base in (self.project_root, os.path.dirname(self.rules_dir)):
                candidates.append(os.path.join(base, PROJECT_CONFIG))
        for path in candidates:
            if path and os.path.isfile(path):
                try:
                    data = yamlite.load_file(path) or {}
                except Exception as exc:
                    self.warnings.append("项目配置解析失败 %s: %s" % (path, exc))
                    continue
                self._apply_project_config(data)
                break

    def _apply_project_config(self, data: Dict[str, Any]) -> None:
        self.project_data = dict(data or {})
        for rid, sev in (data.get("severity") or {}).items():
            if rid in self.rules:
                self.rules[rid]["severity"] = normalize_severity(str(sev), "WARNING")
        for rid in _as_list(data.get("disable")):
            if rid in self.rules:
                self.rules[rid]["enabled"] = False
        for rid, extra in (data.get("data") or {}).items():
            if rid in self.rules and isinstance(extra, dict):
                merged = dict(self.rules[rid].get("data") or {})
                merged.update(extra)
                self.rules[rid]["data"] = merged
        allow = data.get("allow") or {}
        for key in ("domains", "registries", "blocked_domains", "similar_packages"):
            extra = _as_list(allow.get(key))
            if not extra:
                continue
            existing = list(self.allow.get(key) or [])
            for item in extra:
                if item not in existing:
                    existing.append(item)
            self.allow[key] = existing
        if allow.get("domains"):
            self._domain_set |= {str(d).lower().lstrip(".") for d in allow["domains"]}
        if allow.get("blocked_domains"):
            self._blocked |= {str(d).lower() for d in allow["blocked_domains"]}
        for entry in _as_list(data.get("ignore")):
            self._add_ignore_line(str(entry))

    def _load_ignore(self, ignore_file: Optional[str]) -> None:
        path = ignore_file or os.path.join(self.project_root, IGNORE_FILE)
        if not os.path.isfile(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    self._add_ignore_line(line)
        except OSError as exc:
            self.warnings.append("豁免文件读取失败: %s" % exc)

    def _add_ignore_line(self, line: str) -> None:
        text = line.split("#", 1)[0].strip()
        if not text:
            return
        parts = text.split(None, 1)
        if len(parts) == 1:
            self.ignore_rules.append(("*", parts[0].strip()))
        else:
            self.ignore_rules.append((parts[0].strip(), parts[1].strip()))

    # ------------------------------------------------------------- accessors
    def rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        return self.rules.get(rule_id)

    def severity(self, rule_id: str, default: str = "WARNING") -> str:
        rule = self.rules.get(rule_id)
        if not rule:
            return normalize_severity(default)
        return rule["severity"]

    def data(self, rule_id: str) -> Dict[str, Any]:
        rule = self.rules.get(rule_id) or {}
        data = rule.get("data") or {}
        return data if isinstance(data, dict) else {}

    def suggestion(self, rule_id: str) -> str:
        rule = self.rules.get(rule_id) or {}
        return str(rule.get("suggestion") or "")

    def message(self, rule_id: str) -> str:
        rule = self.rules.get(rule_id) or {}
        return str(rule.get("message") or rule.get("title") or rule_id)

    def enabled(self, rule_id: str) -> bool:
        rule = self.rules.get(rule_id)
        return bool(rule and rule.get("enabled", True))

    def category(self, rule_id: str) -> str:
        return self.categories.get(rule_id, "supply_chain")

    def is_ignored(self, rule_id: str, rel_path: str) -> bool:
        for rid, pattern in self.ignore_rules:
            if rid not in ("*", rule_id):
                continue
            if path_matches(rel_path, pattern):
                return True
        return False

    def in_doc_path(self, rel_path: str) -> bool:
        return any(path_matches(rel_path, p) for p in self.allow.get("doc_path_globs", []))

    def in_test_path(self, rel_path: str) -> bool:
        return any(path_matches(rel_path, p) for p in self.allow.get("test_path_globs", []))

    # --------------------------------------------------------------- domains
    def host_status(self, host: str) -> str:
        """Return one of: reserved | allowed | blocked | suspicious | unknown."""
        h = (host or "").lower().strip(".")
        if not h:
            return "unknown"
        if h.startswith("127.") or h.endswith(".localhost"):
            return "reserved"
        for reserved in self._reserved:
            if h == reserved or h.endswith("." + reserved):
                return "reserved"
        if h in self._blocked:
            return "blocked"
        if h in self._domain_set:
            return "allowed"
        for base in self._domain_set:
            if h.endswith("." + base):
                return "allowed"
        for pat in self._suspicious:
            if pat.search(h):
                return "suspicious"
        return "unknown"

    def registry_allowed(self, host: str) -> bool:
        h = (host or "").lower()
        for reg in self.allow.get("registries", []):
            reg = str(reg).lower()
            if h == reg or h.endswith("." + reg):
                return True
        return False

    def known_similar(self, a: str, b: str) -> bool:
        a, b = a.lower(), b.lower()
        for pair in self.allow.get("similar_packages", []):
            if isinstance(pair, (list, tuple)) and len(pair) >= 2:
                left, right = str(pair[0]).lower(), str(pair[1]).lower()
                if (a == left and b == right) or (a == right and b == left):
                    return True
        return False

    def popular_packages(self) -> Iterable[str]:
        return [str(p).lower() for p in self.allow.get("popular_packages", [])]
