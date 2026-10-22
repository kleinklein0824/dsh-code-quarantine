"""Language detection plus a lexer that separates code / comment / string.

Every layer above relies on this: an ad link inside a comment is a very
different signal from the same link inside a `requests.get(...)` call, and a
`#` inside a Python string is not a comment. We therefore build real spans
instead of grepping raw text.

Python uses the stdlib `tokenize` + `ast` (exact). Other C-like and shell
languages use a hand written scanner that is span-accurate for comments and
string literals, which is what the lexical rules need. Architecture-level
judgement is *not* done on top of this scanner - see rules/arch.py.
"""

from __future__ import annotations

import ast
import io
import os
import re
import tokenize
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------- languages
EXT_LANG = {
    ".py": "python",
    ".pyi": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".vue": "vue",
    ".svelte": "svelte",
    ".html": "html",
    ".htm": "html",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".scala": "scala",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".go": "go",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".ps1": "powershell",
    ".psm1": "powershell",
    ".lua": "lua",
    ".sql": "sql",
    ".json": "json",
    ".jsonc": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".ini": "ini",
    ".cfg": "ini",
    ".env": "dotenv",
    ".md": "markdown",
    ".txt": "text",
    ".dockerfile": "dockerfile",
}

FILENAME_LANG = {
    "dockerfile": "dockerfile",
    "makefile": "makefile",
    "gemfile": "ruby",
    "rakefile": "ruby",
    ".env": "dotenv",
    "requirements.txt": "requirements",
    # npm/pip 的点文件依赖清单：没有扩展名，靠文件名识别，否则会被当成 unknown 跳过
    ".npmrc": "ini",
    ".yarnrc": "ini",
    ".yarnrc.yml": "yaml",
    ".pypirc": "ini",
    "pip.conf": "ini",
}

CODE_LANGS = {
    "python",
    "javascript",
    "typescript",
    "vue",
    "svelte",
    "html",
    "java",
    "kotlin",
    "scala",
    "c",
    "cpp",
    "csharp",
    "go",
    "rust",
    "ruby",
    "php",
    "swift",
    "shell",
    "powershell",
    "lua",
    "sql",
    "dockerfile",
    "makefile",
}

AST_LANGS_BUILTIN = {"python"}

CLIKE = {"javascript", "typescript", "java", "kotlin", "scala", "c", "cpp", "csharp", "go", "swift", "vue", "svelte", "jsonc", "php", "ruby", "rust"}
HASH_COMMENT = {"shell", "powershell", "yaml", "toml", "ini", "dockerfile", "makefile", "dotenv", "requirements", "perl"}
MARKUP = {"html", "vue", "svelte", "markdown"}


def detect_language(path: str, text: str = "") -> str:
    base = os.path.basename(path).lower()
    if base in FILENAME_LANG:
        return FILENAME_LANG[base]
    if base.startswith("dockerfile"):
        return "dockerfile"
    ext = os.path.splitext(base)[1]
    if ext in EXT_LANG:
        return EXT_LANG[ext]
    if text.startswith("#!"):
        head = text.split("\n", 1)[0].lower()
        if "python" in head:
            return "python"
        if "node" in head:
            return "javascript"
        if any(s in head for s in ("bash", "/sh", "zsh", "ksh")):
            return "shell"
        if "ruby" in head:
            return "ruby"
        if "perl" in head:
            return "perl"
    return "unknown"


# ------------------------------------------------------------------- spans
@dataclass
class Span:
    kind: str  # comment | string | docstring | code
    start: int
    end: int

    def contains(self, offset: int) -> bool:
        return self.start <= offset < self.end


class Source:
    """A file plus its comment/string segmentation."""

    def __init__(self, path: str, text: str, lang: Optional[str] = None) -> None:
        self.path = path
        self.rel_path = path
        self.text = text
        self.lang = lang or detect_language(path, text)
        self.lines: List[str] = text.split("\n")
        self._line_offsets: List[int] = []
        pos = 0
        for line in self.lines:
            self._line_offsets.append(pos)
            pos += len(line) + 1
        self.spans: List[Span] = []
        self.parse_error: Optional[str] = None
        self.tree: Optional[ast.AST] = None
        self._scan()
        self._build_views()

    # ------------------------------------------------------------- geometry
    def line_of(self, offset: int) -> int:
        lo, hi = 0, len(self._line_offsets) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self._line_offsets[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    def col_of(self, offset: int) -> int:
        return offset - self._line_offsets[self.line_of(offset) - 1] + 1

    def offset_of(self, line: int, col: int) -> int:
        if line < 1 or line > len(self._line_offsets):
            return 0
        return self._line_offsets[line - 1] + col

    def line_text(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1]
        return ""

    def region(self, offset: int) -> str:
        for span in self.spans:
            if span.start <= offset < span.end:
                return span.kind
        return "code"

    def spans_of(self, kinds: Tuple[str, ...], start: int = 0, end: Optional[int] = None) -> List[Span]:
        end = len(self.text) if end is None else end
        return [s for s in self.spans if s.kind in kinds and s.start < end and s.end > start]

    # -------------------------------------------------------------- scanning
    def _add(self, kind: str, start: int, end: int) -> None:
        if end > start:
            self.spans.append(Span(kind, start, end))

    def _scan(self) -> None:
        lang = self.lang
        if lang == "python":
            if self._scan_python():
                return
        if lang in MARKUP:
            self._scan_markup()
            return
        if lang in HASH_COMMENT:
            self._scan_hash()
            return
        if lang in CLIKE:
            self._scan_clike()
            return
        if lang in ("html",):
            self._scan_markup()
            return
        # unknown / data files: nothing to mask
        self.spans.sort(key=lambda s: s.start)

    def _scan_python(self) -> bool:
        try:
            self.tree = ast.parse(self.text)
        except SyntaxError as exc:
            self.parse_error = "syntax: %s" % exc
            self.tree = None
        try:
            toks = list(tokenize.generate_tokens(io.StringIO(self.text).readline))
        except (tokenize.TokenError, IndentationError, SyntaxError):
            return False
        for tok in toks:
            if tok.type == tokenize.COMMENT:
                start = self.offset_of(tok.start[0], tok.start[1])
                end = self.offset_of(tok.end[0], tok.end[1])
                self._add("comment", start, end)
            elif tok.type == tokenize.STRING:
                start = self.offset_of(tok.start[0], tok.start[1])
                end = self.offset_of(tok.end[0], tok.end[1])
                self._add("string", start, end)
        self._mark_docstrings()
        self.spans.sort(key=lambda s: s.start)
        return True

    def _mark_docstrings(self) -> None:
        if not isinstance(self.tree, ast.AST):
            return
        nodes = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        doc_ranges = []
        for node in ast.walk(self.tree):
            if not isinstance(node, nodes):
                continue
            body = getattr(node, "body", None)
            if not body:
                continue
            first = body[0]
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
                and getattr(first.value, "end_lineno", None)
            ):
                start = self.offset_of(first.value.lineno, first.value.col_offset)
                end = self.offset_of(first.value.end_lineno, first.value.end_col_offset)
                doc_ranges.append((start, end))
        for span in self.spans:
            if span.kind != "string":
                continue
            for start, end in doc_ranges:
                if span.start >= start and span.end <= end:
                    span.kind = "docstring"
                    break

    def _scan_hash(self) -> None:
        text = self.text
        n = len(text)
        i = 0
        while i < n:
            ch = text[i]
            if ch == "#" and (i == 0 or text[i - 1] in " \t\n"):
                j = text.find("\n", i)
                j = n if j < 0 else j
                self._add("comment", i, j)
                i = j
                continue
            if ch in ("'", '"'):
                j = self._scan_quoted(i)
                self._add("string", i, j)
                i = j
                continue
            if self.lang == "powershell" and text.startswith("<#", i):
                j = text.find("#>", i)
                j = n if j < 0 else j + 2
                self._add("comment", i, j)
                i = j
                continue
            if self.lang == "dockerfile" and ch == "#" and i == 0:
                j = text.find("\n", i)
                j = n if j < 0 else j
                self._add("comment", i, j)
                i = j
                continue
            i += 1
        self.spans.sort(key=lambda s: s.start)

    def _scan_markup(self) -> None:
        """Markup: comments, attribute values and text nodes.

        Only marking ``<!-- -->`` as comments is not enough. Markup has no "code"
        in the sense the other scanners mean: the visible text and the attribute
        values *are* the data, and that is exactly where an injected ad link
        lives (a relay station's landing page is nothing but text and links).
        Without string spans the ad rules get an empty per-line text cache and
        can never fire on such a page -- it comes back SAFE while advertising a
        mirror in every paragraph.

        ``<script>`` / ``<style>`` bodies are left as code so the JavaScript and
        shell rules keep working on inline handlers and blocks.
        """
        text = self.text
        n = len(text)
        i = 0
        while i < n:
            if text.startswith("<!--", i):
                j = text.find("-->", i)
                j = n if j < 0 else j + 3
                self._add("comment", i, j)
                i = j
                continue
            if text[i] == "<":
                j = self._skip_tag(i)
                if j > i:
                    self._scan_attributes(i, j)
                    name = self._tag_name(i, j)
                    # A *closing* tag ends a raw-text block; it must not re-enter
                    # the body-skip branch, or `</style>` would look for another
                    # `</style>` after itself, find none, and swallow the rest of
                    # the document as one giant raw-text region.
                    closing = text[i + 1:i + 2] == "/"
                    if name in ("script", "style", "textarea") and not closing:
                        close = text.lower().find("</" + name, j)
                        i = n if close < 0 else close
                        continue
                    i = j
                    # text node runs until the next tag
                    k = text.find("<", i)
                    k = n if k < 0 else k
                    self._add("string", i, k)
                    i = k
                    continue
            i += 1
        self.spans.sort(key=lambda s: s.start)

    def _skip_tag(self, i: int) -> int:
        """Offset just past the ``>`` closing the tag that starts at i (0 if none).

        Quoted attribute values may contain ``>``; a plain ``text.find(">")``
        would cut the tag in half and turn the rest of the value into text.
        """
        text = self.text
        n = len(text)
        j = i + 1
        quote = ""
        while j < n:
            c = text[j]
            if quote:
                if c == quote:
                    quote = ""
            elif c in ("'", '"'):
                quote = c
            elif c == ">":
                return j + 1
            j += 1
        return 0

    def _tag_name(self, start: int, end: int) -> str:
        match = re.match(r"<\s*/?\s*([A-Za-z][A-Za-z0-9:-]*)", self.text[start:end])
        return match.group(1).lower() if match else ""

    def _scan_attributes(self, start: int, end: int) -> None:
        """Mark quoted attribute values inside the tag span [start, end) as strings."""
        text = self.text
        i = start
        while i < end:
            c = text[i]
            if c in ("'", '"'):
                j = text.find(c, i + 1)
                if j < 0 or j >= end:
                    return
                self._add("string", i, j + 1)
                i = j + 1
                continue
            i += 1

    def _scan_quoted(self, i: int) -> int:
        """Scan a simple quoted string starting at i; return end offset."""
        text = self.text
        n = len(text)
        quote = text[i]
        j = i + 1
        while j < n:
            c = text[j]
            if c == "\\":
                j += 2
                continue
            if c == quote:
                return j + 1
            if c == "\n" and quote != "`":
                return j
            j += 1
        return n

    def _scan_clike(self) -> None:
        text = self.text
        n = len(text)
        lang = self.lang
        i = 0
        last_sig = ""
        while i < n:
            ch = text[i]
            nxt = text[i + 1] if i + 1 < n else ""
            if text.startswith("//", i):
                j = text.find("\n", i)
                j = n if j < 0 else j
                self._add("comment", i, j)
                i = j
                continue
            if text.startswith("/*", i):
                j = text.find("*/", i + 2)
                j = n if j < 0 else j + 2
                self._add("comment", i, j)
                i = j
                continue
            if lang in ("php", "ruby") and ch == "#":
                j = text.find("\n", i)
                j = n if j < 0 else j
                self._add("comment", i, j)
                i = j
                continue
            if lang == "rust" and ch in "rb" and text.startswith('"', i + 1):
                j = self._scan_quoted(i + 1)
                self._add("string", i, j)
                i = j
                continue
            if lang == "rust" and ch == "r":
                # r"..." / r#"..."# / r##"..."##
                match = re.match(r'r(#+)"', text[i:i + 12])
                if match:
                    fence = '"' + match.group(1)
                    j = text.find(fence, i + match.end())
                    j = n if j < 0 else j + len(fence)
                    self._add("string", i, j)
                    i = j
                    continue
            if lang == "csharp" and ch == "@" and nxt == '"':
                j = i + 2
                while j < n:
                    if text[j] == '"':
                        if j + 1 < n and text[j + 1] == '"':
                            j += 2
                            continue
                        j += 1
                        break
                    j += 1
                self._add("string", i, j)
                i = j
                continue
            if ch in ('"', "'"):
                j = self._scan_quoted(i)
                self._add("string", i, j)
                i = j
                continue
            if ch == "`" and lang in ("javascript", "typescript", "vue", "svelte"):
                i = self._scan_template(i)
                continue
            if ch == "`" and lang == "go":
                j = self._scan_quoted(i)
                self._add("string", i, j)
                i = j
                continue
            if ch == "/" and lang in ("javascript", "typescript", "vue", "svelte"):
                if self._regex_allowed(last_sig):
                    j = self._scan_regex(i)
                    if j > i + 1:
                        self._add("string", i, j)
                        i = j
                        continue
            if not ch.isspace():
                last_sig = ch
            i += 1
        self.spans.sort(key=lambda s: s.start)

    @staticmethod
    def _regex_allowed(last_sig: str) -> bool:
        if not last_sig:
            return True
        return last_sig in "(,=:[!&|?{};+-*%~^<>"

    def _scan_regex(self, i: int) -> int:
        text = self.text
        n = len(text)
        j = i + 1
        in_class = False
        while j < n:
            c = text[j]
            if c == "\\":
                j += 2
                continue
            if c == "\n":
                return i  # not a regex
            if c == "[":
                in_class = True
            elif c == "]":
                in_class = False
            elif c == "/" and not in_class:
                j += 1
                while j < n and text[j].isalpha():
                    j += 1
                return j
            j += 1
        return i

    def _scan_template(self, i: int) -> int:
        """Scan a JS template literal; `${...}` interiors are left as code."""
        text = self.text
        n = len(text)
        j = i + 1
        seg_start = i
        while j < n:
            c = text[j]
            if c == "\\":
                j += 2
                continue
            if c == "`":
                self._add("string", seg_start, j + 1)
                return j + 1
            if text.startswith("${", j):
                self._add("string", seg_start, j)
                depth = 1
                k = j + 2
                while k < n and depth > 0:
                    if text[k] == "{":
                        depth += 1
                    elif text[k] == "}":
                        depth -= 1
                    k += 1
                j = k
                seg_start = j
                continue
            j += 1
        self._add("string", seg_start, n)
        return n

    # ---------------------------------------------------------------- views
    def _build_views(self) -> None:
        masked = list(self.text)
        nocomment = list(self.text)
        for span in self.spans:
            if span.kind == "comment":
                for k in range(span.start, min(span.end, len(masked))):
                    if masked[k] != "\n":
                        masked[k] = " "
                        nocomment[k] = " "
            elif span.kind in ("string", "docstring"):
                for k in range(span.start + 1, min(span.end - 1, len(masked))):
                    if masked[k] != "\n":
                        masked[k] = " "
        self.masked = "".join(masked)
        self.nocomment = "".join(nocomment)

    def masked_line(self, lineno: int) -> str:
        start = self._line_offsets[lineno - 1] if 1 <= lineno <= len(self._line_offsets) else 0
        end = start + len(self.line_text(lineno))
        return self.masked[start:end]

    def nocomment_line(self, lineno: int) -> str:
        """Line with comments blanked but string literals intact."""
        start = self._line_offsets[lineno - 1] if 1 <= lineno <= len(self._line_offsets) else 0
        end = start + len(self.line_text(lineno))
        return self.nocomment[start:end]

    def snippet(self, lineno: int, pad: int = 0) -> str:
        lo = max(1, lineno - pad)
        hi = min(len(self.lines), lineno + pad)
        return "\n".join(self.lines[k - 1] for k in range(lo, hi + 1)).strip()
