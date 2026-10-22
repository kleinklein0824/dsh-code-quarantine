"""Dependency-free loader for the small YAML subset used by the rule files.

If PyYAML is importable we use it; otherwise this module parses the subset
we actually write by hand: nested mappings, block sequences, inline lists,
quoted/plain scalars, comments. That keeps the skill runnable on a bare
Python install with no pip step.
"""

from __future__ import annotations

from typing import Any, List, Tuple

try:  # pragma: no cover - depends on environment
    import yaml as _pyyaml
except Exception:  # pragma: no cover
    _pyyaml = None


class YamlError(ValueError):
    pass


def _strip_comment(line: str) -> str:
    out = []
    quote = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            out.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < len(line):
                out.append(line[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "#" and (i == 0 or line[i - 1] in " \t"):
            break
        out.append(ch)
        i += 1
    return "".join(out).rstrip()


def _split_inline(text: str) -> List[str]:
    items, buf, quote, depth = [], [], None, 0
    for ch in text:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
        elif ch in "[{":
            depth += 1
            buf.append(ch)
        elif ch in "]}":
            depth -= 1
            buf.append(ch)
        elif ch == "," and depth == 0:
            items.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        items.append(tail)
    return items


def _scalar(text: str) -> Any:
    s = text.strip()
    if not s:
        return None
    if s[0] == s[-1] and s[0] in ("'", '"') and len(s) >= 2:
        body = s[1:-1]
        if s[0] == '"':
            return (
                body.replace('\\"', '"')
                .replace("\\n", "\n")
                .replace("\\t", "\t")
                .replace("\\\\", "\\")
            )
        return body.replace("''", "'")
    low = s.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "none", "~"):
        return None
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        return [_scalar(x) for x in _split_inline(inner)] if inner else []
    if s.startswith("{") and s.endswith("}"):
        inner = s[1:-1].strip()
        out = {}
        for part in (_split_inline(inner) if inner else []):
            if ":" in part:
                k, v = part.split(":", 1)
                out[_scalar(k)] = _scalar(v)
        return out
    try:
        if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
            return int(s)
        if s.replace(".", "", 1).replace("-", "", 1).isdigit() and s.count(".") == 1:
            return float(s)
    except Exception:
        pass
    return s


def _prepare(text: str) -> List[Tuple[int, str]]:
    lines: List[Tuple[int, str]] = []
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        raw = raw.replace("\t", "    ")
        if not raw.strip():
            continue
        stripped = _strip_comment(raw)
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        lines.append((indent, stripped.strip()))
    return lines


def _parse_block(lines: List[Tuple[int, str]], idx: int, indent: int) -> Tuple[Any, int]:
    if idx >= len(lines):
        return None, idx
    if lines[idx][1].startswith("- ") or lines[idx][1] == "-":
        return _parse_seq(lines, idx, indent)
    return _parse_map(lines, idx, indent)


def _parse_seq(lines: List[Tuple[int, str]], idx: int, indent: int) -> Tuple[Any, int]:
    out = []
    while idx < len(lines):
        ind, content = lines[idx]
        if ind != indent or not (content.startswith("- ") or content == "-"):
            if ind > indent:
                raise YamlError("bad indent in sequence near: %s" % content)
            break
        rest = content[2:].strip() if content != "-" else ""
        if not rest:
            idx += 1
            if idx < len(lines) and lines[idx][0] > indent:
                val, idx = _parse_block(lines, idx, lines[idx][0])
                out.append(val)
            else:
                out.append(None)
            continue
        if _looks_like_kv(rest):
            # inline mapping start: "- id: AD001"
            key, _, value = rest.partition(":")
            item = {}
            item[_scalar(key)] = _scalar(value) if value.strip() else None
            idx += 1
            child_indent = ind + 2
            while idx < len(lines) and lines[idx][0] >= child_indent:
                sub_ind, sub = lines[idx]
                if not _looks_like_kv(sub):
                    break
                k, _, v = sub.partition(":")
                if v.strip():
                    item[_scalar(k)] = _scalar(v)
                    idx += 1
                else:
                    idx += 1
                    if idx < len(lines) and lines[idx][0] > sub_ind:
                        val, idx = _parse_block(lines, idx, lines[idx][0])
                        item[_scalar(k)] = val
                    else:
                        item[_scalar(k)] = None
            out.append(item)
            continue
        out.append(_scalar(rest))
        idx += 1
    return out, idx


def _parse_map(lines: List[Tuple[int, str]], idx: int, indent: int) -> Tuple[Any, int]:
    out = {}
    while idx < len(lines):
        ind, content = lines[idx]
        if ind != indent:
            if ind > indent:
                raise YamlError("bad indent in mapping near: %s" % content)
            break
        if not _looks_like_kv(content):
            break
        key, _, value = content.partition(":")
        key = _scalar(key)
        if value.strip():
            out[key] = _scalar(value)
            idx += 1
        else:
            idx += 1
            if idx < len(lines) and lines[idx][0] > indent:
                val, idx = _parse_block(lines, idx, lines[idx][0])
                out[key] = val
            else:
                out[key] = None
    return out, idx


def _looks_like_kv(text: str) -> bool:
    quote = None
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
        elif ch == ":" and (i + 1 == len(text) or text[i + 1] in " \t"):
            return True
    return False


def loads(text: str) -> Any:
    if _pyyaml is not None:
        try:
            return _pyyaml.safe_load(text)
        except Exception:
            pass
    lines = _prepare(text)
    if not lines:
        return None
    value, idx = _parse_block(lines, 0, lines[0][0])
    if idx != len(lines):
        raise YamlError("trailing content at line index %d: %s" % (idx, lines[idx][1]))
    return value


def load_file(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return loads(fh.read())
