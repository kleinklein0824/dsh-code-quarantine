"""Encoded-payload decoding.

Base64 / hex / char-code blobs are decoded and re-inspected before any verdict
is produced, because the dangerous content never appears in the literal source
text. We only report when the decoded text actually contains a URL, a shell
command, a credential path or a dynamic-exec call.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Iterable, List, Optional, Set, Tuple

B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){24,}")
XESC_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){10,}")
CHR_CHAIN_RE = re.compile(r"(?:chr\(\s*\d{1,3}\s*\)\s*\+?\s*){6,}")
FROMCHAR_RE = re.compile(r"String\.fromCharCode\(([\d,\s]{8,})\)")

SIGNALS = {
    "url": re.compile(r"https?://[^\s\"'<>]+", re.I),
    "shell": re.compile(
        r"(curl\s+|wget\s+|/bin/(?:ba)?sh|bash\s+-i|sh\s+-c|powershell|Invoke-Expression"
        r"|nc\s+-e|chmod\s+\+x|rm\s+-rf)",
        re.I,
    ),
    "credential_path": re.compile(
        r"(\.ssh/|\.aws/|\.env\b|credentials|id_rsa|\.npmrc|\.git-credentials|\.kube/|Login Data)",
        re.I,
    ),
    "dynamic_exec": re.compile(
        r"(eval\s*\(|exec\s*\(|subprocess\.|os\.system|child_process|__import__)", re.I
    ),
}


@dataclass
class Payload:
    start: int
    end: int
    kind: str
    decoded: str
    signals: List[Tuple[str, str]]

    def summary(self) -> str:
        return ", ".join(sorted({s for s, _ in self.signals}))


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    ok = sum(1 for c in text if c.isprintable() or c in "\n\t\r")
    return ok / len(text)


def _clean(decoded: bytes) -> Optional[str]:
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            text = decoded.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
        text = text.strip("\x00")
        if len(text) >= 8 and _printable_ratio(text) >= 0.85:
            return text
    return None


def _decode_b64(raw: str) -> Optional[str]:
    pad = "=" * (-len(raw) % 4)
    try:
        return _clean(base64.b64decode(raw + pad, validate=False))
    except (binascii.Error, ValueError):
        return None


def _decode_hex(raw: str) -> Optional[str]:
    try:
        return _clean(bytes.fromhex(raw))
    except ValueError:
        return None


def _decode_chr_chain(raw: str) -> Optional[str]:
    nums = re.findall(r"chr\(\s*(\d{1,3})\s*\)", raw)
    try:
        text = "".join(chr(int(n)) for n in nums)
    except ValueError:
        return None
    return text if len(text) >= 8 else None


def inspect_text(text: str) -> List[Tuple[str, str]]:
    out = []
    for name, pattern in SIGNALS.items():
        match = pattern.search(text)
        if match:
            out.append((name, match.group(0)[:80]))
    return out


def _iter_raw(text: str) -> Iterable[Tuple[int, int, str, str]]:
    for match in B64_RE.finditer(text):
        blob = match.group(0)
        if len(set(blob)) < 8:  # long identifiers / repeated padding
            continue
        yield match.start(), match.end(), "base64", blob
    for match in HEX_RE.finditer(text):
        yield match.start(), match.end(), "hex", match.group(0)
    for match in XESC_RE.finditer(text):
        yield match.start(), match.end(), "hex-escape", match.group(0)
    for match in FROMCHAR_RE.finditer(text):
        yield match.start(), match.end(), "charcode", match.group(1)
    for match in CHR_CHAIN_RE.finditer(text):
        yield match.start(), match.end(), "chr-chain", match.group(0)


def _decode(kind: str, raw: str) -> Optional[str]:
    if kind == "base64":
        return _decode_b64(raw)
    if kind in ("hex", "hex-escape"):
        return _decode_hex(raw.replace("\\x", ""))
    if kind == "charcode":
        try:
            return "".join(chr(int(x)) for x in raw.split(",") if x.strip())
        except ValueError:
            return None
    if kind == "chr-chain":
        return _decode_chr_chain(raw)
    return None


def _deep_signals(text: str, depth: int, max_depth: int, min_len: int) -> List[Tuple[str, str]]:
    signals = inspect_text(text)
    if depth >= max_depth:
        return signals
    for s, e, kind, raw in _iter_raw(text):
        if (e - s) < min_len:
            continue
        inner = _decode(kind, raw)
        if inner:
            signals.extend(_deep_signals(inner, depth + 1, max_depth, min_len))
    return signals


def find_payloads(text: str, min_len: int = 40, max_depth: int = 2) -> List[Payload]:
    """Decode every candidate blob and report the ones whose plaintext is dangerous.

    Dedupe key is ``(start, end, kind)``, never ``(start, end)`` alone: a hex
    blob is also a syntactically valid base64 blob, so both decoders claim the
    same span. Keying on the span made base64 win the race and ``continue``
    skipped the hex decoder entirely, which silently disabled hex payload
    detection. We also key on the decoded text so one blob reachable through
    two encodings is reported once.
    """
    found: List[Payload] = []
    seen: Set[Tuple[int, int, str]] = set()
    seen_text: Set[str] = set()
    for start, end, kind, raw in _iter_raw(text):
        key = (start, end, kind)
        if (end - start) < min_len or key in seen:
            continue
        decoded = _decode(kind, raw)
        if not decoded:
            # only a successful decode reserves the key, so a failing decoder
            # never blocks a sibling decoder for the same span
            continue
        seen.add(key)
        if decoded in seen_text:
            continue
        seen_text.add(decoded)
        signals = _deep_signals(decoded, 1, max_depth, min_len)
        if signals:
            found.append(Payload(start, end, kind, decoded, signals))
    return found
