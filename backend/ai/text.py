"""Model output parsing and sanitisation."""
from __future__ import annotations

import re

from backend.exceptions import AnalyzerError

MARKER_RE = re.compile(r"<<<\s*(WHY|ATTACK|FIX)\s*>>>", re.IGNORECASE)

_FIX_SIGNALS = (
    "(", "=", "use ", "enable ", "replace ", "set ", "add ", "run ", "install ",
    "upgrade ", "remove ", "rotate ", "pin ", "switch ",
)


def clean_text(text: str, max_chars: int = 2400) -> str:
    """Normalises model output to bounded plain text with no markdown syntax."""
    if not text:
        return ""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"```[a-zA-Z0-9_+-]*", "", text)
    text = re.sub(r"`([^`\n]*)`", r"\1", text)
    text = text.replace("**", "").replace("__", "")
    text = re.sub(r"^\s{0,3}#{1,6}\s*", "", text, flags=re.MULTILINE)
    text = re.sub(r"^\s*[-*+]\s+", "• ", text, flags=re.MULTILINE)
    text = re.sub(r"<<<[^>]*>>>", "", text)
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = text.strip()
    if len(text) > max_chars:
        cut = text[:max_chars]
        if " " in cut[-40:]:
            cut = cut[: cut.rfind(" ")]
        text = cut.rstrip() + " …"
    return text


def parse_sections(raw: str) -> dict[str, str]:
    markers = list(MARKER_RE.finditer(raw or ""))
    if not markers:
        raise AnalyzerError("Unparseable model response (no section markers).")
    sections: dict[str, str] = {}
    for index, marker in enumerate(markers):
        end = markers[index + 1].start() if index + 1 < len(markers) else len(raw)
        sections.setdefault(marker.group(1).upper(), raw[marker.end():end].strip())
    return sections


def fix_is_thin(fix: str) -> bool:
    """A useful fix shows corrected code or concrete actions, with some length."""
    text = (fix or "").strip()
    if len(text) < 220:
        return True
    lowered = text.lower()
    return not any(signal in lowered for signal in _FIX_SIGNALS)
