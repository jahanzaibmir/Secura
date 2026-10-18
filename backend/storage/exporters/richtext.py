"""Renders explanation text as HTML, setting code lines apart from prose.

Model output is plain text by design. Lines that read as code (indented lines,
statements that open with a language keyword, or lines dense with code
punctuation and free of sentence structure) are grouped into code blocks;
everything else becomes paragraphs. The output is always fully escaped.
"""
from __future__ import annotations

import html
import re
import textwrap

_CODE_START = re.compile(
    r"^(?:import\s|from\s+\S+\s+import\b|def\s|class\s+\w+[(:]|return\b|raise\b|elif\b|else:|try:|"
    r"except\b|finally:|with\s.*:$|for\s.+\sin\s.+:$|while\s.+:$|if\s.+:$|const\s|let\s|var\s|"
    r"function\b|await\s|async\s|export\s|module\.exports|require\(|@\w|\$\s|pip\s|npm\s|yarn\s|"
    r"docker\s|RUN\s|FROM\s|USER\s|COPY\s|ENV\s|ARG\s|git\s|SELECT\s|INSERT\s|UPDATE\s)"
)
_PROSE_START = re.compile(r"^[A-Z][a-z]+[\s,]")
_ASSIGNMENT_START = re.compile(r"^[A-Za-z_][\w.\[\]'\"]*\s*(?:=|\+=|:=)\s*\S")


def is_code_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith(("•", "- ")):
        return False
    if line.startswith(("    ", "\t")):
        return True
    if _CODE_START.match(stripped):
        return True
    if _ASSIGNMENT_START.match(stripped) and ". " not in stripped:
        return True
    if _PROSE_START.match(stripped):
        return False
    punctuation = sum(stripped.count(char) for char in "()=[]{};")
    sentence_like = ". " in stripped or stripped.endswith((".", "?", "!")) and not stripped.endswith(").")
    return punctuation >= 2 and not sentence_like


def blocks(text: str) -> list[tuple[str, str]]:
    """Splits text into ("code" | "prose", content) blocks."""
    lines = (text or "").replace("\r\n", "\n").split("\n")
    result: list[list] = []
    for index, line in enumerate(lines):
        if not line.strip():
            if result and result[-1][0] == "code":
                upcoming = next((later for later in lines[index + 1:] if later.strip()), "")
                if upcoming and is_code_line(upcoming):
                    result[-1][1].append("")
                    continue
            result.append(["gap", []])
            continue
        kind = "code" if is_code_line(line) else "prose"
        if result and result[-1][0] == kind:
            result[-1][1].append(line)
        else:
            result.append([kind, [line]])
    rendered = []
    for kind, content in result:
        if kind == "code":
            rendered.append(("code", textwrap.dedent("\n".join(content)).strip("\n")))
        elif kind == "prose":
            rendered.append(("prose", "\n".join(line.strip() for line in content)))
    return rendered


def to_html(text: str, empty: str, code_class: str = "code", prose_class: str = "") -> str:
    parts = blocks(text)
    if not parts:
        return f"<p class='{prose_class}'>{html.escape(empty)}</p>" if prose_class else f"<p>{html.escape(empty)}</p>"
    out = []
    for kind, content in parts:
        if kind == "code":
            out.append(f"<pre class='{code_class}'>{html.escape(content)}</pre>")
        else:
            attr = f" class='{prose_class}'" if prose_class else ""
            out.append(f"<p{attr}>{html.escape(content)}</p>")
    return "".join(out)
