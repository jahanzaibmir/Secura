"""JavaScript and TypeScript pattern analysis."""
from __future__ import annotations

from backend.engines.base import Engine, EngineContext, EngineResult, trim_snippet
from backend.engines.inventory import Inventory, looks_minified, read_text
from backend.engines.rules.javascript import RULES
from backend.schemas import Finding

_KINDS = ("JavaScript", "TypeScript", "HTML")
_MAX_PER_FILE = 25
_MAX_LINE = 2000


def strip_comments(line: str, in_block: bool) -> tuple:
    """Removes // and /* */ comments from one line, tracking block-comment state.

    Returns ``(code, masked, in_block)`` where ``masked`` is the code with the
    contents of string literals replaced by spaces.
    """
    out = []
    masked = []
    i = 0
    quote = ""
    while i < len(line):
        if in_block:
            end = line.find("*/", i)
            if end == -1:
                return "".join(out), "".join(masked), True
            i = end + 2
            in_block = False
            continue
        char = line[i]
        if quote:
            out.append(char)
            if char == "\\" and i + 1 < len(line):
                out.append(line[i + 1])
                masked.append("  ")
                i += 2
                continue
            if char == quote:
                quote = ""
                masked.append(char)
            else:
                masked.append(" ")
            i += 1
            continue
        if char in "\"'`":
            quote = char
            out.append(char)
            masked.append(char)
            i += 1
            continue
        if line.startswith("//", i):
            break
        if line.startswith("/*", i):
            in_block = True
            i += 2
            continue
        out.append(char)
        masked.append(char)
        i += 1
    return "".join(out), "".join(masked), in_block


class JavaScriptEngine(Engine):
    name = "javascript"
    label = "JavaScript / TypeScript"
    description = "Rules for XSS sinks, injection, insecure crypto, JWT and TLS misuse in JS and TS."

    def applies(self, inventory: Inventory) -> bool:
        return bool(inventory.of_kind(*_KINDS))

    def run(self, context: EngineContext) -> EngineResult:
        files = context.inventory.of_kind(*_KINDS)
        result = EngineResult()
        skipped_minified = 0
        for index, file in enumerate(files):
            if index % 50 == 0:
                context.token.raise_if_cancelled()
                context.progress(f"{index}/{len(files)} files", index / max(1, len(files)))
            if ".min." in file.name or file.name.endswith(".map"):
                skipped_minified += 1
                continue
            text = read_text(file)
            if text is None:
                continue
            if looks_minified(text):
                skipped_minified += 1
                continue
            result.findings.extend(self._scan_text(file.rel, text))

        if skipped_minified:
            result.notes.append(f"Skipped {skipped_minified} minified or bundled JavaScript file(s).")
        result.detail = f"{len(files)} file(s)"
        return result

    @staticmethod
    def _scan_text(rel: str, text: str) -> list[Finding]:
        lines = text.splitlines()
        findings: list[Finding] = []
        in_block = False
        for number, raw in enumerate(lines, start=1):
            if len(raw) > _MAX_LINE:
                continue
            code, masked, in_block = strip_comments(raw, in_block)
            if not code.strip():
                continue
            for rule in RULES:
                if rule.matches(code, masked):
                    findings.append(Finding(
                        engine="javascript",
                        rule_id=rule.rule_id,
                        title=rule.title,
                        description=rule.description,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        file_path=rel,
                        line=number,
                        snippet=trim_snippet(lines, number),
                        cwe=rule.cwe,
                        references=list(rule.references),
                    ))
                    break
            if len(findings) >= _MAX_PER_FILE:
                break
        return findings
