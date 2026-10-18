"""Report-wide secret redaction.

Engines quote source code in snippets and messages, and those quotes can contain
credentials that another engine detected: a context line next to an XSS finding,
or a scanner message that repeats a hardcoded password. Every finding passes
through this module before it is explained, stored or exported, so no complete
secret ever reaches a report, an export, or an AI provider.
"""
from __future__ import annotations

import re

from backend.engines.rules import secrets as catalog
from backend.schemas import Finding

_LINE_PREFIX = re.compile(r"^(\s*\d+\s{2})(.*)$")
_QUOTED = re.compile(r"""(["'`])([^"'`\s]{6,})\1""")
_CREDENTIAL_NAME = (
    r"[A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|credential)[A-Za-z0-9_.-]*"
)
_UNQUOTED_ASSIGNMENT = re.compile(rf"(?i)(\b{_CREDENTIAL_NAME}\s*[=\s]\s*)([^\s\"'`$]{{4,}})")
_CREDENTIAL_CWE = "CWE-798"


def _mask(value: str) -> str:
    return catalog.redact(value)


def _replace_group(match: re.Match, group: int, check=None) -> str:
    value = match.group(group)
    if not value or "•" in value or (check is not None and not check(value)):
        return match.group(0)
    start, end = match.span(group)
    offset = match.start(0)
    whole = match.group(0)
    return whole[: start - offset] + _mask(value) + whole[end - offset:]


def scrub(text: str) -> str:
    """Masks every recognisable credential in free text, leaving the rest intact."""
    if not text:
        return text
    for rule in catalog.RULES:
        if rule.rule_id == "SEC019":
            continue
        text = rule.pattern.sub(
            lambda m, r=rule: _replace_group(m, r.secret_group, lambda v, r=r: catalog.is_plausible(r, v)),
            text,
        )
    generic = catalog.GENERIC_ASSIGNMENT
    text = generic.pattern.sub(
        lambda m: _replace_group(m, generic.secret_group, lambda v: catalog.is_plausible(generic, v)), text,
    )
    env = catalog.ENV_ASSIGNMENT
    return "\n".join(
        env.pattern.sub(lambda m: _replace_group(m, env.secret_group, lambda v: catalog.is_plausible(env, v)), line)
        for line in text.split("\n")
    )


def _scrub_snippet(snippet: str, flagged_line, credential: bool) -> str:
    lines = []
    for raw in snippet.split("\n"):
        match = _LINE_PREFIX.match(raw)
        prefix, code = (match.group(1), match.group(2)) if match else ("", raw)
        code = scrub(code)
        if credential and (flagged_line is None or prefix.strip() == str(flagged_line)):
            code = _QUOTED.sub(lambda m: _replace_group(m, 2), code)
            code = _UNQUOTED_ASSIGNMENT.sub(lambda m: _replace_group(m, 2), code)
        lines.append(prefix + code)
    return "\n".join(lines)


def redact_finding(finding: Finding) -> Finding:
    credential = finding.cwe == _CREDENTIAL_CWE
    finding.snippet = _scrub_snippet(finding.snippet or "", finding.line, credential)
    description = scrub(finding.description or "")
    if credential:
        description = _QUOTED.sub(lambda m: _replace_group(m, 2), description)
    finding.description = description
    return finding
