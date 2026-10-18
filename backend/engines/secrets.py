"""Secret detection across every text file in the tree.

Matched values are redacted before they reach the report, so a scan result can
be shared without re-leaking the credentials it found.
"""
from __future__ import annotations

from pathlib import PurePosixPath

from backend.engines.base import Engine, EngineContext, EngineResult
from backend.engines.inventory import (
    KIND_CREDENTIALS,
    Inventory,
    SourceFile,
    is_test_path,
    looks_minified,
    read_text,
)
from backend.engines.rules import secrets as catalog
from backend.schemas import Finding, Severity

_SKIP_NAMES = frozenset({
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "uv.lock", "pipfile.lock", "cargo.lock", "composer.lock", "gemfile.lock", "go.sum",
})
_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults")
_MAX_PER_FILE = 20
_MAX_LINE = 4000


class SecretsEngine(Engine):
    name = "secrets"
    label = "Secrets"
    description = "Detects API keys, tokens, private keys and passwords committed to source."

    def applies(self, inventory: Inventory) -> bool:
        return bool(inventory.files)

    def run(self, context: EngineContext) -> EngineResult:
        files = [f for f in context.inventory.files if self._eligible(f)]
        result = EngineResult()
        seen: set[tuple[str, str, str]] = set()
        for index, file in enumerate(files):
            if index % 100 == 0:
                context.token.raise_if_cancelled()
                context.progress(f"{index}/{len(files)} files", index / max(1, len(files)))
            text = read_text(file)
            if text is None or (file.suffix in (".js", ".css") and looks_minified(text)):
                continue
            for finding in self._scan_file(file, text):
                key = (finding.rule_id, finding.file_path, finding.metadata.get("redacted", ""))
                if key not in seen:
                    seen.add(key)
                    result.findings.append(finding)
        result.detail = f"{len(files)} file(s)"
        return result

    @staticmethod
    def _eligible(file: SourceFile) -> bool:
        name = file.name.lower()
        return name not in _SKIP_NAMES and not name.endswith((".min.js", ".map"))

    def _scan_file(self, file: SourceFile, text: str) -> list[Finding]:
        lines = text.splitlines()
        lowered_name = file.name.lower()
        is_env_file = file.kind == KIND_CREDENTIALS
        is_template = lowered_name.endswith(_TEMPLATE_SUFFIXES)
        in_tests = is_test_path(file.rel)
        allow_generic = file.kind != "Python" and not is_template
        findings: list[Finding] = []

        for number, line in enumerate(lines, start=1):
            if len(line) > _MAX_LINE or not line.strip():
                continue
            for rule in catalog.RULES:
                for match in rule.pattern.finditer(line):
                    value = catalog.secret_value(rule, match) or ""
                    if rule.rule_id == "SEC019" or catalog.is_plausible(rule, value):
                        findings.append(self._finding(rule, file, number, line, value, in_tests))
            if is_env_file and not is_template:
                match = catalog.ENV_ASSIGNMENT.pattern.search(line)
                if match and catalog.is_plausible(catalog.ENV_ASSIGNMENT, match.group(2)) \
                        and not self._covered(findings, number):
                    findings.append(self._finding(
                        catalog.ENV_ASSIGNMENT, file, number, line, match.group(2), in_tests,
                        variable=match.group(1)))
            elif allow_generic:
                match = catalog.GENERIC_ASSIGNMENT.pattern.search(line)
                if match and catalog.is_plausible(catalog.GENERIC_ASSIGNMENT, match.group(2)) \
                        and not self._covered(findings, number):
                    findings.append(self._finding(
                        catalog.GENERIC_ASSIGNMENT, file, number, line, match.group(2), in_tests,
                        variable=match.group(1)))
            if len(findings) >= _MAX_PER_FILE:
                break
        return findings

    @staticmethod
    def _covered(findings: list[Finding], line: int) -> bool:
        return any(f.line == line for f in findings)

    @staticmethod
    def _finding(
        rule: catalog.SecretRule, file: SourceFile, number: int, line: str, value: str,
        in_tests: bool, variable: str = "",
    ) -> Finding:
        redacted = catalog.redact(value) if rule.rule_id != "SEC019" else value
        shown = line.strip()
        if value and rule.rule_id != "SEC019":
            shown = shown.replace(value, redacted)
        if len(shown) > 240:
            shown = shown[:239] + "…"
        severity = rule.severity
        confidence = rule.confidence
        if in_tests:
            confidence = round(confidence * 0.6, 2)
            if severity in (Severity.CRITICAL, Severity.HIGH):
                severity = Severity.MEDIUM
        subject = f"'{variable}'" if variable else "A value"
        description = (
            f"{subject} matching the {rule.title} format is committed in "
            f"{PurePosixPath(file.rel).name}. Treat it as compromised: revoke it, rotate it, "
            "and load it from the environment or a secrets manager."
        )
        return Finding(
            engine="secrets",
            rule_id=rule.rule_id,
            title=rule.title if rule.rule_id != "SEC100" else "Hardcoded credential",
            description=description,
            severity=severity,
            confidence=confidence,
            file_path=file.rel,
            line=number,
            snippet=f"{number}  {shown}",
            cwe="CWE-798",
            references=list(catalog.ROTATE),
            metadata={"redacted": redacted},
        )
