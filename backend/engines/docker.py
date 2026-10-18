"""Dockerfile hardening analysis."""
from __future__ import annotations

import re
from dataclasses import dataclass

from backend.engines.base import Engine, EngineContext, EngineResult, trim_snippet
from backend.engines.inventory import KIND_DOCKERFILE, Inventory, read_text
from backend.engines.rules.docker import INSTRUCTION_RULES, ROOT_USER, UNPINNED_IMAGE
from backend.engines.rules.model import PatternRule
from backend.schemas import Finding

_FROM_RE = re.compile(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", re.IGNORECASE)
_USER_RE = re.compile(r"^USER\s+(\S+)", re.IGNORECASE)
_ROOT_USERS = {"root", "0", "0:0", "root:root"}


@dataclass
class Instruction:
    line: int
    text: str


def parse_instructions(text: str) -> list[Instruction]:
    """Joins continuation lines and drops comments, keeping each instruction's first line."""
    instructions: list[Instruction] = []
    buffer = ""
    start = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not buffer and (not stripped or stripped.startswith("#")):
            continue
        if buffer and stripped.startswith("#"):
            continue
        if not buffer:
            start = number
        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
            continue
        buffer += stripped
        instructions.append(Instruction(line=start, text=buffer))
        buffer = ""
    if buffer:
        instructions.append(Instruction(line=start, text=buffer))
    return instructions


class DockerfileEngine(Engine):
    name = "docker"
    label = "Dockerfile"
    description = "Container hardening checks: root user, unpinned images, baked-in secrets."

    def applies(self, inventory: Inventory) -> bool:
        return bool(inventory.of_kind(KIND_DOCKERFILE))

    def run(self, context: EngineContext) -> EngineResult:
        files = context.inventory.of_kind(KIND_DOCKERFILE)
        result = EngineResult()
        for file in files:
            context.token.raise_if_cancelled()
            text = read_text(file)
            if text is None:
                continue
            result.findings.extend(self._analyse(file.rel, text))
        result.detail = f"{len(files)} Dockerfile(s)"
        return result

    def _analyse(self, rel: str, text: str) -> list[Finding]:
        lines = text.splitlines()
        instructions = parse_instructions(text)
        findings: list[Finding] = []
        stages: set[str] = set()
        last_from: Instruction | None = None
        final_user: str | None = None

        for instruction in instructions:
            from_match = _FROM_RE.match(instruction.text)
            if from_match:
                image, alias = from_match.group(1), from_match.group(2)
                if self._unpinned(image, stages):
                    findings.append(self._finding(UNPINNED_IMAGE, rel, lines, instruction.line))
                if alias:
                    stages.add(alias.lower())
                last_from = instruction
                final_user = None
                continue
            user_match = _USER_RE.match(instruction.text)
            if user_match:
                final_user = user_match.group(1).lower()
            for rule in INSTRUCTION_RULES:
                if rule.matches(instruction.text):
                    findings.append(self._finding(rule, rel, lines, instruction.line))

        if last_from is not None and (final_user is None or final_user in _ROOT_USERS):
            target = last_from.line
            findings.append(self._finding(ROOT_USER, rel, lines, target))
        return findings

    @staticmethod
    def _unpinned(image: str, stages: set[str]) -> bool:
        lowered = image.lower()
        if lowered == "scratch" or lowered in stages or "$" in image or "@sha256:" in lowered:
            return False
        name = lowered.rsplit("/", 1)[-1]
        if ":" not in name:
            return True
        return name.endswith(":latest")

    @staticmethod
    def _finding(rule: PatternRule, rel: str, lines: list[str], line: int) -> Finding:
        return Finding(
            engine="docker",
            rule_id=rule.rule_id,
            title=rule.title,
            description=rule.description,
            severity=rule.severity,
            confidence=rule.confidence,
            file_path=rel,
            line=line,
            snippet=trim_snippet(lines, line, radius=0),
            cwe=rule.cwe,
            references=list(rule.references),
        )
