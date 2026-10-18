"""Shared rule model for line-oriented pattern engines."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from re import Pattern

from backend.schemas import Severity


@dataclass(frozen=True)
class PatternRule:
    rule_id: str
    title: str
    pattern: Pattern[str]
    severity: Severity
    confidence: float
    cwe: str
    description: str
    unless: Pattern[str] | None = None
    references: tuple[str, ...] = field(default_factory=tuple)
    masked: bool = False

    def matches(self, line: str, masked: str | None = None) -> bool:
        """Tests one line. Rules flagged ``masked`` look at the line with string contents
        blanked out, so a sink named inside a string literal never matches."""
        subject = masked if self.masked and masked is not None else line
        if not self.pattern.search(subject):
            return False
        return not (self.unless is not None and self.unless.search(line))


def rx(pattern: str, flags: int = 0) -> Pattern[str]:
    return re.compile(pattern, flags)
