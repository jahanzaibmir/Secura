"""Finding model: one security issue located in the scanned source."""
from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

from pydantic import BaseModel, Field, computed_field

from backend.schemas.common import ExplanationSource, Severity, new_id


class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: new_id("fnd"))
    fingerprint: str = ""
    engine: str = ""
    rule_id: str = ""
    title: str = "Unknown issue"
    description: str = ""
    severity: Severity = Severity.INFO
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    file_path: str = ""
    line: int | None = Field(default=None, ge=0)
    snippet: str = ""
    cwe: str | None = None
    references: list[str] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)

    why_dangerous: str = ""
    how_to_fix: str = ""
    explanation_source: ExplanationSource = ExplanationSource.NONE
    explanation_model: str = ""

    @computed_field
    @property
    def location(self) -> str:
        if not self.file_path:
            return ""
        return f"{self.file_path}:{self.line}" if self.line else self.file_path

    @property
    def explained_by_ai(self) -> bool:
        return self.explanation_source == ExplanationSource.AI


class ScanSummary(BaseModel):
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    def count(self, severity: Severity) -> int:
        return int(getattr(self, severity.value))


def build_summary(findings: Iterable[Finding]) -> ScanSummary:
    counts = Counter(finding.severity for finding in findings)
    return ScanSummary(
        total=sum(counts.values()),
        **{severity.value: counts.get(severity, 0) for severity in Severity},
    )
