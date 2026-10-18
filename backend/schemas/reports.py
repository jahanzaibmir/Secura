"""Report models: the persisted outcome of one scan."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, computed_field

from backend import __version__
from backend.schemas.common import TargetType, new_id, utc_now
from backend.schemas.findings import Finding, ScanSummary


class RiskScore(BaseModel):
    score: int = Field(default=100, ge=0, le=100)
    grade: str = "A"
    label: str = "Excellent"


class EngineRun(BaseModel):
    name: str
    label: str
    status: str = "completed"
    findings: int = 0
    duration_seconds: float = 0.0
    detail: str = ""


class ScanStats(BaseModel):
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    languages: dict[str, int] = Field(default_factory=dict)


class AnalysisInfo(BaseModel):
    provider: str = ""
    model: str = ""
    explained_by_ai: int = 0
    explained_by_knowledge_base: int = 0


class Report(BaseModel):
    schema_version: int = 2
    tool_version: str = __version__
    report_id: str = Field(default_factory=lambda: new_id("rpt"))
    target: str = ""
    target_type: TargetType = TargetType.LOCAL_PATH
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None
    summary: ScanSummary = Field(default_factory=ScanSummary)
    risk: RiskScore = Field(default_factory=RiskScore)
    stats: ScanStats = Field(default_factory=ScanStats)
    engines: list[EngineRun] = Field(default_factory=list)
    analysis: AnalysisInfo = Field(default_factory=AnalysisInfo)
    findings: list[Finding] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    @computed_field
    @property
    def duration_seconds(self) -> float | None:
        if self.finished_at is None:
            return None
        return round((self.finished_at - self.started_at).total_seconds(), 2)


class ReportMeta(BaseModel):
    report_id: str
    target: str
    target_type: TargetType
    started_at: datetime | None = None
    finished_at: datetime | None = None
    summary: ScanSummary = Field(default_factory=ScanSummary)
    risk: RiskScore = Field(default_factory=RiskScore)

    @classmethod
    def from_report(cls, report: Report) -> ReportMeta:
        return cls(
            report_id=report.report_id,
            target=report.target,
            target_type=report.target_type,
            started_at=report.started_at,
            finished_at=report.finished_at,
            summary=report.summary,
            risk=report.risk,
        )
