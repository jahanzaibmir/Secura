"""Scan job models: requests, live progress views, and acknowledgements."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from backend.schemas.common import JobStatus, StageStatus, TargetType
from backend.schemas.findings import ScanSummary
from backend.schemas.reports import RiskScore


class ScanRequest(BaseModel):
    """Internal scan request. Any target type, including uploads."""

    target_type: TargetType
    target: str = Field(min_length=1, max_length=4096)


class ScanCreate(BaseModel):
    """Public scan request accepted by ``POST /api/scans``."""

    target_type: Literal["github_repo", "local_path"] = "github_repo"
    target: str = Field(min_length=1, max_length=2048)

    def to_request(self) -> ScanRequest:
        return ScanRequest(target_type=TargetType(self.target_type), target=self.target.strip())


class StageInfo(BaseModel):
    key: str
    label: str
    status: StageStatus = StageStatus.PENDING
    detail: str = ""


class JobView(BaseModel):
    job_id: str
    label: str
    target: str
    target_type: TargetType
    status: JobStatus
    progress: int = Field(default=0, ge=0, le=100)
    current_stage: str = ""
    stages: list[StageInfo] = Field(default_factory=list)
    error: str | None = None
    report_id: str | None = None
    summary: ScanSummary | None = None
    risk: RiskScore | None = None
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None


class ScanAccepted(BaseModel):
    job_id: str
    status: JobStatus
    message: str
