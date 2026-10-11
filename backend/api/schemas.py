"""Pydantic models shared by backend, scanners, and UI."""
import uuid
from collections import Counter
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class TargetType(str, Enum):
    GITHUB_REPO = "github_repo"
    LOCAL_PATH = "local_path"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# ----------------------------- requests ---------------------------------- #

class ScanRequest(BaseModel):
    target_type: TargetType
    target: str = Field(min_length=1, max_length=2048)


# ----------------------------- findings ---------------------------------- #

class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: new_id("fnd"))
    vulnerability_type: str = "Unknown"
    location: str = ""
    severity: Severity = Severity.INFO
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence: str = ""
    why_dangerous: str = ""
    how_to_fix: str = ""
    analyzed: bool = False
    analysis_source: str = ""


class ScanSummary(BaseModel):
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


def build_summary(findings: Iterable[Finding]) -> ScanSummary:
    counts = Counter(f.severity for f in findings)
    return ScanSummary(
        total=sum(counts.values()),
        critical=counts.get(Severity.CRITICAL, 0),
        high=counts.get(Severity.HIGH, 0),
        medium=counts.get(Severity.MEDIUM, 0),
        low=counts.get(Severity.LOW, 0),
        info=counts.get(Severity.INFO, 0),
    )


# ----------------------------- reports ----------------------------------- #

class Report(BaseModel):
    report_id: str = Field(default_factory=lambda: new_id("rpt"))
    target: str = ""
    target_type: TargetType = TargetType.LOCAL_PATH
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: Optional[datetime] = None
    summary: ScanSummary = Field(default_factory=ScanSummary)
    findings: List[Finding] = Field(default_factory=list)
    scanner_notes: List[str] = Field(default_factory=list)


class ReportMeta(BaseModel):
    report_id: str
    target: str
    target_type: TargetType
    finished_at: Optional[datetime] = None
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


# ----------------------------- jobs -------------------------------------- #

class StageInfo(BaseModel):
    name: str
    status: str = "pending"
    detail: str = ""


class JobView(BaseModel):
    job_id: str
    target: str
    target_type: TargetType
    status: JobStatus
    label: Optional[str] = None
    progress: int = 0
    current_stage: str = ""
    stages: List[StageInfo] = Field(default_factory=list)
    error: Optional[str] = None
    report: Optional[Report] = None


class JobSummary(BaseModel):
    job_id: str
    label: Optional[str] = None
    target: str
    target_type: TargetType
    status: JobStatus
    progress: int = 0
    current_stage: str = ""
    created_at: float = 0.0
    report_id: Optional[str] = None
    error: Optional[str] = None


class ScanAccepted(BaseModel):
    job_id: str
    status: JobStatus
    message: str


# ----------------------------- system ------------------------------------ #

class HealthResponse(BaseModel):
    status: str
    version: str
    ollama: Dict[str, Any]
    scanners_registered: List[str]


# ----------------------------- ai settings ------------------------------- #

class AISettingsRequest(BaseModel):
    provider: str = Field(pattern="^(ollama|mistral|groq|openrouter|openai|custom)$")
    api_base: str = ""
    api_key: str = ""
    model: str = ""


class AISettingsResponse(BaseModel):
    provider: str
    provider_label: str
    model: str
    api_base: str = ""
    key_set: bool = False
    key_masked: str = ""
    ready: bool = False
    message: str = ""
    presets: Dict[str, Any] = Field(default_factory=dict)


class AIKeyRequest(BaseModel):
    api_key: str = Field(min_length=8, max_length=4096)
