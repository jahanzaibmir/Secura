"""Pydantic models shared by the API, the core services, and the interface."""
from backend.schemas.ai import AIKeyRequest, AIProviderUpdate, AISettingsResponse, ProviderPreset
from backend.schemas.common import (
    ExplanationSource,
    JobStatus,
    Severity,
    StageStatus,
    TargetType,
    new_id,
    utc_now,
)
from backend.schemas.findings import Finding, ScanSummary, build_summary
from backend.schemas.jobs import JobView, ScanAccepted, ScanCreate, ScanRequest, StageInfo
from backend.schemas.reports import (
    AnalysisInfo,
    EngineRun,
    Report,
    ReportMeta,
    RiskScore,
    ScanStats,
)
from backend.schemas.system import AIStatus, EngineInfo, HealthResponse

__all__ = [
    "AIKeyRequest",
    "AIProviderUpdate",
    "AISettingsResponse",
    "AIStatus",
    "AnalysisInfo",
    "EngineInfo",
    "EngineRun",
    "ExplanationSource",
    "Finding",
    "HealthResponse",
    "JobStatus",
    "JobView",
    "ProviderPreset",
    "Report",
    "ReportMeta",
    "RiskScore",
    "ScanAccepted",
    "ScanCreate",
    "ScanRequest",
    "ScanStats",
    "ScanSummary",
    "Severity",
    "StageInfo",
    "StageStatus",
    "TargetType",
    "build_summary",
    "new_id",
    "utc_now",
]
