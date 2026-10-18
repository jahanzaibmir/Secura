"""Shared enums and helpers used across every schema module."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import Enum


def utc_now() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class TargetType(str, Enum):
    GITHUB_REPO = "github_repo"
    LOCAL_PATH = "local_path"
    UPLOAD = "upload"

    @property
    def label(self) -> str:
        return _TARGET_LABELS[self]


_TARGET_LABELS = {
    TargetType.GITHUB_REPO: "GitHub repository",
    TargetType.LOCAL_PATH: "Local folder",
    TargetType.UPLOAD: "Uploaded codebase",
}


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Sort key: 0 is the most severe."""
        return _SEVERITY_RANK[self]

    @property
    def label(self) -> str:
        return self.value.capitalize()

    @classmethod
    def ordered(cls) -> list[Severity]:
        return sorted(cls, key=lambda severity: severity.rank)


_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def is_terminal(self) -> bool:
        return self in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED)


class StageStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    SKIPPED = "skipped"
    FAILED = "failed"

    @property
    def is_settled(self) -> bool:
        return self in (StageStatus.DONE, StageStatus.SKIPPED, StageStatus.FAILED)


class ExplanationSource(str, Enum):
    AI = "ai"
    KNOWLEDGE_BASE = "knowledge_base"
    NONE = "none"
