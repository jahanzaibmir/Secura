"""Thread-safe in-memory scan job tracker.

Worker threads mutate jobs while request handlers read them, so every access
goes through a single lock and readers only ever receive immutable views.
Overall progress is derived from weighted stages, so the bar moves smoothly and
never goes backwards.
"""
from __future__ import annotations

import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from backend.core.cancellation import CancelToken
from backend.exceptions import JobNotFound
from backend.schemas import (
    JobStatus,
    JobView,
    Report,
    RiskScore,
    ScanRequest,
    ScanSummary,
    StageInfo,
    StageStatus,
    new_id,
    utc_now,
)

StageSpec = tuple[str, str, float]


@dataclass
class _Stage:
    key: str
    label: str
    weight: float
    status: StageStatus = StageStatus.PENDING
    detail: str = ""
    fraction: float = 0.0


@dataclass
class Job:
    job_id: str
    request: ScanRequest
    label: str
    created_at: datetime = field(default_factory=utc_now)
    status: JobStatus = JobStatus.QUEUED
    stages: list[_Stage] = field(default_factory=list)
    current_stage: str = ""
    progress: int = 0
    error: str | None = None
    report_id: str | None = None
    summary: ScanSummary | None = None
    risk: RiskScore | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    cleanup_path: Path | None = None
    token: CancelToken = field(default_factory=CancelToken)

    def view(self) -> JobView:
        return JobView(
            job_id=self.job_id,
            label=self.label,
            target=self.request.target,
            target_type=self.request.target_type,
            status=self.status,
            progress=self.progress,
            current_stage=self.current_stage,
            stages=[
                StageInfo(key=s.key, label=s.label, status=s.status, detail=s.detail)
                for s in self.stages
            ],
            error=self.error,
            report_id=self.report_id,
            summary=self.summary.model_copy() if self.summary else None,
            risk=self.risk.model_copy() if self.risk else None,
            created_at=self.created_at,
            started_at=self.started_at,
            finished_at=self.finished_at,
        )


class JobManager:
    def __init__(self, max_jobs: int = 100) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._max_jobs = max_jobs

    def create(
        self,
        request: ScanRequest,
        label: str | None = None,
        cleanup_path: Path | None = None,
    ) -> Job:
        job = Job(
            job_id=new_id("job"),
            request=request,
            label=label or request.target,
            cleanup_path=cleanup_path,
        )
        with self._lock:
            self._jobs[job.job_id] = job
            self._trim_locked()
        return job

    def get(self, job_id: str) -> Job:
        with self._lock:
            job = self._jobs.get(job_id)
        if job is None:
            raise JobNotFound(f"Unknown scan job: {job_id}")
        return job

    def view(self, job_id: str) -> JobView:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise JobNotFound(f"Unknown scan job: {job_id}")
            return job.view()

    def list_views(self) -> list[JobView]:
        with self._lock:
            views = [job.view() for job in self._jobs.values()]
        views.sort(key=lambda view: view.created_at, reverse=True)
        return views

    def counts(self) -> tuple[int, int]:
        """Returns (running, queued)."""
        with self._lock:
            running = sum(1 for j in self._jobs.values() if j.status == JobStatus.RUNNING)
            queued = sum(1 for j in self._jobs.values() if j.status == JobStatus.QUEUED)
        return running, queued

    def start(self, job_id: str, stages: Sequence[StageSpec]) -> bool:
        """Moves a queued job to running. Returns False if it was cancelled first."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.status != JobStatus.QUEUED:
                return False
            job.status = JobStatus.RUNNING
            job.started_at = utc_now()
            job.stages = [_Stage(key=key, label=label, weight=weight) for key, label, weight in stages]
            job.current_stage = job.stages[0].label if job.stages else ""
            job.progress = 1
            return True

    def begin_stage(self, job_id: str, key: str, detail: str = "") -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            stage = self._stage_locked(job, key)
            if job is None or stage is None:
                return
            stage.status = StageStatus.RUNNING
            stage.detail = detail
            stage.fraction = 0.0
            job.current_stage = stage.label
            self._recompute_locked(job)

    def update_stage(
        self, job_id: str, key: str, detail: str | None = None,
        fraction: float | None = None,
    ) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            stage = self._stage_locked(job, key)
            if job is None or stage is None or stage.status != StageStatus.RUNNING:
                return
            if detail is not None:
                stage.detail = detail
            if fraction is not None:
                stage.fraction = max(stage.fraction, min(1.0, max(0.0, fraction)))
            self._recompute_locked(job)

    def finish_stage(
        self, job_id: str, key: str, status: StageStatus = StageStatus.DONE,
        detail: str | None = None,
    ) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            stage = self._stage_locked(job, key)
            if job is None or stage is None:
                return
            stage.status = status
            stage.fraction = 1.0
            if detail is not None:
                stage.detail = detail
            self._recompute_locked(job)

    def complete(self, job_id: str, report: Report) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            job.status = JobStatus.COMPLETED
            job.progress = 100
            job.current_stage = ""
            job.report_id = report.report_id
            job.summary = report.summary.model_copy()
            job.risk = report.risk.model_copy()
            job.finished_at = utc_now()
            for stage in job.stages:
                if not stage.status.is_settled:
                    stage.status = StageStatus.DONE

    def fail(self, job_id: str, error: str) -> None:
        self._settle(job_id, JobStatus.FAILED, error, StageStatus.FAILED)

    def mark_cancelled(self, job_id: str) -> None:
        self._settle(job_id, JobStatus.CANCELLED, "Cancelled by user.", StageStatus.SKIPPED)

    def cancel(self, job_id: str) -> JobView:
        """Requests cancellation. Queued jobs stop immediately, running jobs cooperatively."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise JobNotFound(f"Unknown scan job: {job_id}")
            job.token.cancel()
            if job.status == JobStatus.QUEUED:
                job.status = JobStatus.CANCELLED
                job.error = "Cancelled by user."
                job.finished_at = utc_now()
            return job.view()

    def _settle(self, job_id: str, status: JobStatus, error: str, open_stage: StageStatus) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            job.status = status
            job.error = error
            job.current_stage = ""
            job.finished_at = utc_now()
            for stage in job.stages:
                if stage.status == StageStatus.RUNNING:
                    stage.status = open_stage
                elif stage.status == StageStatus.PENDING:
                    stage.status = StageStatus.SKIPPED

    @staticmethod
    def _stage_locked(job: Job | None, key: str) -> _Stage | None:
        if job is None:
            return None
        for stage in job.stages:
            if stage.key == key:
                return stage
        return None

    @staticmethod
    def _recompute_locked(job: Job) -> None:
        total = sum(stage.weight for stage in job.stages) or 1.0
        earned = 0.0
        for stage in job.stages:
            if stage.status.is_settled:
                earned += stage.weight
            elif stage.status == StageStatus.RUNNING:
                earned += stage.weight * stage.fraction
        job.progress = max(job.progress, min(99, int(earned / total * 100)))

    def _trim_locked(self) -> None:
        excess = len(self._jobs) - self._max_jobs
        if excess <= 0:
            return
        finished = sorted(
            (job.created_at, job_id)
            for job_id, job in self._jobs.items()
            if job.status.is_terminal
        )
        for _, job_id in finished[:excess]:
            self._jobs.pop(job_id, None)
