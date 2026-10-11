"""Thread-safe in-memory scan job tracker.

Jobs are mutated by worker threads and read by request handlers,
so every access goes through one lock and readers get immutable views.
list_summaries() backs the UI's persistent "Recent uploads" panel —
the backend, not the browser, is the source of truth for scan state.
"""
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from backend.api.schemas import (
    JobStatus, JobSummary, JobView, Report, ScanRequest, StageInfo, new_id,
)

_TERMINAL = (JobStatus.COMPLETED, JobStatus.FAILED)


@dataclass
class Job:
    job_id: str
    request: ScanRequest
    label: Optional[str] = None          # friendly name ("myproject · 7 file(s)")
    status: JobStatus = JobStatus.QUEUED
    progress: int = 0
    current_stage: str = ""
    stages: List[StageInfo] = field(default_factory=list)
    error: Optional[str] = None
    report: Optional[Report] = None
    created_at: float = field(default_factory=time.time)

    def view(self) -> JobView:
        return JobView(
            job_id=self.job_id,
            target=self.request.target,
            target_type=self.request.target_type,
            status=self.status,
            label=self.label,
            progress=self.progress,
            current_stage=self.current_stage,
            stages=[StageInfo(**s.model_dump()) for s in self.stages],
            error=self.error,
            report=self.report,
        )

    def summary(self) -> JobSummary:
        return JobSummary(
            job_id=self.job_id,
            label=self.label,
            target=self.request.target,
            target_type=self.request.target_type,
            status=self.status,
            progress=self.progress,
            current_stage=self.current_stage,
            created_at=self.created_at,
            report_id=self.report.report_id if self.report else None,
            error=self.error,
        )


class JobManager:
    def __init__(self, max_jobs: int = 50) -> None:
        self._jobs: Dict[str, Job] = {}
        self._lock = threading.Lock()
        self._max_jobs = max_jobs

    # -- lifecycle ----------------------------------------------------------

    def create(self, request: ScanRequest, label: Optional[str] = None) -> Job:
        job = Job(job_id=new_id("job"), request=request, label=label)
        with self._lock:
            self._jobs[job.job_id] = job
            self._trim_locked()
        return job

    def get(self, job_id: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(job_id)

    def get_view(self, job_id: str) -> Optional[JobView]:
        with self._lock:
            job = self._jobs.get(job_id)
            return job.view() if job is not None else None

    def list_summaries(self) -> List[JobSummary]:
        """All jobs, newest first — the persistence backbone for the UI."""
        with self._lock:
            items = [job.summary() for job in self._jobs.values()]
        items.sort(key=lambda s: s.created_at, reverse=True)
        return items

    # -- stage transitions ----------------------------------------------------

    def start(self, job_id: str, stage_names: List[str]) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.status == JobStatus.RUNNING:
                return
            job.status = JobStatus.RUNNING
            job.stages = [StageInfo(name=name, status="pending") for name in stage_names]
            job.current_stage = stage_names[0] if stage_names else ""
            job.progress = 2

    def begin_stage(self, job_id: str, stage_name: str) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            self._set_stage_locked(job, stage_name, "running")
            job.current_stage = stage_name

    def finish_stage(self, job_id: str, stage_name: str, status: str = "done", detail: str = "") -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            self._set_stage_locked(job, stage_name, status, detail)
            job.progress = self._stage_progress_locked(job)

    def touch(self, job_id: str, stage_name: str, detail: str) -> None:
        """Live detail update from inside a running stage."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            for stage in job.stages:
                if stage.name == stage_name and stage.status == "running":
                    stage.detail = detail
                    return

    def bump_progress(self, job_id: str, pct: int) -> None:
        """Raise progress to pct if higher (never lowers, never reaches 100)."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.status != JobStatus.RUNNING:
                return
            if pct > job.progress:
                job.progress = min(pct, 99)

    def complete(self, job_id: str, report: Report) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            job.status = JobStatus.COMPLETED
            job.progress = 100
            job.report = report
            job.current_stage = ""
            for stage in job.stages:
                if stage.status in ("pending", "running"):
                    stage.status = "done"

    def fail(self, job_id: str, error: str) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            job.status = JobStatus.FAILED
            job.error = error
            job.current_stage = ""
            for stage in job.stages:
                if stage.status == "running":
                    stage.status = "skipped"

    # -- internals ------------------------------------------------------------

    @staticmethod
    def _set_stage_locked(job: Job, stage_name: str, status: str, detail: str = "") -> None:
        for stage in job.stages:
            if stage.name == stage_name:
                stage.status = status
                if detail:
                    stage.detail = detail
                return
        job.stages.append(StageInfo(name=stage_name, status=status, detail=detail))

    @staticmethod
    def _stage_progress_locked(job: Job) -> int:
        if not job.stages:
            return job.progress
        done = sum(1 for s in job.stages if s.status in ("done", "skipped"))
        return min(99, int((done / len(job.stages)) * 100))

    def _trim_locked(self) -> None:
        if len(self._jobs) <= self._max_jobs:
            return
        finished = sorted(
            (job.created_at, job_id)
            for job_id, job in self._jobs.items()
            if job.status in _TERMINAL
        )
        excess = len(self._jobs) - self._max_jobs
        for _, job_id in finished[:excess]:
            self._jobs.pop(job_id, None)
