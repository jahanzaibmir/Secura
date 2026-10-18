"""Service container: the single place where backend components are wired together."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from backend.ai.manager import AnalyzerManager
from backend.config import Settings
from backend.core.executor import ScanExecutor
from backend.core.jobs import Job, JobManager
from backend.core.pipeline import ScanPipeline
from backend.engines import Engine, default_engines
from backend.exceptions import CapacityError
from backend.schemas import EngineInfo, ScanRequest
from backend.sources import SourceRegistry, build_source_registry
from backend.storage.report_store import ReportStore

logger = logging.getLogger("secura.container")


@dataclass
class Container:
    settings: Settings
    sources: SourceRegistry
    engines: list[Engine]
    jobs: JobManager
    store: ReportStore
    ai: AnalyzerManager
    executor: ScanExecutor
    pipeline: ScanPipeline = field(repr=False)

    def submit(
        self, request: ScanRequest, label: str | None = None, cleanup_path: Path | None = None,
    ) -> Job:
        _, queued = self.jobs.counts()
        if queued >= self.settings.max_queued_scans:
            raise CapacityError("The scan queue is full. Try again when a running scan finishes.")
        job = self.jobs.create(request, label=label, cleanup_path=cleanup_path)
        self.executor.submit(self.pipeline.run_job, job.job_id)
        logger.info("Queued %s for %s (%s)", job.job_id, job.label, request.target_type.value)
        return job

    def engine_info(self) -> list[EngineInfo]:
        return [engine.info(self.settings) for engine in self.engines]

    def shutdown(self) -> None:
        self.executor.shutdown(wait=False)


def build_container(settings: Settings) -> Container:
    settings.ensure_dirs()
    sources = build_source_registry()
    engines = default_engines()
    jobs = JobManager(max_jobs=settings.max_stored_jobs)
    store = ReportStore(settings.reports_dir)
    ai = AnalyzerManager(settings)
    executor = ScanExecutor(settings.max_concurrent_scans)
    pipeline = ScanPipeline(settings, sources, engines, jobs, ai.current, store)
    return Container(settings, sources, engines, jobs, store, ai, executor, pipeline)
