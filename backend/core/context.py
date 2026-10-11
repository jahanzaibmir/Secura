"""Single place where backend wiring happens. Import cycle-proof by design."""
import backend.scanners  # noqa: F401  — scanner modules self-register

from backend.config import settings
from backend.core.ai_manager import AnalyzerManager
from backend.core.jobs import JobManager
from backend.core.pipeline import ScanPipeline
from backend.core.registry import registry
from backend.storage.report_store import ReportStore

ai_manager = AnalyzerManager(settings)   # owns the active analyzer; swappable
jobs = JobManager(max_jobs=settings.max_stored_jobs)
store = ReportStore(settings.reports_dir)
pipeline = ScanPipeline(registry, jobs, ai_manager, store, settings)
