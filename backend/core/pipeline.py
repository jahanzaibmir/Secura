"""Scan pipeline: validate, acquire, index, scan, explain, report.

Engines are isolated from one another: one engine failing is recorded in the
report and the scan carries on. Findings are de-duplicated and ranked before
analysis, so the AI budget always lands on the most severe issues while every
other finding receives deterministic knowledge-base guidance.
"""
from __future__ import annotations

import hashlib
import logging
import re
import time
from collections.abc import Callable, Sequence
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait

from backend.ai.analyzers import BaseAnalyzer
from backend.ai.knowledge import explain_from_knowledge
from backend.config import Settings
from backend.core.jobs import Job, JobManager
from backend.core.redaction import redact_finding
from backend.core.scoring import compute_risk
from backend.core.validators import validate_target
from backend.engines import Engine, EngineContext
from backend.engines.inventory import Inventory, build_inventory
from backend.exceptions import EngineError, JobNotFound, ScanCancelled, SecuraError
from backend.schemas import (
    AnalysisInfo,
    EngineRun,
    ExplanationSource,
    Finding,
    Report,
    ScanStats,
    Severity,
    StageStatus,
    TargetType,
    build_summary,
    utc_now,
)
from backend.sources import SourceContext, SourceRegistry
from backend.storage.workspace import remove_tree

logger = logging.getLogger("secura.pipeline")

STAGE_VALIDATE = "validate"
STAGE_ACQUIRE = "acquire"
STAGE_INDEX = "index"
STAGE_SCAN = "scan"
STAGE_ANALYZE = "analyze"
STAGE_REPORT = "report"

STAGES = (
    (STAGE_VALIDATE, "Validate target", 2.0),
    (STAGE_ACQUIRE, "Fetch source", 18.0),
    (STAGE_INDEX, "Index files", 5.0),
    (STAGE_SCAN, "Run security engines", 45.0),
    (STAGE_ANALYZE, "Explain findings", 25.0),
    (STAGE_REPORT, "Compile report", 5.0),
)

AnalyzerProvider = Callable[[], BaseAnalyzer]


def fingerprint(finding: Finding) -> str:
    snippet = re.sub(r"^\s*\d+\s+", "", finding.snippet or "", flags=re.MULTILINE)
    snippet = re.sub(r"\s+", " ", snippet).strip()
    material = "|".join([
        finding.engine, finding.rule_id, finding.file_path, str(finding.line or ""),
        snippet[:400], finding.metadata.get("redacted", ""),
    ])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def rank(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (f.severity.rank, -f.confidence, f.file_path, f.line or 0, f.rule_id),
    )


class ScanPipeline:
    def __init__(
        self,
        settings: Settings,
        sources: SourceRegistry,
        engines: Sequence[Engine],
        jobs: JobManager,
        analyzer: AnalyzerProvider,
        store,
    ) -> None:
        self._settings = settings
        self._sources = sources
        self._engines = list(engines)
        self._jobs = jobs
        self._analyzer = analyzer
        self._store = store

    def run_job(self, job_id: str) -> None:
        try:
            job = self._jobs.get(job_id)
        except JobNotFound:
            logger.error("Received unknown job %s", job_id)
            return
        try:
            if not self._jobs.start(job_id, STAGES):
                return
            report = self._execute(job)
            self._jobs.complete(job_id, report)
            logger.info("Job %s completed: %d finding(s), grade %s, report %s",
                        job_id, report.summary.total, report.risk.grade, report.report_id)
        except ScanCancelled:
            self._jobs.mark_cancelled(job_id)
            logger.info("Job %s cancelled", job_id)
        except SecuraError as exc:
            self._jobs.fail(job_id, str(exc))
            logger.warning("Job %s failed: %s", job_id, exc)
        except Exception as exc:
            self._jobs.fail(job_id, f"Unexpected error: {exc.__class__.__name__}: {exc}")
            logger.exception("Job %s crashed", job_id)
        finally:
            if job.cleanup_path is not None:
                remove_tree(job.cleanup_path)

    def _execute(self, job: Job) -> Report:
        job_id, token, request = job.job_id, job.token, job.request

        self._jobs.begin_stage(job_id, STAGE_VALIDATE)
        normalized = validate_target(request.target_type, request.target)
        display = job.label if request.target_type == TargetType.UPLOAD else normalized
        report = Report(target=display, target_type=request.target_type)
        self._jobs.finish_stage(job_id, STAGE_VALIDATE, detail="Target accepted")

        source = self._sources.get(request.target_type)
        self._jobs.begin_stage(job_id, STAGE_ACQUIRE, detail=source.label)
        context = SourceContext(
            settings=self._settings,
            token=token,
            progress=lambda detail, fraction: self._jobs.update_stage(
                job_id, STAGE_ACQUIRE, detail=detail, fraction=fraction),
        )
        with source.open(normalized, context) as root:
            self._jobs.finish_stage(job_id, STAGE_ACQUIRE, detail="Source ready")
            token.raise_if_cancelled()

            self._jobs.begin_stage(job_id, STAGE_INDEX)
            inventory = build_inventory(root, self._settings.max_scan_file_bytes, token)
            report.stats = ScanStats(
                files_scanned=len(inventory.files),
                files_skipped=inventory.skipped,
                bytes_scanned=inventory.total_bytes,
                languages=inventory.languages,
            )
            self._jobs.finish_stage(job_id, STAGE_INDEX, detail=f"{len(inventory.files)} relevant file(s)")
            if not inventory.files:
                report.notes.append("No source code, configuration or manifests were found to scan.")

            findings = self._run_engines(job_id, root, inventory, token, report)

        findings = self._consolidate([redact_finding(f) for f in findings], report)
        self._analyze(job_id, token, findings, report)

        self._jobs.begin_stage(job_id, STAGE_REPORT)
        report.findings = findings
        report.summary = build_summary(findings)
        report.risk = compute_risk(findings)
        report.finished_at = utc_now()
        self._store.save(report)
        self._jobs.finish_stage(job_id, STAGE_REPORT, detail=f"Grade {report.risk.grade}")
        return report

    def _run_engines(self, job_id, root, inventory: Inventory, token, report: Report) -> list[Finding]:
        self._jobs.begin_stage(job_id, STAGE_SCAN)
        planned = [e for e in self._engines if e.applies(inventory)]
        findings: list[Finding] = []

        for index, engine in enumerate(planned):
            token.raise_if_cancelled()
            available, reason = engine.availability(self._settings)
            if not available:
                report.engines.append(EngineRun(name=engine.name, label=engine.label,
                                                status="skipped", detail=reason))
                continue

            def progress(detail: str, fraction: float, _i=index, _engine=engine) -> None:
                self._jobs.update_stage(
                    job_id, STAGE_SCAN, detail=f"{_engine.label}: {detail}",
                    fraction=(_i + max(0.0, min(1.0, fraction))) / max(1, len(planned)),
                )

            progress("starting", 0.0)
            started = time.monotonic()
            context = EngineContext(root=root, inventory=inventory, settings=self._settings,
                                    token=token, progress=progress)
            try:
                result = engine.run(context)
            except ScanCancelled:
                raise
            except EngineError as exc:
                report.engines.append(EngineRun(name=engine.name, label=engine.label, status="failed",
                                                duration_seconds=round(time.monotonic() - started, 2),
                                                detail=str(exc)[:300]))
                report.notes.append(f"{engine.label} failed: {exc}")
                continue
            except Exception as exc:
                logger.exception("Engine %s crashed", engine.name)
                report.engines.append(EngineRun(name=engine.name, label=engine.label, status="failed",
                                                duration_seconds=round(time.monotonic() - started, 2),
                                                detail=f"Internal error: {exc.__class__.__name__}"))
                report.notes.append(f"{engine.label} stopped unexpectedly and was skipped.")
                continue

            findings.extend(result.findings)
            report.notes.extend(result.notes)
            report.engines.append(EngineRun(
                name=engine.name, label=engine.label, status="completed",
                findings=len(result.findings),
                duration_seconds=round(time.monotonic() - started, 2),
                detail=result.detail,
            ))

        ran = sum(1 for e in report.engines if e.status == "completed")
        self._jobs.finish_stage(job_id, STAGE_SCAN,
                                detail=f"{ran} engine(s), {len(findings)} raw finding(s)")
        return findings

    def _consolidate(self, findings: list[Finding], report: Report) -> list[Finding]:
        unique: dict[str, Finding] = {}
        for finding in findings:
            finding.fingerprint = finding.fingerprint or fingerprint(finding)
            current = unique.get(finding.fingerprint)
            if current is None or finding.severity.rank < current.severity.rank:
                unique[finding.fingerprint] = finding
        ranked = rank(list(unique.values()))
        cap = self._settings.max_findings
        if len(ranked) > cap:
            report.notes.append(f"{len(ranked)} findings were reported; the {cap} most severe are kept.")
            ranked = ranked[:cap]
        return ranked

    def _analyze(self, job_id: str, token, findings: list[Finding], report: Report) -> None:
        analyzer = self._analyzer()
        report.analysis = AnalysisInfo(provider=analyzer.provider_label, model=analyzer.model)

        if not findings:
            self._jobs.finish_stage(job_id, STAGE_ANALYZE, StageStatus.SKIPPED, "No findings to explain")
            return

        self._jobs.begin_stage(job_id, STAGE_ANALYZE, detail="Checking AI provider")
        readiness = analyzer.readiness()
        budget = self._settings.ai_max_findings if readiness.ready else 0
        candidates = [f for f in findings if f.severity != Severity.INFO][:budget]
        chosen = {id(f) for f in candidates}

        for finding in findings:
            if id(finding) not in chosen:
                self._apply_knowledge(finding)

        if not candidates:
            if not readiness.ready:
                report.notes.append(f"{readiness.message} Every finding uses knowledge-base guidance.")
            report.analysis.explained_by_knowledge_base = len(findings)
            self._jobs.finish_stage(job_id, STAGE_ANALYZE, StageStatus.DONE, "Knowledge base guidance applied")
            return

        explained, failures = self._explain_parallel(job_id, token, analyzer, candidates)
        report.analysis.explained_by_ai = explained
        report.analysis.explained_by_knowledge_base = len(findings) - explained
        if failures:
            report.notes.append(
                f"The AI could not explain {failures} finding(s); knowledge-base guidance was used instead.")
        remaining = len(findings) - explained
        if remaining and explained:
            report.notes.append(
                f"{analyzer.model} explained the {explained} most severe finding(s); the other "
                f"{remaining} use knowledge-base guidance. Raise SECURA_AI_MAX_FINDINGS to explain more.")
        self._jobs.finish_stage(job_id, STAGE_ANALYZE,
                                detail=f"{explained} by AI, {len(findings) - explained} by knowledge base")

    def _explain_parallel(self, job_id, token, analyzer: BaseAnalyzer, candidates: list[Finding]):
        total = len(candidates)
        done = explained = failures = 0
        workers = max(1, min(analyzer.max_concurrency, total))
        pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="secura-ai")
        pending: dict[Future, Finding] = {}
        try:
            for finding in candidates:
                pending[pool.submit(analyzer.explain, finding)] = finding
            self._jobs.update_stage(job_id, STAGE_ANALYZE, detail=f"Explaining 0/{total} with {analyzer.model}")
            while pending:
                if token.cancelled:
                    raise ScanCancelled("The scan was cancelled.")
                finished, _ = wait(list(pending), timeout=0.5, return_when=FIRST_COMPLETED)
                for future in finished:
                    finding = pending.pop(future)
                    try:
                        why, fix = future.result()
                        finding.why_dangerous, finding.how_to_fix = why, fix
                        finding.explanation_source = ExplanationSource.AI
                        finding.explanation_model = analyzer.model
                        explained += 1
                    except Exception as exc:
                        failures += 1
                        logger.warning("AI explanation failed for %s: %s", finding.rule_id, exc)
                        self._apply_knowledge(finding)
                    done += 1
                    self._jobs.update_stage(
                        job_id, STAGE_ANALYZE,
                        detail=f"Explaining {done}/{total}: {finding.title[:48]}",
                        fraction=done / total,
                    )
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        return explained, failures

    @staticmethod
    def _apply_knowledge(finding: Finding) -> None:
        try:
            why, fix = explain_from_knowledge(finding)
        except Exception:
            logger.exception("Knowledge base lookup failed for %s", finding.rule_id)
            why, fix = "", ""
        finding.why_dangerous = why
        finding.how_to_fix = fix
        finding.explanation_source = ExplanationSource.KNOWLEDGE_BASE
        finding.explanation_model = ""
