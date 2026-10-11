"""Scan pipeline: validate → scan → analyze → report.

Findings are severity-sorted immediately after scanning so the AI
budget always covers the most severe issues; everything beyond the budget
receives deterministic rule-based guidance.

The analyzer is resolved at analysis time through the AnalyzerManager
(passed in as `analyzer`), so provider switches made in AI Setup take
effect on the next scan. For test compatibility a plain analyzer instance
is also accepted and used directly.
"""
import logging
from typing import List

from backend.ai.analyzer import OllamaAnalyzer
from backend.ai.knowledge import fallback_explanation
from backend.api.schemas import (
    Finding, Report, ScanRequest, Severity, build_summary, utc_now,
)
from backend.core.jobs import JobManager
from backend.core.registry import ScannerRegistry
from backend.core.validators import validate_target
from backend.exceptions import ValidationError, SecuraError
from backend.storage.report_store import ReportStore

STAGE_VALIDATE = "Validating target"
STAGE_SCAN = "Scanning target"
STAGE_ANALYZE = "Analyzing findings (AI)"
STAGE_REPORT = "Compiling report"
PIPELINE_STAGES = [STAGE_VALIDATE, STAGE_SCAN, STAGE_ANALYZE, STAGE_REPORT]

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class ScanPipeline:
    def __init__(
        self,
        registry: ScannerRegistry,
        jobs: JobManager,
        analyzer,
        store: ReportStore,
        settings,
    ) -> None:
        self._registry = registry
        self._jobs = jobs
        self._analyzer_source = analyzer   # AnalyzerManager or plain analyzer
        self._store = store
        self._settings = settings
        self._log = logging.getLogger("secura.pipeline")

    @property
    def _analyzer(self):
        """Resolve the active analyzer (manager-aware, live)."""
        source = self._analyzer_source
        if hasattr(source, "current"):
            return source.current()
        return source

    # -- entrypoint (run in a worker thread by the API layer) ----------------

    def run_job(self, job_id: str) -> None:
        job = self._jobs.get(job_id)
        if job is None:
            self._log.error("Received unknown job %s", job_id)
            return
        request = job.request
        self._jobs.start(job_id, PIPELINE_STAGES)
        report = Report(target=request.target, target_type=request.target_type)
        try:
            self._run(job_id, request, report)
        except ValidationError as exc:
            self._jobs.fail(job_id, str(exc))
            self._log.info("Job %s rejected: %s", job_id, exc)
        except SecuraError as exc:
            self._jobs.fail(job_id, str(exc))
            self._log.error("Job %s failed: %s", job_id, exc)
        except Exception as exc:  # last-resort guard. a job never hangs
            self._jobs.fail(job_id, f"Unexpected error: {exc}")
            self._log.exception("Job %s crashed unexpectedly", job_id)

    # -- the four stages -------------------------------------------------------

    def _run(self, job_id: str, request: ScanRequest, report: Report) -> None:
        # 1. validate
        self._jobs.begin_stage(job_id, STAGE_VALIDATE)
        normalized = validate_target(request.target_type, request.target)
        report.target = normalized
        self._jobs.finish_stage(job_id, STAGE_VALIDATE, detail="Target accepted")

        # 2. scan, then sort and cap BEFORE analysis so the AI budget
        #     always lands on the most severe findings.
        findings: List[Finding] = []
        scanner = self._registry.create(
            request.target_type,
            normalized,
            progress=lambda detail, pct: self._jobs.touch(job_id, STAGE_SCAN, detail),
        )
        if scanner is None:
            report.scanner_notes.append(
                f"No scanner registered for '{request.target_type.value}'. "
                "its module may be missing a dependency. Check logs/secura.log."
            )
            self._jobs.finish_stage(job_id, STAGE_SCAN, status="skipped",
                                    detail="Scanner unavailable")
        else:
            self._jobs.begin_stage(job_id, STAGE_SCAN)
            findings = scanner.scan() or []
            report.scanner_notes.extend(scanner.notes)
            findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))
            cap = self._settings.max_findings_per_scan
            if len(findings) > cap:
                report.scanner_notes.append(
                    f"The scanner reported {len(findings)} findings; "
                    f"the {cap} most severe are kept."
                )
                findings = findings[:cap]
            self._jobs.finish_stage(job_id, STAGE_SCAN,
                                    detail=f"{len(findings)} finding(s) collected")

        # 3. analyze (AI for the budget, rules for the rest)
        self._analyze(job_id, findings, report)

        # 4. report
        self._jobs.begin_stage(job_id, STAGE_REPORT)
        report.findings = findings
        report.summary = build_summary(findings)
        report.finished_at = utc_now()
        self._store.save(report)
        self._jobs.complete(job_id, report)
        self._log.info(
            "Job %s completed. %d finding(s), report %s",
            job_id, len(report.findings), report.report_id,
        )

    def _analyze(self, job_id: str, findings: List[Finding], report: Report) -> None:
        # Pin the analyzer for this whole stage. provider switches made
        # concurrently apply from the next scan, never mid-scan.
        analyzer = self._analyzer

        if not findings:
            self._jobs.finish_stage(job_id, STAGE_ANALYZE, status="skipped",
                                    detail="No findings to analyze")
            return

        if analyzer.can_analyze():
            self._jobs.begin_stage(job_id, STAGE_ANALYZE)
            budget = min(len(findings), self._settings.max_ai_findings)
            self._jobs.touch(
                job_id, STAGE_ANALYZE,
                f"Explaining 1/{len(findings)}. Starting AI analysis…",
            )
            analyzed = failures = 0
            total = len(findings)
            for index, finding in enumerate(findings):
                if index < budget:
                    try:
                        why, fix = analyzer.explain(finding)
                        finding.why_dangerous = why
                        finding.how_to_fix = fix
                        finding.analyzed = True
                        finding.analysis_source = "mistral"
                        analyzed += 1
                    except SecuraError as exc:
                        self._apply_fallback(finding)
                        failures += 1
                        self._log.warning("AI analysis failed for %s: %s",
                                          finding.finding_id, exc)
                else:
                    self._apply_fallback(finding)
                done = index + 1
                self._jobs.touch(
                    job_id, STAGE_ANALYZE,
                    f"Explaining {done}/{total}: {finding.vulnerability_type[:48]}",
                )
                # Analysis spans 50%→75% of the bar (stage 3 of 4):
                # every completed finding visibly moves it.
                self._jobs.bump_progress(
                    job_id, 50 + int((done / total) * 25))
            templated = total - analyzed
            self._jobs.finish_stage(
                job_id, STAGE_ANALYZE,
                detail=f"{analyzed} by AI · {templated} rule-based",
            )
            if failures:
                report.scanner_notes.append(
                    f"The AI could not explain {failures} findings. "
                    "Knowledge base guidance was used instead."
                )
            if templated > 0 and analyzed > 0:
                report.scanner_notes.append(
                    f"The AI ({analyzer.model}) explained the {analyzed} most "
                    f"severe finding(s); the remaining {templated} use knowledge base "
                    "guidance. Increase VW_MAX_AI_FINDINGS to raise "
                    "the limit."
                )
            return

        # AI layer unavailable or disabled. everything gets rule-based guidance.
        for finding in findings:
            self._apply_fallback(finding)
        if not getattr(self._settings, "enable_ai", True):
            reason = "AI explanations are disabled (VW_ENABLE_AI=0)"
        else:
            reason = (f"AI model '{analyzer.model}' is not ready. Start "
                      "Ollama (ollama serve) for local mode, or configure an "
                      "API provider in AI Setup")
        report.scanner_notes.append(
            f"{reason}. All findings use knowledge base guidance."
        )
        self._jobs.finish_stage(job_id, STAGE_ANALYZE, status="skipped",
                                detail="Knowledge base guidance applied")

    def _apply_fallback(self, finding: Finding) -> None:
        try:
            why, fix = fallback_explanation(finding)
        except Exception:  # the fallback itself must never break a scan
            why, fix = "", ""
            self._log.exception("Rule-based fallback failed for %s", finding.finding_id)
        finding.why_dangerous = why
        finding.how_to_fix = fix
        finding.analysis_source = "template"
