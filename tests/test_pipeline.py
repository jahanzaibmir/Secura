"""Pipeline tests — full flow offline (fake scanner + fake analyzer),
the caps, the fallback wiring, and report export with hostile content."""
from pathlib import Path

from backend.ai.analyzer import OllamaAnalyzer
from backend.api.schemas import Finding, Report, ScanRequest, Severity, TargetType
from backend.config import Settings
from backend.core.jobs import JobManager
from backend.core.pipeline import ScanPipeline
from backend.core.registry import ScannerRegistry
from backend.exceptions import AnalyzerError, ScannerError
from backend.scanners.base import BaseScanner
from backend.storage.report_export import to_html, to_markdown
from backend.storage.report_store import ReportStore


def _finding(severity, name=None):
    return Finding(
        vulnerability_type=name or f"Issue {severity.value}",
        severity=severity, confidence=0.8,
        location="app.py · line 1", evidence="evidence text",
    )


class FakeAnalyzer(OllamaAnalyzer):
    def __init__(self, mode="ok"):
        super().__init__("http://fake:11434", "mistral:7b", timeout=5)
        self.mode = mode
        self.calls = 0

    def can_analyze(self):
        return self.mode != "down"

    def is_available(self):
        return self.mode != "down"

    def explain(self, finding):
        self.calls += 1
        if self.mode == "fail_low" and finding.severity == Severity.LOW:
            raise AnalyzerError("simulated failure")
        return f"AI why: {finding.vulnerability_type}", "AI fix: remediate it"


def _build(tmp_path: Path, findings=None, error=None, analyzer=None, settings=None):
    registry = ScannerRegistry()

    class FakeScanner(BaseScanner):
        target_type = TargetType.LOCAL_PATH    # pipeline is target-agnostic;
        name = "fake"                          # a valid folder target is enough

        def scan(self):
            if error is not None:
                raise error
            return [f.model_copy(deep=True) for f in (findings or [])]

    registry.register(TargetType.LOCAL_PATH)(FakeScanner)
    jobs = JobManager()
    store = ReportStore(tmp_path / "reports")
    pipeline = ScanPipeline(
        registry, jobs, analyzer or FakeAnalyzer(), store,
        settings or Settings(max_findings_per_scan=10, max_ai_findings=3),
    )
    return pipeline, jobs, store


def _run(pipeline, jobs, tmp_path):
    # A real, NON-empty folder — the validator rejects empty ones
    # (correctly — so the test target must contain a file).
    target_dir = tmp_path / "project"
    target_dir.mkdir(exist_ok=True)
    (target_dir / "placeholder.txt").write_text("placeholder", encoding="utf-8")
    job = jobs.create(ScanRequest(target_type=TargetType.LOCAL_PATH,
                                  target=str(target_dir)))
    pipeline.run_job(job.job_id)
    return jobs.get_view(job.job_id)


def test_pipeline_happy_path_sorted_and_analyzed(tmp_path):
    findings = [_finding(Severity.LOW), _finding(Severity.CRITICAL),
                _finding(Severity.MEDIUM)]
    pipeline, jobs, _ = _build(tmp_path, findings=findings)
    view = _run(pipeline, jobs, tmp_path)

    assert view.status.value == "completed"
    assert view.progress == 100
    report = view.report
    assert [f.severity for f in report.findings] == [
        Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]
    assert all(f.analyzed and f.analysis_source == "mistral" for f in report.findings)
    assert report.summary.critical == 1 and report.summary.total == 3
    assert (tmp_path / "reports" / f"{report.report_id}.json").is_file()


def test_pipeline_ai_budget_uses_rule_based_for_rest(tmp_path):
    findings = ([_finding(Severity.CRITICAL)] * 2 + [_finding(Severity.HIGH)] * 2
                + [_finding(Severity.MEDIUM)] * 2)
    analyzer = FakeAnalyzer()
    pipeline, jobs, _ = _build(tmp_path, findings=findings, analyzer=analyzer)
    view = _run(pipeline, jobs, tmp_path)
    report = view.report

    assert analyzer.calls == 3
    ai = [f for f in report.findings if f.analysis_source == "mistral"]
    template = [f for f in report.findings if f.analysis_source == "template"]
    assert len(ai) == 3 and len(template) == 3
    assert all(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in ai)
    assert any("knowledge base" in note for note in report.scanner_notes)


def test_pipeline_analyzer_down_uses_templates(tmp_path):
    pipeline, jobs, _ = _build(tmp_path, findings=[_finding(Severity.HIGH)],
                               analyzer=FakeAnalyzer(mode="down"))
    view = _run(pipeline, jobs, tmp_path)
    report = view.report

    assert view.status.value == "completed"
    assert report.findings[0].analysis_source == "template"
    assert report.findings[0].why_dangerous
    assert any("not ready" in note or "Ollama" in note
               for note in report.scanner_notes)


def test_pipeline_ai_failure_falls_back_per_finding(tmp_path):
    pipeline, jobs, _ = _build(tmp_path,
                               findings=[_finding(Severity.LOW), _finding(Severity.HIGH)],
                               analyzer=FakeAnalyzer(mode="fail_low"))
    view = _run(pipeline, jobs, tmp_path)
    report = view.report

    by_severity = {f.severity: f for f in report.findings}
    assert by_severity[Severity.HIGH].analysis_source == "mistral"
    assert by_severity[Severity.LOW].analysis_source == "template"
    assert any("could not explain" in note for note in report.scanner_notes)


def test_pipeline_scanner_error_fails_job(tmp_path):
    pipeline, jobs, _ = _build(tmp_path, error=ScannerError("scanner exploded"))
    view = _run(pipeline, jobs, tmp_path)
    assert view.status.value == "failed"
    assert "scanner exploded" in (view.error or "")


def test_pipeline_display_cap_keeps_most_severe(tmp_path):
    findings = [_finding(Severity.LOW)] * 8 + [_finding(Severity.CRITICAL)] * 8
    pipeline, jobs, _ = _build(
        tmp_path, findings=findings,
        settings=Settings(max_findings_per_scan=10, max_ai_findings=3))
    view = _run(pipeline, jobs, tmp_path)
    report = view.report

    assert len(report.findings) == 10
    assert sum(1 for f in report.findings if f.severity == Severity.CRITICAL) == 8
    assert any("most severe" in note for note in report.scanner_notes)


def test_pipeline_validation_error_fails_cleanly(tmp_path):
    pipeline, jobs, _ = _build(tmp_path, findings=[])
    job = jobs.create(ScanRequest(target_type=TargetType.LOCAL_PATH,
                                  target="/definitely/not/a/real/path"))
    pipeline.run_job(job.job_id)
    view = jobs.get_view(job.job_id)
    assert view.status.value == "failed"
    assert "does not exist" in (view.error or "")


def test_export_markdown_and_html(tmp_path):
    pipeline, jobs, _ = _build(tmp_path, findings=[_finding(Severity.CRITICAL,
                                                            name="SQL Injection")])
    view = _run(pipeline, jobs, tmp_path)
    report = view.report

    markdown = to_markdown(report)
    assert "SQL Injection" in markdown
    assert "Critical" in markdown
    assert "evidence text" in markdown

    html_out = to_html(report)
    assert html_out.startswith("<!doctype html>")
    assert "SQL Injection" in html_out
    assert "AI why" in html_out


def test_export_escapes_hostile_content():
    report = Report(
        target="<script>alert(1)</script>",
        target_type=TargetType.LOCAL_PATH,
        findings=[Finding(
            vulnerability_type="XSS <b>", severity=Severity.HIGH,
            evidence="<img src=x onerror=alert(1)>",
            why_dangerous="<i>bad</i>", how_to_fix="<i>fix</i>")],
    )
    html_out = to_html(report)
    assert "<script>alert" not in html_out
    assert "&lt;script&gt;" in html_out
    assert "<img src=x" not in html_out
    assert "&lt;img src=x" in html_out
