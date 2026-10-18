"""Pipeline behaviour with fake engines and analyzers, plus one real end-to-end run."""
import threading
from contextlib import contextmanager
from pathlib import Path

from backend.ai.analyzers.base import BaseAnalyzer, Generation, Readiness
from backend.core.jobs import JobManager
from backend.core.pipeline import ScanPipeline, fingerprint
from backend.engines import default_engines
from backend.engines.base import Engine, EngineResult
from backend.exceptions import AnalyzerError, EngineError, SourceError
from backend.schemas import ExplanationSource, Finding, JobStatus, ScanRequest, Severity, TargetType
from backend.sources import Source, SourceRegistry, build_source_registry
from backend.storage.report_store import ReportStore


class StaticEngine(Engine):
    name = "static"
    label = "Static"
    description = "returns canned findings"

    def __init__(self, findings: list[Finding] = (), error: Exception = None, name: str = "static"):
        self._findings = list(findings)
        self._error = error
        self.name = name

    def applies(self, inventory):
        return True

    def run(self, context):
        if self._error is not None:
            raise self._error
        return EngineResult(findings=[f.model_copy(deep=True) for f in self._findings], detail="done")


class BlockingEngine(Engine):
    name = "blocking"
    label = "Blocking"
    description = "waits for cancellation"

    def __init__(self):
        self.started = threading.Event()

    def applies(self, inventory):
        return True

    def run(self, context):
        self.started.set()
        while not context.token.wait(0.05):
            pass
        context.token.raise_if_cancelled()
        return EngineResult()


class FakeAnalyzer(BaseAnalyzer):
    provider = "fake"
    max_concurrency = 3

    def __init__(self, ready=True, fail_titles=()):
        super().__init__(model="fake-model", retry_backoff=0)
        self._ready = ready
        self._fail = set(fail_titles)
        self.explained: list[str] = []
        self._lock = threading.Lock()

    @property
    def provider_label(self):
        return "Fake"

    def _probe_readiness(self):
        return Readiness(self._ready, "ready" if self._ready else "Fake provider offline.")

    def _complete(self, prompt, system, max_tokens):
        return Generation("unused")

    def explain(self, finding):
        with self._lock:
            self.explained.append(finding.title)
        if finding.title in self._fail:
            raise AnalyzerError("simulated failure")
        return f"AI why: {finding.title}", "AI fix"


class FailingSource(Source):
    target_types = (TargetType.LOCAL_PATH, TargetType.UPLOAD)
    label = "Failing"

    @contextmanager
    def open(self, target, context):
        raise SourceError("clone exploded")
        yield


def _finding(severity, title=None, line=1, engine="static"):
    return Finding(engine=engine, rule_id=f"R-{severity.value}", title=title or f"Issue {severity.value}",
                   severity=severity, confidence=0.8, file_path="app.py", line=line, snippet=f"{line}  x")


def _pipeline(settings, engines, analyzer=None, sources=None):
    jobs = JobManager()
    store = ReportStore(settings.reports_dir)
    analyzer = analyzer or FakeAnalyzer(ready=False)
    pipeline = ScanPipeline(settings, sources or build_source_registry(), engines, jobs, lambda: analyzer, store)
    return pipeline, jobs, store


def _run(pipeline, jobs, root: Path, target_type=TargetType.LOCAL_PATH, label=None, cleanup=None):
    job = jobs.create(ScanRequest(target_type=target_type, target=str(root)), label=label, cleanup_path=cleanup)
    pipeline.run_job(job.job_id)
    return jobs.view(job.job_id)


def test_findings_are_ranked_deduplicated_and_explained(settings, make_tree):
    root = make_tree({"app.py": "x = 1\n"})
    findings = [_finding(Severity.LOW), _finding(Severity.CRITICAL, line=2),
                _finding(Severity.MEDIUM, line=3), _finding(Severity.MEDIUM, line=3)]
    analyzer = FakeAnalyzer(ready=True)
    pipeline, jobs, store = _pipeline(settings, [StaticEngine(findings)], analyzer)
    view = _run(pipeline, jobs, root)

    assert view.status == JobStatus.COMPLETED and view.progress == 100
    report = store.load(view.report_id)
    assert [f.severity for f in report.findings] == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]
    assert all(f.fingerprint for f in report.findings)
    assert all(f.explanation_source == ExplanationSource.AI for f in report.findings)
    assert report.analysis.explained_by_ai == 3
    assert report.risk.grade == "F"
    assert report.engines[0].status == "completed"
    assert report.stats.files_scanned == 1


def test_ai_budget_targets_the_most_severe_non_info_findings(settings, make_tree):
    root = make_tree({"app.py": "x = 1\n"})
    findings = [_finding(Severity.INFO, line=1), _finding(Severity.HIGH, "high", line=2),
                _finding(Severity.LOW, "low", line=3), _finding(Severity.CRITICAL, "critical", line=4)]
    analyzer = FakeAnalyzer(ready=True, fail_titles={"high"})
    pipeline, jobs, store = _pipeline(settings.with_overrides(ai_max_findings=2), [StaticEngine(findings)], analyzer)
    report = store.load(_run(pipeline, jobs, root).report_id)

    assert sorted(analyzer.explained) == ["critical", "high"]
    sources = {f.title: f.explanation_source for f in report.findings}
    assert sources["critical"] == ExplanationSource.AI
    assert sources["high"] == ExplanationSource.KNOWLEDGE_BASE
    assert sources["low"] == ExplanationSource.KNOWLEDGE_BASE
    assert any("could not explain 1" in note for note in report.notes)


def test_unavailable_ai_falls_back_to_the_knowledge_base(settings, make_tree):
    root = make_tree({"app.py": "x = 1\n"})
    pipeline, jobs, store = _pipeline(settings, [StaticEngine([_finding(Severity.HIGH)])], FakeAnalyzer(ready=False))
    report = store.load(_run(pipeline, jobs, root).report_id)
    assert report.findings[0].explanation_source == ExplanationSource.KNOWLEDGE_BASE
    assert report.findings[0].why_dangerous
    assert any("Fake provider offline." in note for note in report.notes)


def test_engine_failures_are_isolated(settings, make_tree):
    root = make_tree({"app.py": "x = 1\n"})
    engines = [
        StaticEngine(error=EngineError("tool missing"), name="broken"),
        StaticEngine(error=RuntimeError("bug"), name="crashing"),
        StaticEngine([_finding(Severity.MEDIUM)], name="healthy"),
    ]
    pipeline, jobs, store = _pipeline(settings, engines)
    view = _run(pipeline, jobs, root)
    assert view.status == JobStatus.COMPLETED
    report = store.load(view.report_id)
    statuses = {run.name: run.status for run in report.engines}
    assert statuses == {"broken": "failed", "crashing": "failed", "healthy": "completed"}
    assert len(report.findings) == 1
    assert any("tool missing" in note for note in report.notes)


def test_source_and_validation_errors_fail_the_job(settings, make_tree):
    root = make_tree({"app.py": "x = 1\n"})
    sources = SourceRegistry()
    sources.register(FailingSource())
    pipeline, jobs, _ = _pipeline(settings, [StaticEngine()], sources=sources)
    view = _run(pipeline, jobs, root)
    assert view.status == JobStatus.FAILED and "clone exploded" in view.error

    pipeline, jobs, _ = _pipeline(settings, [StaticEngine()])
    view = _run(pipeline, jobs, root.parent / "does-not-exist")
    assert view.status == JobStatus.FAILED and "does not exist" in view.error


def test_cancellation_stops_a_running_scan_and_cleans_up(settings, make_tree):
    root = make_tree({"app.py": "x = 1\n"}, name="upload_dir")
    engine = BlockingEngine()
    pipeline, jobs, _ = _pipeline(settings, [engine])
    job = jobs.create(ScanRequest(target_type=TargetType.UPLOAD, target=str(root)), label="upload",
                      cleanup_path=root)
    worker = threading.Thread(target=pipeline.run_job, args=(job.job_id,))
    worker.start()
    assert engine.started.wait(5)
    jobs.cancel(job.job_id)
    worker.join(5)
    assert jobs.view(job.job_id).status == JobStatus.CANCELLED
    assert not root.exists()


def test_finding_cap_keeps_the_most_severe(settings, make_tree):
    root = make_tree({"app.py": "x = 1\n"})
    findings = [_finding(Severity.LOW, line=i) for i in range(8)] + \
               [_finding(Severity.CRITICAL, line=100 + i) for i in range(4)]
    pipeline, jobs, store = _pipeline(settings.with_overrides(max_findings=5), [StaticEngine(findings)])
    report = store.load(_run(pipeline, jobs, root).report_id)
    assert len(report.findings) == 5
    assert sum(f.severity == Severity.CRITICAL for f in report.findings) == 4
    assert any("most severe are kept" in note for note in report.notes)


def test_upload_reports_use_the_friendly_label(settings, make_tree):
    root = make_tree({"app.py": "x = 1\n"}, name="upload_x")
    pipeline, jobs, store = _pipeline(settings, [StaticEngine()])
    view = _run(pipeline, jobs, root, target_type=TargetType.UPLOAD, label="my-project", cleanup=root)
    assert store.load(view.report_id).target == "my-project"
    assert not root.exists()


def test_fingerprint_ignores_line_number_prefixes_but_not_location():
    a = _finding(Severity.LOW, line=3)
    b = a.model_copy(update={"snippet": "3    x"})
    c = a.model_copy(update={"line": 4})
    assert fingerprint(a) == fingerprint(b)
    assert fingerprint(a) != fingerprint(c)


def test_stored_reports_never_contain_raw_secrets(settings, make_tree):
    token = "ghp" + "_Z8xk2LmQ9pWv4RtY7uNc3HbJ6sDf1GaE5oKi"
    root = make_tree({
        "web/app.js": f"el.innerHTML = location.hash;\nconst token = '{token}';\n",
        "app.py": "password = 'MYSUPERSECRETKEY'\n",
    })
    pipeline, jobs, store = _pipeline(settings, default_engines())
    view = _run(pipeline, jobs, root)
    stored = (settings.reports_dir / f"{view.report_id}.json").read_text()
    assert token not in stored and "MYSUPERSECRETKEY" not in stored
    assert len(store.load(view.report_id).findings) >= 3


def test_real_engines_end_to_end(settings, make_tree):
    root = make_tree({
        "src/app.py": "import subprocess\n\ndef run(cmd):\n    subprocess.call(cmd, shell=True)\n",
        "web/app.js": "el.innerHTML = location.hash;\n",
        "config.js": "const token = 'ghp" + "_Z8xk2LmQ9pWv4RtY7uNc3HbJ6sDf1GaE5oKi';\n",
        "Dockerfile": "FROM python\nCMD python app.py\n",
        "requirements.txt": "flask==0.12.2\n",
    })
    pipeline, jobs, store = _pipeline(settings, default_engines())
    view = _run(pipeline, jobs, root)
    assert view.status == JobStatus.COMPLETED, view.error
    report = store.load(view.report_id)
    engines = {f.engine for f in report.findings}
    assert {"bandit", "javascript", "secrets", "docker"} <= engines
    statuses = {run.name: run.status for run in report.engines}
    assert statuses["dependencies"] == "skipped"
    assert report.risk.grade == "F"
