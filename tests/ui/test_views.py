"""Headless rendering tests for every page, backed by a fake API client."""
from datetime import timedelta

import pytest
from streamlit.testing.v1 import AppTest

from backend.schemas import (
    AISettingsResponse,
    AIStatus,
    EngineInfo,
    ExplanationSource,
    Finding,
    HealthResponse,
    JobStatus,
    JobView,
    Report,
    ReportMeta,
    ScanAccepted,
    Severity,
    StageInfo,
    StageStatus,
    TargetType,
    build_summary,
    utc_now,
)
from ui import services
from ui.client import ApiError


def _harness():
    import streamlit as st

    from ui import navigation
    from ui.theme import apply_theme
    from ui.views import history, report, scan, settings

    apply_theme()
    target = st.query_params.get("page", "scan")
    views = {"scan": scan.render, "reports": history.render, "report": report.render, "settings": settings.render}
    pages = {name: st.Page(view, title=name, url_path=name, default=name == target) for name, view in views.items()}
    for name, page in pages.items():
        navigation.register(name, page)
    st.navigation(list(pages.values()), position="hidden").run()


def _report() -> Report:
    findings = [
        Finding(engine="bandit", rule_id="B602", title="Shell injection (subprocess with shell=True)",
                severity=Severity.CRITICAL, confidence=0.9, file_path="src/app.py", line=7,
                snippet="7  subprocess.call(cmd, shell=True)", cwe="CWE-78",
                why_dangerous="Attackers run commands.",
                how_to_fix="Pass a list:\n\nsubprocess.run(['ls', path], check=True)",
                explanation_source=ExplanationSource.AI, explanation_model="mistral:7b"),
        Finding(engine="secrets", rule_id="SEC003", title="GitHub token", severity=Severity.HIGH,
                confidence=0.95, file_path="config.js", line=2, snippet="2  const t = 'ghp_••••'",
                explanation_source=ExplanationSource.KNOWLEDGE_BASE),
        Finding(engine="docker", rule_id="DOCKER002", title="Base image is not pinned", severity=Severity.LOW,
                confidence=0.8, file_path="Dockerfile", line=1),
    ]
    started = utc_now() - timedelta(seconds=42)
    return Report(target="https://github.com/acme/shop", target_type=TargetType.GITHUB_REPO,
                  started_at=started, finished_at=utc_now(), findings=findings,
                  summary=build_summary(findings), notes=["Example note."])


class FakeClient:
    def __init__(self, report: Report):
        self.report = report
        self.started = []
        self.connected = []
        self.job_status = JobStatus.RUNNING

    def health(self):
        return HealthResponse(
            status="ok", version="2.0.0",
            ai=AIStatus(enabled=True, ready=True, provider="ollama", provider_label="Ollama (local)",
                        model="mistral:7b", message="Local mode."),
            engines=[EngineInfo(name="bandit", label="Python SAST", description="Bandit"),
                     EngineInfo(name="dependencies", label="Dependencies", description="OSV",
                                available=False, detail="Disabled")],
        )

    def list_scans(self):
        return [self._job("job_other", JobStatus.RUNNING)]

    def list_reports(self, limit=None):
        return [ReportMeta.from_report(self.report)]

    def get_report(self, report_id):
        if report_id != self.report.report_id:
            raise ApiError(404, "No report found")
        return self.report

    def get_scan(self, job_id):
        return self._job(job_id, self.job_status)

    def start_scan(self, target, target_type="github_repo"):
        if "gitlab" in target:
            raise ApiError(400, "Expected a public GitHub repository")
        self.started.append(target)
        return ScanAccepted(job_id="job_new", status=JobStatus.QUEUED, message="queued")

    def cancel_scan(self, job_id):
        return self._job(job_id, JobStatus.CANCELLED)

    def ai_settings(self):
        return AISettingsResponse(provider="ollama", provider_label="Ollama (local)", model="mistral:7b",
                                  ready=True, message="Local mode.", local_models=["mistral:7b", "llama3:8b"])

    def connect_key(self, key):
        self.connected.append(key)
        return self.ai_settings()

    def update_ai(self, *args):
        return self.ai_settings()

    def export_report(self, report_id, fmt):
        return b"{}"

    def delete_report(self, report_id):
        pass

    def _job(self, job_id, status):
        stages = [StageInfo(key="validate", label="Validate target", status=StageStatus.DONE, detail="ok"),
                  StageInfo(key="scan", label="Run security engines", status=StageStatus.RUNNING, detail="Bandit")]
        return JobView(job_id=job_id, label="acme/shop", target="https://github.com/acme/shop",
                       target_type=TargetType.GITHUB_REPO, status=status, progress=40, stages=stages,
                       created_at=utc_now(), report_id=self.report.report_id if status == JobStatus.COMPLETED else None,
                       summary=self.report.summary if status == JobStatus.COMPLETED else None,
                       risk=self.report.risk if status == JobStatus.COMPLETED else None)


@pytest.fixture
def fake(monkeypatch):
    client = FakeClient(_report())
    monkeypatch.setattr(services, "client", lambda: client)
    monkeypatch.setattr(services, "health", lambda: client.health())
    monkeypatch.setattr(services, "report", lambda report_id: client.get_report(report_id))
    monkeypatch.setattr(services, "export", lambda report_id, fmt: client.export_report(report_id, fmt))
    return client


def _app(page="scan", **query):
    app = AppTest.from_function(_harness, default_timeout=20)
    app.query_params["page"] = page
    for key, value in query.items():
        app.query_params[key] = value
    return app.run()


def _html(app) -> str:
    parts = []
    for element in app.get("html"):
        value = getattr(element, "value", None)
        parts.append(value if isinstance(value, str) else element.proto.body)
    return "\n".join(parts)


def test_scan_page_renders_capabilities_and_recent_activity(fake):
    app = _app("scan")
    assert not app.exception
    html = _html(app)
    assert "Find and fix security issues" in html
    assert "Python SAST" in html and "Ollama (local) · mistral:7b" in html
    assert "acme/shop" in html


def test_scan_form_reports_errors_and_starts_jobs(fake):
    app = _app("scan")
    app.text_input[0].input("https://gitlab.com/a/b")
    app.button[0].click().run()
    assert not app.exception
    assert any("Expected a public GitHub repository" in e.value for e in app.error)

    app.text_input[0].input("acme/shop")
    app.button[0].click().run()
    assert fake.started == ["acme/shop"]
    assert app.session_state["scan.active_job"] == "job_new"
    assert "Current scan" in _html(app)


def test_completed_scan_offers_the_report(fake):
    fake.job_status = JobStatus.COMPLETED
    app = AppTest.from_function(_harness, default_timeout=20)
    app.session_state["scan.active_job"] = "job_done"
    app.run()
    assert not app.exception
    assert "Scan complete" in _html(app)
    assert any(button.label == "Open report" for button in app.button)


def test_report_page_renders_and_filters(fake):
    report_id = fake.report.report_id
    app = _app("report", id=report_id)
    assert not app.exception
    html = _html(app)
    assert "acme/shop" in html
    assert html.count("sc-finding sev-") == 3
    assert "<pre class='sc-code'>subprocess.run([&#x27;ls&#x27;, path], check=True)</pre>" in html

    app.pills[0].set_value([Severity.CRITICAL]).run()
    assert _html(app).count("sc-finding sev-") == 1

    app.pills[0].set_value([Severity.CRITICAL, Severity.HIGH, Severity.LOW]).run()
    app.text_input(key=f"report.q.{report_id}").input("docker").run()
    html = _html(app)
    assert html.count("sc-finding sev-") == 1 and "Base image is not pinned" in html


def test_missing_report_shows_an_empty_state(fake):
    app = _app("report", id="rpt_000000000000")
    assert not app.exception
    assert "Report not found" in _html(app)


def test_reports_page_lists_and_searches(fake):
    app = _app("reports")
    assert not app.exception
    assert "acme/shop" in _html(app)
    app.text_input(key="history.q").input("nothing-matches").run()
    assert "Nothing matches this search" in _html(app)


def test_settings_page(fake):
    app = _app("settings")
    assert not app.exception
    html = _html(app)
    assert "Ollama (local)" in html and "Python SAST" in html and "Disabled" in html
    assert app.selectbox(key="settings.local.model").value == "mistral:7b"


def test_backend_outage_is_explained(monkeypatch):
    def down():
        raise ApiError(0, "The Secura backend is not reachable.")

    class DownClient:
        def __getattr__(self, name):
            return lambda *a, **k: down()

    monkeypatch.setattr(services, "client", lambda: DownClient())
    monkeypatch.setattr(services, "health", lambda: None)
    for page in ("scan", "reports", "settings"):
        app = _app(page)
        assert not app.exception
        assert any("not reachable" in error.value for error in app.error)
