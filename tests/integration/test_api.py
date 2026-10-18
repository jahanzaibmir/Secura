"""HTTP API behaviour through FastAPI's test client."""
import io
import json
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

from backend.main import create_app
from backend.schemas import ScanRequest, TargetType

VULNERABLE_PY = b"import subprocess\n\ndef run(cmd):\n    subprocess.call(cmd, shell=True)\n"


@pytest.fixture
def client(settings):
    with TestClient(create_app(settings)) as http:
        yield http


def _wait(client, job_id, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        view = client.get(f"/api/scans/{job_id}").json()
        if view["status"] in ("completed", "failed", "cancelled"):
            return view
        time.sleep(0.2)
    raise AssertionError("scan did not finish")


def test_health_reports_capabilities(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert {e["name"] for e in body["engines"]} == {"bandit", "javascript", "secrets", "dependencies", "docker"}
    assert body["ai"]["enabled"] is False and body["ai"]["ready"] is False
    assert body["allow_local_paths"] is False
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Request-ID"]


def test_invalid_repository_is_rejected_synchronously(client):
    response = client.post("/api/scans", json={"target_type": "github_repo", "target": "https://gitlab.com/a/b"})
    assert response.status_code == 400
    assert response.json()["error"] == "ValidationError"
    assert client.post("/api/scans", json={"target_type": "nope", "target": "x"}).status_code == 422


def test_server_folders_are_forbidden_by_default(client, make_tree):
    root = make_tree({"app.py": "x = 1\n"})
    response = client.post("/api/scans", json={"target_type": "local_path", "target": str(root)})
    assert response.status_code == 403
    assert "SECURA_ALLOW_LOCAL_PATHS" in response.json()["detail"]


def test_server_folders_can_be_enabled(settings, make_tree):
    root = make_tree({"app.py": VULNERABLE_PY.decode()})
    with TestClient(create_app(settings.with_overrides(allow_local_paths=True))) as http:
        accepted = http.post("/api/scans", json={"target_type": "local_path", "target": str(root)})
        assert accepted.status_code == 202
        view = _wait(http, accepted.json()["job_id"])
    assert view["status"] == "completed"
    assert view["summary"]["critical"] >= 1


def test_file_upload_scan_report_lifecycle(client):
    files = [("files", ("app.py", VULNERABLE_PY, "text/x-python")),
             ("files", ("logo.png", b"\x89PNG", "image/png"))]
    data = {"paths": json.dumps(["demo/app.py", "demo/logo.png"])}
    accepted = client.post("/api/scans/upload", files=files, data=data)
    assert accepted.status_code == 202, accepted.text
    assert "1 file(s) (1 skipped)" in accepted.json()["message"]

    view = _wait(client, accepted.json()["job_id"])
    assert view["status"] == "completed" and view["label"] == "demo"
    report_id = view["report_id"]

    report = client.get(f"/api/reports/{report_id}").json()
    assert report["target"] == "demo" and report["target_type"] == "upload"
    assert any(f["rule_id"] == "B602" for f in report["findings"])
    assert [m["report_id"] for m in client.get("/api/reports").json()] == [report_id]

    for fmt, media in (("json", "application/json"), ("md", "text/markdown"),
                       ("html", "text/html"), ("sarif", "application/sarif+json")):
        exported = client.get(f"/api/reports/{report_id}/export", params={"format": fmt})
        assert exported.status_code == 200 and exported.headers["content-type"].startswith(media)
        assert f"secura-{report_id}.{fmt}" in exported.headers["content-disposition"]
    view_page = client.get(f"/api/reports/{report_id}/view")
    assert "default-src 'none'" in view_page.headers["content-security-policy"]

    assert client.delete(f"/api/reports/{report_id}").status_code == 204
    missing = client.get(f"/api/reports/{report_id}")
    assert missing.status_code == 404 and missing.json()["error"] == "ReportNotFound"


def test_zip_upload(client):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("proj-main/src/app.py", VULNERABLE_PY)
        archive.writestr("proj-main/web/app.js", "el.innerHTML = location.hash;\n")
    accepted = client.post("/api/scans/upload",
                           files={"archive": ("proj.zip", buffer.getvalue(), "application/zip")})
    assert accepted.status_code == 202, accepted.text
    view = _wait(client, accepted.json()["job_id"])
    assert view["status"] == "completed" and view["label"] == "proj"
    assert view["summary"]["total"] >= 2


def test_uploads_beyond_the_default_multipart_limit(client):
    count = 1100
    files = [("files", (f"f{i}.py", b"x = 1\n", "text/x-python")) for i in range(count)]
    paths = json.dumps([f"big/pkg/f{i}.py" for i in range(count)])
    accepted = client.post("/api/scans/upload", files=files, data={"paths": paths})
    assert accepted.status_code == 202, accepted.text
    assert f"Received {count} file(s)" in accepted.json()["message"]


def test_upload_validation_errors(client):
    assert client.post("/api/scans/upload", data={"name": "x"}).status_code == 400
    nothing = client.post("/api/scans/upload", files=[("files", ("a.png", b"x", "image/png"))])
    assert nothing.status_code == 400 and "No scannable files" in nothing.json()["detail"]
    mismatch = client.post("/api/scans/upload", files=[("files", ("a.py", b"x", "text/plain"))],
                           data={"paths": json.dumps(["a.py", "b.py"])})
    assert mismatch.status_code == 400


def test_unknown_jobs_and_cancellation(client):
    missing = client.get("/api/scans/job_missing")
    assert missing.status_code == 404 and missing.json()["error"] == "JobNotFound"
    assert client.post("/api/scans/job_missing/cancel").status_code == 404


def test_queue_limit(settings):
    app = create_app(settings.with_overrides(max_queued_scans=1))
    container = app.state.container
    container.jobs.create(ScanRequest(target_type=TargetType.GITHUB_REPO, target="https://github.com/a/b"))
    with TestClient(app) as http:
        response = http.post("/api/scans", json={"target_type": "github_repo", "target": "a/b"})
    assert response.status_code == 429


def test_ai_settings_endpoints(client):
    status = client.get("/api/settings/ai").json()
    assert status["provider"] == "ollama" and status["enabled"] is False
    assert client.put("/api/settings/ai", json={"provider": "bogus"}).status_code == 422
    short = client.post("/api/settings/ai/key", json={"api_key": "12345678901"})
    assert short.status_code == 400 and "too short" in short.json()["detail"]
