"""Upload endpoint tests — path sanitization (pure) + end-to-end (optional)."""
import json
import shutil
import time

import pytest

from backend.api.routes.upload import sanitize_rel_path


def test_sanitize_accepts_normal_paths():
    assert sanitize_rel_path("project/src/app.py") == "project/src/app.py"
    assert sanitize_rel_path("./a.py") == "a.py"


def test_sanitize_handles_windows_separators():
    assert sanitize_rel_path("project\\src\\app.py") == "project/src/app.py"


def test_sanitize_blocks_traversal():
    assert sanitize_rel_path("../../etc/passwd.py") is None
    assert sanitize_rel_path("a/../../b.py") is None


def test_sanitize_skips_junk_and_non_source():
    assert sanitize_rel_path("proj/node_modules/x.py") is None
    assert sanitize_rel_path("proj/.git/config.py") is None
    assert sanitize_rel_path("proj/logo.png") is None
    assert sanitize_rel_path("proj/app.js") == "proj/app.js"
    assert sanitize_rel_path("") is None


def test_upload_end_to_end():
    pytest.importorskip("httpx")
    pytest.importorskip("multipart")  # python-multipart
    from fastapi.testclient import TestClient
    from backend.core import context
    from backend.main import app

    code = (b"import subprocess\n\n"
            b"def run(cmd):\n"
            b"    subprocess.call(cmd, shell=True)\n")
    files = [("files", ("app.py", code, "text/x-python"))]
    data = {"paths": json.dumps(["myproject/app.py"])}

    with TestClient(app) as http:
        response = http.post("/api/scan/upload", files=files, data=data)
    assert response.status_code == 202, response.text
    job_id = response.json()["job_id"]

    view = None
    for _ in range(120):                      # bandit runs as a subprocess
        view = context.jobs.get_view(job_id)
        if view and view.status.value in ("completed", "failed"):
            break
        time.sleep(0.5)
    assert view is not None and view.status.value == "completed", (
        view.error if view else "job never returned")
    assert view.report.summary.total >= 1
    target_dir = view.report.target
    shutil.rmtree(target_dir, ignore_errors=True)   # test's own cleanup
