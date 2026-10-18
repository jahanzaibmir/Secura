"""Secura launcher: starts the API, waits until it is healthy, then serves the interface."""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def _env_int(default: int, *names: str) -> int:
    for name in names:
        value = os.getenv(name)
        if value:
            try:
                return int(value)
            except ValueError:
                pass
    return default


API_HOST = os.getenv("SECURA_HOST") or os.getenv("VW_HOST") or "127.0.0.1"
API_PORT = _env_int(8642, "SECURA_PORT", "VW_PORT")
UI_PORT = _env_int(8501, "SECURA_UI_PORT", "VW_UI_PORT", "PORT")


def _wait_for_api(process: subprocess.Popen, timeout: float = 45.0) -> bool:
    url = f"http://127.0.0.1:{API_PORT}/api/health"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return True
        except OSError:
            time.sleep(0.4)
    return False


def _stop(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()


def main() -> int:
    env = dict(os.environ)
    env.setdefault("SECURA_API_URL", f"http://127.0.0.1:{API_PORT}")
    env.setdefault("PYTHONUNBUFFERED", "1")

    api = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "backend.main:create_app", "--factory",
         "--host", API_HOST, "--port", str(API_PORT), "--no-access-log"],
        cwd=ROOT, env=env,
    )
    if not _wait_for_api(api):
        _stop(api)
        print("The Secura API failed to start. See the output above and data/logs/secura.log.", file=sys.stderr)
        return 1

    print(f"\n  Secura interface  http://localhost:{UI_PORT}")
    print(f"  Secura API        http://127.0.0.1:{API_PORT}/docs\n")

    ui = subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run", str(ROOT / "ui" / "app.py"),
         f"--server.port={UI_PORT}"],
        cwd=ROOT, env=env,
    )

    def shutdown(*_):
        _stop(ui)
        _stop(api)
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    try:
        return ui.wait()
    except KeyboardInterrupt:
        return 0
    finally:
        _stop(ui)
        _stop(api)


if __name__ == "__main__":
    sys.exit(main())
