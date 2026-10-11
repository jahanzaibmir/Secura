"""Secura launcher — starts the FastAPI backend, then the Streamlit UI."""
import atexit
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


BACKEND_PORT = _env_int("VW_PORT", 8642)
UI_PORT = _env_int("VW_UI_PORT", 8501)


def _wait_for_backend(process: subprocess.Popen) -> bool:
    url = f"http://127.0.0.1:{BACKEND_PORT}/api/health"
    for _ in range(80):
        if process.poll() is not None:
            return False
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return True
        except Exception:
            time.sleep(0.5)
    return False


def main() -> None:
    backend = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "backend.main:app",
         "--host", "127.0.0.1", "--port", str(BACKEND_PORT)],
        cwd=ROOT,
    )
    atexit.register(lambda: backend.terminate())

    if not _wait_for_backend(backend):
        backend.terminate()
        print("Backend failed to start — check the output above and logs/secura.log",
              file=sys.stderr)
        sys.exit(1)

    print(f"Secura UI  →  http://localhost:{UI_PORT}")
    print(f"Secura API →  http://127.0.0.1:{BACKEND_PORT}/docs")
    try:
        subprocess.run(
            [sys.executable, "-m", "streamlit", "run", "ui/secura_app.py",
             f"--server.port={UI_PORT}", "--browser.gatherUsageStats=false"],
            cwd=ROOT,
        )
    finally:
        backend.terminate()
        try:
            backend.wait(timeout=5)
        except subprocess.TimeoutExpired:
            backend.kill()


if __name__ == "__main__":
    main()
