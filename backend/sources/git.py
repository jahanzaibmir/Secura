"""Shallow, non-interactive, cancellable ``git clone``.

The clone never prompts for credentials, never materialises symlinks (a hostile
repository could otherwise point a file at secrets on the host), is bounded by a
hard timeout, reports live progress parsed from git's own output, and maps raw
git errors to plain English.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
from collections.abc import Callable
from pathlib import Path

from backend.core.cancellation import CancelToken
from backend.exceptions import ScanCancelled, SourceError

_PHASES = (
    (re.compile(r"Counting objects:\s+(\d+)%"), 0.0, 0.05),
    (re.compile(r"Compressing objects:\s+(\d+)%"), 0.05, 0.10),
    (re.compile(r"Receiving objects:\s+(\d+)%"), 0.10, 0.80),
    (re.compile(r"Resolving deltas:\s+(\d+)%"), 0.80, 0.95),
    (re.compile(r"Updating files:\s+(\d+)%"), 0.95, 1.0),
)

_GIT_CONFIG = (
    "core.symlinks=false",
    "core.hooksPath=/dev/null",
    "protocol.file.allow=never",
    "protocol.ext.allow=never",
    "credential.helper=",
)


def git_available() -> bool:
    return shutil.which("git") is not None


def _git_env() -> dict:
    env = dict(os.environ)
    env.update({
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "true",
        "SSH_ASKPASS": "true",
        "GCM_INTERACTIVE": "never",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "LC_ALL": "C",
    })
    return env


def _parse_progress(line: str) -> tuple | None:
    for pattern, start, end in _PHASES:
        match = pattern.search(line)
        if match:
            fraction = start + (end - start) * int(match.group(1)) / 100
            label = line.split(":", 1)[0].strip()
            return label, fraction
    return None


def friendly_git_error(stderr: str) -> str:
    lowered = stderr.lower()
    if "terminal prompts disabled" in lowered or "could not read username" in lowered:
        return ("GitHub asked for authentication. The repository is private, does not "
                "exist, or the rate limit was hit. Secura clones public repositories only.")
    if "repository not found" in lowered or "not found" in lowered:
        return "Repository not found. Check the URL; private repositories are not supported."
    if "could not resolve host" in lowered or "unable to access" in lowered:
        return "Cannot reach GitHub. Check the network connection, DNS, or firewall."
    if "ssl" in lowered or "tls" in lowered or "certificate" in lowered:
        return "A TLS error occurred while contacting GitHub."
    if "no space left" in lowered:
        return "The server ran out of disk space while cloning."
    lines = [line for line in stderr.strip().splitlines() if line.strip()]
    tail = lines[-1][:200] if lines else "unknown git error"
    return f"git clone failed: {tail}"


def clone_repository(
    url: str,
    destination: Path,
    timeout: int,
    token: CancelToken | None = None,
    progress: Callable[[str, float], None] | None = None,
) -> Path:
    """Clones ``url`` (depth 1) into the existing, empty ``destination``."""
    if not git_available():
        raise SourceError("The git executable is not installed on the server.")

    command: list[str] = ["git"]
    for option in _GIT_CONFIG:
        command += ["-c", option]
    command += [
        "clone", "--depth=1", "--single-branch", "--no-tags",
        "--progress", "--", url, str(destination),
    ]

    process = subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        env=_git_env(),
    )
    captured: list[str] = []
    reader = threading.Thread(
        target=_pump_stderr, args=(process, captured, progress), daemon=True,
    )
    reader.start()

    deadline = time.monotonic() + timeout
    try:
        while process.poll() is None:
            if token is not None and token.cancelled:
                _terminate(process)
                raise ScanCancelled("The scan was cancelled.")
            if time.monotonic() > deadline:
                _terminate(process)
                raise SourceError(
                    f"Cloning took longer than {timeout}s. The repository may be too "
                    "large, or the connection to GitHub is slow.")
            time.sleep(0.2)
    finally:
        reader.join(timeout=2)

    if process.returncode != 0:
        raise SourceError(friendly_git_error("".join(captured)))
    return destination


def _pump_stderr(process: subprocess.Popen, captured: list[str], progress) -> None:
    buffer = b""
    stream = process.stderr
    if stream is None:
        return
    while True:
        chunk = stream.read(256)
        if not chunk:
            break
        buffer += chunk
        parts = re.split(rb"[\r\n]", buffer)
        buffer = parts.pop()
        for raw in parts:
            line = raw.decode("utf-8", errors="replace")
            if not line.strip():
                continue
            if len(captured) < 400:
                captured.append(line + "\n")
            if progress is not None:
                parsed = _parse_progress(line)
                if parsed is not None:
                    progress(*parsed)
    if buffer:
        captured.append(buffer.decode("utf-8", errors="replace"))


def _terminate(process: subprocess.Popen) -> None:
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
