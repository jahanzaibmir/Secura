"""GitHub repository cloning with timeouts, no credential prompts, safe cleanup."""
import logging
import os
import shutil
import stat
import sys
from pathlib import Path

import git

from backend.exceptions import ScannerError

logger = logging.getLogger("secura.scanners.git")

# ── Critical: git must FAIL, never PROMPT ──────────────────────────
# Without this, git blocks forever waiting for credentials when the repo
# is private, rate-limited, or GitHub issues an auth challenge — and the
# clone runs in a background thread with no TTY to answer on.
os.environ.setdefault("GIT_TERMINAL_PROMPT", "0")
os.environ.setdefault("GIT_ASKPASS", "/bin/false")
os.environ.setdefault("GIT_SSH_COMMAND", "ssh -oBatchMode=yes -oStrictHostKeyChecking=no")

# 120s is plenty for a shallow clone of a normal repo; large repos will
# hit the timeout and get an honest error instead of hanging.
CLONE_TIMEOUT = 120


def _rmtree_error_handler(func, path, _exc) -> None:
    # Third argument differs between onerror (exc_info tuple, <=3.11) and
    # onexc (exception instance, >=3.12) — unused either way.
    try:
        os.chmod(path, stat.S_IWRITE)   # git packfiles are read-only on Windows
        func(path)
    except OSError:
        pass


def remove_tree(path: Path) -> None:
    """Delete a directory tree, tolerating read-only files (git clones)."""
    if not path.exists():
        return
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_rmtree_error_handler)
    else:
        shutil.rmtree(path, onerror=_rmtree_error_handler)


def _decode_stderr(raw) -> str:
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")
    return raw or ""


def _friendly_git_error(stderr: str) -> str:
    lowered = stderr.lower()
    if "terminal prompts disabled" in lowered:
        return ("GitHub requested authentication (the repository may be private, "
                "deleted, or you are rate-limited). Secura only clones public "
                "repositories — wait a minute and try again.")
    if "repository not found" in lowered or "does not exist" in lowered or "403" in lowered:
        return ("Repository not accessible — it may be private, deleted, or the "
                "URL is wrong. Secura can only clone public repositories.")
    if "authentication failed" in lowered or "401" in lowered:
        return ("Authentication required — this repository is private. "
                "Secura only scans public repositories.")
    if "timed out" in lowered or "timeout" in lowered:
        return ("Clone timed out — the repository may be too large for a shallow "
                "clone, or your network connection to GitHub is slow.")
    if "could not resolve host" in lowered or "network" in lowered:
        return ("Cannot reach GitHub — check your internet connection "
                "(DNS or firewall may be blocking github.com).")
    if "ssl" in lowered or "tls" in lowered:
        return "TLS problem while contacting GitHub."
    snippet = stderr.splitlines()[-1][:200] if stderr else "unknown git error"
    return f"git clone failed: {snippet}"


def clone_repository(url: str, destination: Path, timeout: int = CLONE_TIMEOUT) -> Path:
    """Shallow-clone a public repository into an existing empty directory.

    Never prompts for credentials (GIT_TERMINAL_PROMPT=0), always bounded
    by a hard timeout, and maps raw git errors to plain English.
    """
    try:
        git.Repo.clone_from(
            url,
            str(destination),
            multi_options=["--depth=1", "--no-tags", "--single-branch"],
            kill_after_timeout=timeout,
        )
    except git.GitCommandError as exc:
        raise ScannerError(_friendly_git_error(_decode_stderr(exc.stderr).strip())) from exc
    except git.GitCommandNotFound as exc:
        raise ScannerError("The `git` executable was not found on this machine.") from exc
    except Exception as exc:  # network blips, kill-after-timeout, disk issues
        raise ScannerError(_friendly_git_error(str(exc))) from exc
    return destination
