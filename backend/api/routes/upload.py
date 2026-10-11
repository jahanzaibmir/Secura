"""Folder upload scanning — files arrive over HTTP, get materialized into a
workspace temp folder preserving their structure, then run through the
standard local-code pipeline. The temp folder is deleted after the scan.

Security posture:
  - every browser-supplied path is sanitized: traversal ("..") rejected,
    absolute paths stripped, junk directories (.git, node_modules, …)
    never written
  - only scannable source suffixes are materialized — no images, no bloat
  - hard caps: 2000 files, 10 MB per file, 100 MB total
  - folder names become short, sanitized display labels only
"""
import json
import logging
import tempfile
from pathlib import Path, PurePosixPath
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, UploadFile

from backend.api.schemas import ScanAccepted, ScanRequest, TargetType
from backend.config import settings
from backend.core import context
from backend.scanners.utils.git_handler import remove_tree

logger = logging.getLogger("secura.upload")

router = APIRouter(prefix="/api/scan", tags=["scan"])

MAX_FILES = 2000
MAX_FILE_BYTES = 10 * 1024 * 1024        # 10 MB per file
MAX_TOTAL_BYTES = 100 * 1024 * 1024      # 100 MB per upload

_SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", "node_modules", "venv",
              ".venv", ".tox", ".nox", "dist", "build", ".eggs",
              ".mypy_cache", ".pytest_cache", ".idea", ".vscode"}
_SCANNABLE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}


def sanitize_rel_path(raw: str) -> Optional[str]:
    """Normalize a browser-supplied relative path. None means: skip file."""
    if not raw:
        return None
    parts = [p for p in raw.replace("\\", "/").split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        return None                      # empty or traversal attempt
    if any(p.lower() in _SKIP_DIRS for p in parts):
        return None                      # junk directory anywhere in the path
    rel = "/".join(parts)
    if PurePosixPath(rel).suffix.lower() not in _SCANNABLE_SUFFIXES:
        return None                      # not source code — never written
    return rel


def _sanitize_folder_name(raw: str) -> str:
    """Browser-supplied folder name -> safe, short display label."""
    cleaned = "".join(c for c in (raw or "").strip() if c.isalnum() or c in "._-")
    cleaned = cleaned.strip(".")
    return cleaned[:40] or "folder"


def _cleanup_upload_dir(path: str) -> None:
    """Background task: remove the materialized upload after the scan."""
    try:
        remove_tree(Path(path))
        logger.info("Cleaned uploaded codebase: %s", path)
    except Exception:
        logger.exception("Upload cleanup failed: %s", path)


@router.post("/upload", response_model=ScanAccepted, status_code=202)
def upload_scan(
    background_tasks: BackgroundTasks,
    files: List[UploadFile] = File(...),
    paths: str = Form("[]"),
    folder_name: str = Form(""),
) -> ScanAccepted:
    try:
        rel_paths = json.loads(paths)
    except ValueError:
        raise HTTPException(status_code=400, detail="paths must be a JSON array")
    if not isinstance(rel_paths, list) or len(rel_paths) != len(files):
        raise HTTPException(status_code=400,
                            detail="files and paths length mismatch")
    if not files:
        raise HTTPException(status_code=400, detail="No files received")
    if len(files) > MAX_FILES:
        raise HTTPException(status_code=400,
                            detail=f"Too many files ({len(files)} > {MAX_FILES}).")

    settings.workspace_dir.mkdir(parents=True, exist_ok=True)
    workdir = Path(tempfile.mkdtemp(prefix="vw_upload_",
                                    dir=str(settings.workspace_dir)))
    written = 0
    total_bytes = 0
    try:
        for upload, raw_path in zip(files, rel_paths):
            rel = sanitize_rel_path(str(raw_path))
            if rel is None:
                continue                 # junk, non-source, or unsafe — skipped
            target = workdir / Path(*rel.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            size = 0
            with open(target, "wb") as out:
                while True:
                    chunk = upload.file.read(65536)
                    if not chunk:
                        break
                    size += len(chunk)
                    total_bytes += len(chunk)
                    if size > MAX_FILE_BYTES:
                        raise HTTPException(
                            status_code=400,
                            detail=f"'{rel}' exceeds the 10 MB per-file limit.")
                    if total_bytes > MAX_TOTAL_BYTES:
                        raise HTTPException(
                            status_code=400,
                            detail="Upload exceeds the 100 MB total limit.")
                    out.write(chunk)
            written += 1
    except HTTPException:
        remove_tree(workdir)
        raise

    if written == 0:
        remove_tree(workdir)
        raise HTTPException(
            status_code=400,
            detail="No scannable files found in that folder "
                   "(Python or JavaScript/TypeScript source).")

    label = f"{_sanitize_folder_name(folder_name)} · {written} file(s)"
    job = context.jobs.create(
        ScanRequest(target_type=TargetType.LOCAL_PATH, target=str(workdir)),
        label=label,
    )
    # Background tasks run in order: the scan completes, then cleanup.
    background_tasks.add_task(context.pipeline.run_job, job.job_id)
    background_tasks.add_task(_cleanup_upload_dir, str(workdir))
    logger.info("Upload accepted: %s -> job %s", label, job.job_id)
    return ScanAccepted(
        job_id=job.job_id,
        status=job.status,
        message=f"Uploaded {written} source file(s) — scan queued.",
    )
