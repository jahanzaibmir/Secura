"""Codebase uploads: individual files with relative paths, or one zip archive."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Request, status
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile

from backend.api.dependencies import get_container
from backend.core.container import Container
from backend.exceptions import SecuraError, ValidationError
from backend.schemas import ScanAccepted, ScanRequest, TargetType
from backend.storage.uploads import (
    UploadResult,
    materialize_archive,
    materialize_files,
    sanitize_label,
)
from backend.storage.workspace import remove_tree

router = APIRouter(prefix="/scans", tags=["scans"])


def _uploads(values: list) -> list[UploadFile]:
    return [value for value in values if isinstance(value, UploadFile)]


def _paths(raw: str | None, count: int, files: list[UploadFile]) -> list[str]:
    if not raw:
        return [upload.filename or "" for upload in files]
    try:
        paths = json.loads(raw)
    except ValueError as exc:
        raise ValidationError("'paths' must be a JSON array of relative paths.") from exc
    if not isinstance(paths, list) or len(paths) != count:
        raise ValidationError("'paths' must list exactly one relative path per uploaded file.")
    return [str(path) for path in paths]


@router.post(
    "/upload", response_model=ScanAccepted, status_code=status.HTTP_202_ACCEPTED,
    summary="Upload a codebase (files or a .zip archive) and queue a scan",
)
async def upload_scan(request: Request, container: Container = Depends(get_container)) -> ScanAccepted:
    settings = container.settings
    form = await request.form(
        max_files=settings.upload_max_files + 1,
        max_fields=settings.upload_max_files + 16,
        max_part_size=8 * 1024 * 1024,
    )
    try:
        archive = form.get("archive")
        files = _uploads(form.getlist("files"))
        raw_name = form.get("name")
        name = raw_name if isinstance(raw_name, str) else ""

        result: UploadResult
        if isinstance(archive, UploadFile):
            result = await run_in_threadpool(materialize_archive, archive.file, settings)
            name = name or (archive.filename or "archive").rsplit(".", 1)[0]
        elif files:
            if len(files) > settings.upload_max_files:
                raise ValidationError(f"Too many files; the limit is {settings.upload_max_files}.")
            raw_paths = form.get("paths")
            paths = _paths(raw_paths if isinstance(raw_paths, str) else None, len(files), files)
            pairs = [(path, upload.file) for path, upload in zip(paths, files, strict=True)]
            result = await run_in_threadpool(materialize_files, pairs, settings)
            if not name and paths:
                name = paths[0].replace("\\", "/").split("/", 1)[0]
        else:
            raise ValidationError("Attach files under 'files' or a zip archive under 'archive'.")
    finally:
        await form.close()

    label = sanitize_label(name)
    try:
        job = container.submit(
            ScanRequest(target_type=TargetType.UPLOAD, target=str(result.root)),
            label=label,
            cleanup_path=result.root,
        )
    except SecuraError:
        remove_tree(result.root)
        raise
    return ScanAccepted(
        job_id=job.job_id,
        status=job.status,
        message=f"Received {result.written} file(s) ({result.skipped} skipped). Scan queued.",
    )
