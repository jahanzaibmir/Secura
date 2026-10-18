"""Scan lifecycle: start, list, inspect and cancel."""
from __future__ import annotations

from fastapi import APIRouter, Depends, status

from backend.api.dependencies import get_container
from backend.core.container import Container
from backend.core.validators import validate_target
from backend.exceptions import ForbiddenError
from backend.schemas import JobView, ScanAccepted, ScanCreate, ScanRequest, TargetType

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("", response_model=list[JobView], summary="Recent scans, newest first")
def list_scans(container: Container = Depends(get_container)) -> list[JobView]:
    return container.jobs.list_views()


@router.post("", response_model=ScanAccepted, status_code=status.HTTP_202_ACCEPTED,
             summary="Queue a scan of a GitHub repository or a server-side folder")
def start_scan(body: ScanCreate, container: Container = Depends(get_container)) -> ScanAccepted:
    request = body.to_request()
    if request.target_type == TargetType.LOCAL_PATH and not container.settings.allow_local_paths:
        raise ForbiddenError(
            "Scanning server-side folders is disabled. Upload the folder instead, or set "
            "SECURA_ALLOW_LOCAL_PATHS=1 on a trusted, single-user machine.")
    normalized = validate_target(request.target_type, request.target)
    label = normalized.removeprefix("https://github.com/")
    job = container.submit(ScanRequest(target_type=request.target_type, target=normalized), label=label)
    return ScanAccepted(job_id=job.job_id, status=job.status, message="Scan queued.")


@router.get("/{job_id}", response_model=JobView, summary="Live status of one scan")
def get_scan(job_id: str, container: Container = Depends(get_container)) -> JobView:
    return container.jobs.view(job_id)


@router.post("/{job_id}/cancel", response_model=JobView, summary="Cancel a queued or running scan")
def cancel_scan(job_id: str, container: Container = Depends(get_container)) -> JobView:
    return container.jobs.cancel(job_id)
