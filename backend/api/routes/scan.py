from typing import List

from fastapi import APIRouter, BackgroundTasks, HTTPException, status

from backend.api.schemas import JobSummary, JobView, ScanAccepted, ScanRequest
from backend.core import context

router = APIRouter(prefix="/api", tags=["scan"])


@router.get("/scan", response_model=List[JobSummary])
def list_scans() -> List[JobSummary]:
    """Recent jobs, newest first — the persistence backbone for the UI."""
    return context.jobs.list_summaries()


@router.post("/scan", response_model=ScanAccepted, status_code=status.HTTP_202_ACCEPTED)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks) -> ScanAccepted:
    job = context.jobs.create(request)
    background_tasks.add_task(context.pipeline.run_job, job.job_id)
    return ScanAccepted(
        job_id=job.job_id,
        status=job.status,
        message="Scan queued. Poll GET /api/scan/{job_id} for progress.",
    )


@router.get("/scan/{job_id}", response_model=JobView)
def get_scan(job_id: str) -> JobView:
    view = context.jobs.get_view(job_id)
    if view is None:
        raise HTTPException(status_code=404, detail=f"Unknown job: {job_id}")
    return view
