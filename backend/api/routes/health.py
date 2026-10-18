"""Service health and capabilities."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from backend.api.dependencies import get_container
from backend.core.container import Container
from backend.schemas import HealthResponse

router = APIRouter(tags=["system"])


@router.get("/health", response_model=HealthResponse, summary="Service health and capabilities")
def health(container: Container = Depends(get_container)) -> HealthResponse:
    running, queued = container.jobs.counts()
    return HealthResponse(
        status="ok",
        version=container.settings.version,
        ai=container.ai.ai_status(),
        engines=container.engine_info(),
        sources=container.sources.types(),
        allow_local_paths=container.settings.allow_local_paths,
        active_scans=running,
        queued_scans=queued,
    )
