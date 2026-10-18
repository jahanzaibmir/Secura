"""Route aggregation under the ``/api`` prefix."""
from __future__ import annotations

from fastapi import APIRouter

from backend.api.routes import health, reports, scans, settings, uploads

api_router = APIRouter(prefix="/api")
api_router.include_router(health.router)
api_router.include_router(uploads.router)
api_router.include_router(scans.router)
api_router.include_router(reports.router)
api_router.include_router(settings.router)

__all__ = ["api_router"]
