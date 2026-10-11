from fastapi import APIRouter

from backend.api.schemas import HealthResponse
from backend.core import context

router = APIRouter(tags=["system"])


@router.get("/api/health", response_model=HealthResponse)
def health() -> HealthResponse:
    analyzer = context.ai_manager.current()
    return HealthResponse(
        status="ok",
        version=context.settings.app_version,
        ollama={
            "provider": "api" if context.ai_manager.is_api() else "ollama",
            "reachable": analyzer.is_available(),
            "version": analyzer.server_version(),
            "model": analyzer.model,
            "model_installed": analyzer.model_installed(),
            "ai_enabled": context.settings.enable_ai,
            "ai_ready": analyzer.can_analyze(),
        },
        scanners_registered=context.registry.registered_types(),
    )
