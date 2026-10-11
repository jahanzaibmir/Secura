"""AI provider settings — the endpoints behind the UI's AI Setup page.

Two flows:
  POST /api/settings/ai/auto — paste a key; provider, endpoint, and best
      model are detected and live-verified by the backend.
  POST /api/settings/ai      — manual configuration (custom endpoints).

The API key arrives in the request body, is validated with real provider
requests, and is then held in memory only. It is never persisted, never
logged, and never returned in full — status responses mask it.
"""
from fastapi import APIRouter, HTTPException

from backend.api.schemas import (
    AIKeyRequest, AISettingsRequest, AISettingsResponse,
)
from backend.core import context
from backend.exceptions import AnalyzerError

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("/ai", response_model=AISettingsResponse)
def get_ai_settings() -> AISettingsResponse:
    return context.ai_manager.status()


@router.post("/ai/auto", response_model=AISettingsResponse)
def connect_api_key(request: AIKeyRequest) -> AISettingsResponse:
    try:
        return context.ai_manager.apply_key(request.api_key)
    except AnalyzerError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/ai", response_model=AISettingsResponse)
def set_ai_settings(request: AISettingsRequest) -> AISettingsResponse:
    try:
        return context.ai_manager.apply(
            provider=request.provider,
            api_base=request.api_base,
            api_key=request.api_key,
            model=request.model,
        )
    except AnalyzerError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
