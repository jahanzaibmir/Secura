"""AI provider settings.

API keys arrive in the request body, are verified with live provider requests,
and are then held in memory only. They are never persisted, never logged, and
never returned in full.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends

from backend.api.dependencies import get_container
from backend.core.container import Container
from backend.schemas import AIKeyRequest, AIProviderUpdate, AISettingsResponse

router = APIRouter(prefix="/settings", tags=["settings"])


@router.get("/ai", response_model=AISettingsResponse, summary="Active AI provider")
def get_ai_settings(container: Container = Depends(get_container)) -> AISettingsResponse:
    return container.ai.status()


@router.put("/ai", response_model=AISettingsResponse, summary="Configure a provider explicitly")
def update_ai_settings(body: AIProviderUpdate, container: Container = Depends(get_container)) -> AISettingsResponse:
    return container.ai.apply(provider=body.provider, api_base=body.api_base,
                              api_key=body.api_key, model=body.model)


@router.post("/ai/key", response_model=AISettingsResponse, summary="Connect by pasting an API key")
def connect_key(body: AIKeyRequest, container: Container = Depends(get_container)) -> AISettingsResponse:
    return container.ai.apply_key(body.api_key)
