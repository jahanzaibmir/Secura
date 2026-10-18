"""System status models."""
from __future__ import annotations

from pydantic import BaseModel, Field


class AIStatus(BaseModel):
    enabled: bool
    ready: bool
    provider: str
    provider_label: str
    model: str
    message: str = ""


class EngineInfo(BaseModel):
    name: str
    label: str
    description: str
    available: bool = True
    detail: str = ""


class HealthResponse(BaseModel):
    status: str
    version: str
    ai: AIStatus
    engines: list[EngineInfo] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    allow_local_paths: bool = False
    active_scans: int = 0
    queued_scans: int = 0
