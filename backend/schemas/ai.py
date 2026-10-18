"""AI provider settings models."""
from __future__ import annotations

from pydantic import BaseModel, Field


class AIProviderUpdate(BaseModel):
    provider: str = Field(pattern="^(ollama|mistral|groq|openrouter|openai|custom)$")
    api_base: str = Field(default="", max_length=512)
    api_key: str = Field(default="", max_length=4096)
    model: str = Field(default="", max_length=256)


class AIKeyRequest(BaseModel):
    api_key: str = Field(min_length=8, max_length=4096)


class ProviderPreset(BaseModel):
    label: str
    api_base: str
    model: str


class AISettingsResponse(BaseModel):
    provider: str
    provider_label: str
    model: str
    api_base: str = ""
    key_set: bool = False
    key_masked: str = ""
    enabled: bool = True
    ready: bool = False
    message: str = ""
    local_models: list[str] = Field(default_factory=list)
    presets: dict[str, ProviderPreset] = Field(default_factory=dict)
