"""Provider facts: endpoints, key-format hints, and model ranking.

Model names are never hardcoded as the only option. The live model list from the
provider is ranked, so provider lineup changes cannot break setup.
"""
from __future__ import annotations

from backend.schemas import ProviderPreset

ENDPOINTS: dict[str, tuple[str, str]] = {
    "groq": ("https://api.groq.com/openai/v1", "Groq"),
    "mistral": ("https://api.mistral.ai/v1", "Mistral"),
    "openai": ("https://api.openai.com/v1", "OpenAI"),
    "openrouter": ("https://openrouter.ai/api/v1", "OpenRouter"),
}

KEY_PREFIXES: tuple[tuple[str, str], ...] = (
    ("groq", "gsk_"),
    ("openrouter", "sk-or-"),
    ("openai", "sk-"),
)

DEFAULT_MODELS: dict[str, str] = {
    "groq": "llama-3.3-70b-versatile",
    "mistral": "mistral-small-latest",
    "openai": "gpt-4o-mini",
    "openrouter": "meta-llama/llama-3.1-8b-instruct",
}

PRESETS: dict[str, ProviderPreset] = {
    name: ProviderPreset(label=label, api_base=base, model=DEFAULT_MODELS.get(name, ""))
    for name, (base, label) in ENDPOINTS.items()
}
PRESETS["custom"] = ProviderPreset(label="Custom (OpenAI-compatible)", api_base="", model="")

_NON_CHAT = (
    "embed", "whisper", "tts", "audio", "image", "moderation", "guard", "rerank",
    "dall-e", "transcri", "sora", "stable-diffusion", "flux", "realtime", "search",
)

_PREFERRED = (
    "mistral-small", "llama-3.3-70b", "gpt-4o-mini", "gpt-4.1-mini", "llama-3.1-8b",
    "gpt-4.1-nano", ":free", "mistral-medium", "mistral-large", "gpt-oss-20b", "gpt-oss-120b",
    "qwen3", "kimi", "gemma", "deepseek", "llama-3.1", "llama-3", "mistral", "qwen",
    "gpt-4o", "gpt-4", "llama", "instruct", "chat",
)


def pick_best_chat_model(model_ids: list[str]) -> list[str]:
    """Drops non-chat models and moves the most suitable chat model to the front."""
    usable = [m for m in model_ids if m and not any(t in m.lower() for t in _NON_CHAT)]
    for pattern in _PREFERRED:
        for model in usable:
            if pattern in model.lower():
                return [model] + [m for m in usable if m != model]
    return usable


def mask_key(key: str) -> str:
    key = (key or "").strip()
    if not key:
        return ""
    if len(key) <= 8:
        return "••••"
    return f"{key[:4]}…{key[-4:]}"
