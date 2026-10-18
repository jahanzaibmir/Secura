"""Runtime AI provider management: auto-detecting, swappable, no restart.

Paste-a-key flow:
  1. The key's format hints at its provider; unknown formats are probed live.
  2. The provider's real model list is fetched and ranked.
  3. A minimal live completion proves key, endpoint and model together.
  4. Only then is the active analyzer swapped.

The pipeline pins the analyzer for the duration of one scan, so a provider change
applies to the next scan, never mid-scan. API keys live in memory only: never
written to disk, never logged, and never echoed back in full.
"""
from __future__ import annotations

import logging
import threading
from urllib.parse import urlparse

import requests

from backend.ai.analyzers import BaseAnalyzer, OllamaAnalyzer, OpenAICompatAnalyzer
from backend.ai.providers import (
    ENDPOINTS,
    KEY_PREFIXES,
    PRESETS,
    mask_key,
    pick_best_chat_model,
)
from backend.config import Settings
from backend.exceptions import AnalyzerError
from backend.schemas import AISettingsResponse, AIStatus

logger = logging.getLogger("secura.ai.manager")

_PROBE_MODEL = "secura-auth-probe"


class AnalyzerManager:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._lock = threading.Lock()
        self._key = ""
        self._api_base = ""
        self._analyzer: BaseAnalyzer
        if settings.ai_provider in ("openai", "api") and settings.ai_api_key:
            label = urlparse(settings.ai_api_base).netloc or "API"
            self._install_api(settings.ai_api_base, settings.ai_api_key, settings.ai_api_model, label)
        else:
            self._analyzer = self._build_local(settings.ollama_model)

    def current(self) -> BaseAnalyzer:
        with self._lock:
            return self._analyzer

    def is_api(self) -> bool:
        return self.current().provider == "api"

    def ai_status(self) -> AIStatus:
        analyzer = self.current()
        readiness = analyzer.readiness()
        return AIStatus(
            enabled=analyzer.enabled,
            ready=readiness.ready,
            provider=analyzer.provider,
            provider_label=analyzer.provider_label,
            model=analyzer.model,
            message=readiness.message,
        )

    def status(self) -> AISettingsResponse:
        with self._lock:
            analyzer, key, base = self._analyzer, self._key, self._api_base
        readiness = analyzer.readiness()
        local_models: list[str] = []
        if isinstance(analyzer, OllamaAnalyzer):
            local_models = analyzer.list_models()
        else:
            local_models = self._build_local(self._settings.ollama_model).list_models()
        return AISettingsResponse(
            provider=analyzer.provider,
            provider_label=analyzer.provider_label,
            model=analyzer.model,
            api_base=base,
            key_set=bool(key),
            key_masked=mask_key(key),
            enabled=analyzer.enabled,
            ready=readiness.ready,
            message=readiness.message,
            local_models=local_models,
            presets=PRESETS,
        )

    def apply_key(self, api_key: str) -> AISettingsResponse:
        """Detects the provider, discovers the best model, proves it live, then connects."""
        key = (api_key or "").strip().strip("\"'")
        if len(key) < 20:
            raise AnalyzerError("That does not look like an API key; it is too short.")

        provider, base, label = self._detect_provider(key)
        candidates = self._rank_models(base, key)
        if not candidates:
            raise AnalyzerError(f"{label} accepted the key, but no usable chat models are listed for it.")

        last_error = ""
        for candidate in candidates[:3]:
            try:
                self._validate(base, key, candidate)
            except AnalyzerError as exc:
                last_error = str(exc)
                logger.info("Model candidate '%s' failed validation: %s", candidate, exc)
                continue
            self._install_api(base, key, candidate, label)
            return self.status()
        raise AnalyzerError(
            f"Connected to {label}, but none of its models passed a live test "
            f"(tried {', '.join(candidates[:3])}). Last error: {last_error}")

    def apply(self, provider: str, api_base: str = "", api_key: str = "", model: str = "") -> AISettingsResponse:
        provider = (provider or "").strip().lower()
        if provider == "ollama":
            return self._apply_local(model)
        if provider not in PRESETS:
            raise AnalyzerError(f"Unknown provider: {provider}")

        preset = PRESETS[provider]
        base = (api_base or preset.api_base).strip().rstrip("/")
        key = (api_key or "").strip()
        chosen = (model or preset.model).strip()
        if not base:
            raise AnalyzerError("An API base URL is required.")
        if not base.startswith(("http://", "https://")):
            raise AnalyzerError("The API base URL must start with http:// or https://")
        if not chosen:
            raise AnalyzerError("A model name is required.")
        if not key:
            raise AnalyzerError("An API key is required for API providers.")

        self._validate(base, key, chosen)
        label = ENDPOINTS.get(provider, (base, urlparse(base).netloc or "Custom API"))[1]
        self._install_api(base, key, chosen, label)
        return self.status()

    def _apply_local(self, model: str = "") -> AISettingsResponse:
        analyzer = self._build_local(model.strip() or self._settings.ollama_model)
        with self._lock:
            self._analyzer = analyzer
            self._key = ""
            self._api_base = ""
        logger.info("AI provider switched to local Ollama (%s)", analyzer.model)
        return self.status()

    def _detect_provider(self, key: str) -> tuple[str, str, str]:
        for provider, prefix in KEY_PREFIXES:
            if key.startswith(prefix):
                base, label = ENDPOINTS[provider]
                state = self._auth_probe(base, key)
                if state == "valid":
                    return provider, base, label
                if state == "unreachable":
                    raise AnalyzerError(f"Could not reach {label}. Check the network connection.")
                raise AnalyzerError(
                    f"This looks like a {label} key, but {label} rejected it. The key is invalid, "
                    "revoked, or belongs to an unsupported provider.")

        order = ["mistral", "groq", "openai", "openrouter"]
        for provider in order:
            base, label = ENDPOINTS[provider]
            if self._auth_probe(base, key) == "valid":
                return provider, base, label
        raise AnalyzerError(
            "This key was not accepted by any supported provider (Mistral, Groq, OpenAI, "
            "OpenRouter). Check the key, or configure a custom endpoint.")

    @staticmethod
    def _auth_probe(base: str, key: str) -> str:
        """Classifies a key with one cheap request: 'valid', 'rejected' or 'unreachable'.

        The probe uses a deliberately bogus model name, so a 400/404/422 means
        authentication passed and only the model was refused.
        """
        try:
            response = requests.post(
                f"{base}/chat/completions",
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json={"model": _PROBE_MODEL, "messages": [{"role": "user", "content": "hi"}], "max_tokens": 1},
                timeout=12,
            )
        except requests.RequestException:
            return "unreachable"
        if response.status_code in (200, 400, 404, 422, 429):
            return "valid"
        return "rejected"

    @staticmethod
    def _rank_models(base: str, key: str) -> list[str]:
        try:
            response = requests.get(f"{base}/models", headers={"Authorization": f"Bearer {key}"}, timeout=10)
            if response.status_code != 200:
                return []
            data = response.json()
        except (requests.RequestException, ValueError):
            return []
        ids = [item["id"] for item in data.get("data") or [] if isinstance(item, dict) and item.get("id")]
        return pick_best_chat_model(ids)

    @staticmethod
    def _validate(base: str, key: str, model: str) -> None:
        try:
            response = requests.post(
                f"{base}/chat/completions",
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json={"model": model, "messages": [{"role": "user", "content": "Reply with the single word: OK"}],
                      "max_tokens": 16, "temperature": 0},
                timeout=30,
            )
        except requests.RequestException as exc:
            raise AnalyzerError(f"Could not reach {base}: {exc.__class__.__name__}") from exc
        if response.status_code == 200:
            return
        if response.status_code in (401, 403):
            raise AnalyzerError("The API key was rejected by the provider.")
        if response.status_code == 404:
            raise AnalyzerError(f"Model '{model}' was not found at this provider; check the model name.")
        if response.status_code == 429:
            raise AnalyzerError("Rate limited. The key works, but the provider is throttling; try again shortly.")
        raise AnalyzerError(f"Provider returned HTTP {response.status_code}: {(response.text or '')[:200]}")

    def _install_api(self, base: str, key: str, model: str, label: str) -> None:
        analyzer = OpenAICompatAnalyzer(
            base_url=base, api_key=key, model=model, label=label,
            timeout=min(self._settings.ai_timeout, 120),
            enabled=self._settings.ai_enabled,
            max_tokens=self._settings.ai_max_tokens,
        )
        with self._lock:
            self._analyzer = analyzer
            self._key = key
            self._api_base = base
        logger.info("AI provider connected: %s (%s)", label, model)

    def _build_local(self, model: str) -> OllamaAnalyzer:
        return OllamaAnalyzer(
            base_url=self._settings.ollama_url,
            model=model,
            timeout=self._settings.ai_timeout,
            enabled=self._settings.ai_enabled,
            max_tokens=self._settings.ai_max_tokens,
        )
