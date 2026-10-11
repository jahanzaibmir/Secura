"""Runtime AI provider management. auto-detecting, swappable, no restart.

Paste-a-key flow (v1.4):
  1. the key's format hints at its provider (gsk_ -> Groq, sk-or- ->
     OpenRouter, sk-... -> OpenAI, bare 32-char -> Mistral); unknown
     formats are probed live against every supported provider
  2. the provider's real model list is fetched. model names are NEVER
     hardcoded, so provider lineup changes cannot break setup
  3. candidates are ranked: non-chat models filtered out, best chat
     model chosen by preference order
  4. a real minimal completion proves key + endpoint + model together
     (top-3 candidates tried). only then is the analyzer swapped

The pipeline resolves the analyzer at analysis time and pins it for one
scan, so a provider change applies to the next scan, never mid-scan.
API keys live in memory only: never written to disk, never logged, and
never echoed back in full. status responses carry a masked form only.
"""
import logging
import threading
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

from backend.ai.analyzer import OllamaAnalyzer
from backend.ai.remote_analyzer import OpenAICompatAnalyzer
from backend.api.schemas import AISettingsResponse
from backend.exceptions import AnalyzerError

logger = logging.getLogger("secura.ai.manager")

# provider -> (api base, display label). the only provider facts we hardcode
_PROVIDER_ENDPOINTS: Dict[str, Tuple[str, str]] = {
    "groq": ("https://api.groq.com/openai/v1", "Groq"),
    "mistral": ("https://api.mistral.ai/v1", "Mistral API"),
    "openai": ("https://api.openai.com/v1", "OpenAI"),
    "openrouter": ("https://openrouter.ai/api/v1", "OpenRouter"),
}

# key format hints. confirmed live before being trusted
_KEY_PREFIX_HINTS: Tuple[Tuple[str, str], ...] = (
    ("groq", "gsk_"),
    ("openrouter", "sk-or-"),
    ("openai", "sk-"),
)

_DEFAULT_MODELS: Dict[str, str] = {
    "groq": "llama-3.3-70b-versatile",
    "mistral": "mistral-small-latest",
    "openai": "gpt-4o-mini",
    "openrouter": "meta-llama/llama-3.1-8b-instruct",
}

PROVIDER_PRESETS: Dict[str, Dict[str, str]] = {
    name: {"api_base": base, "model": _DEFAULT_MODELS.get(name, ""),
           "label": label}
    for name, (base, label) in _PROVIDER_ENDPOINTS.items()
}
PROVIDER_PRESETS["custom"] = {"api_base": "", "model": "",
                              "label": "Custom (OpenAI-compatible)"}

_API_PROVIDERS = set(PROVIDER_PRESETS)

# Model selection: never serve these model families as the brain
_NON_CHAT_TOKENS = (
    "embed", "whisper", "tts", "audio", "image", "moderation", "guard",
    "rerank", "dall-e", "transcri", "sora", "stable-diffusion", "flux",
)
# Model selection: prefer these, in order (substring match on the model id)
_PREFERRED_PATTERNS = (
    "mistral-small", "llama-3.3-70b", "llama-3.1-8b", "gpt-4o-mini",
    "gpt-4.1-mini", "gpt-4.1-nano", ":free", "mistral-medium",
    "mistral-large", "gpt-oss-20b", "gpt-oss-120b", "qwen3", "kimi",
    "gemma", "deepseek", "llama-3.1", "llama-3", "mistral", "qwen",
    "gpt-4o", "gpt-4", "gpt-3.5", "llama", "instruct", "chat",
)


def pick_best_chat_model(model_ids: List[str]) -> List[str]:
    """Rank a provider's model list: best chat model first.

    Non-chat families (embeddings, audio, image generation, moderation)
    are removed entirely; remaining models are ordered by preference so
    the caller can try the top candidates in sequence."""
    usable = [m for m in model_ids
              if m and not any(t in m.lower() for t in _NON_CHAT_TOKENS)]
    for pattern in _PREFERRED_PATTERNS:
        for model in usable:
            if pattern in model.lower():
                return [model] + [x for x in usable if x != model]
    return usable


def _mask_key(key: str) -> str:
    key = (key or "").strip()
    if not key:
        return ""
    if len(key) <= 8:
        return "••••"
    return f"{key[:4]}…{key[-4:]}"


class AnalyzerManager:
    def __init__(self, settings) -> None:
        self._lock = threading.Lock()
        self._settings = settings
        self._provider = "ollama"
        self._provider_label = "Local Ollama"
        self._api_base = ""
        self._key = ""

        if settings.ai_provider in ("openai", "api") and settings.ai_api_key:
            # Startup default from env (power users); the UI path is AI Setup.
            self._install_api(
                "custom", settings.ai_api_base, settings.ai_api_key,
                settings.ai_api_model,
                label=urlparse(settings.ai_api_base).netloc or "API")
        else:
            self._analyzer = self._build_local()

    # -- resolution -----------------------------------------------------------

    def current(self):
        """The active analyzer. Safe to call from scan threads."""
        with self._lock:
            return self._analyzer

    def is_api(self) -> bool:
        with self._lock:
            return self._provider == "api"

    # -- status ----------------------------------------------------------------

    def status(self) -> AISettingsResponse:
        with self._lock:
            analyzer = self._analyzer
            provider = self._provider
            label = self._provider_label
            base = self._api_base
            key = self._key
        try:
            ready = bool(analyzer.can_analyze())
        except Exception:
            ready = False
        if provider == "ollama":
            message = (
                "Local mode. Findings never leave this machine."
                if ready else
                "Ollama is not reachable. Start it with: ollama serve"
            )
        elif not key:
            message = "API mode selected but no key is set. Add one below."
        elif ready:
            message = ("API mode. Findings are sent to the provider "
                       "for analysis.")
        else:
            message = "API key rejected or provider unreachable. Check AI Setup."
        return AISettingsResponse(
            provider=provider, provider_label=label, model=analyzer.model,
            api_base=base, key_set=bool(key), key_masked=_mask_key(key),
            ready=ready, message=message, presets=PROVIDER_PRESETS,
        )

    # -- the paste-a-key flow (v1.4) -------------------------------------------

    def apply_key(self, api_key: str) -> AISettingsResponse:
        """Detect provider, discover the best model, prove it live, connect.

        Raises AnalyzerError (mapped to HTTP 400) on any failure; the
        previously active analyzer is kept unchanged in that case."""
        key = (api_key or "").strip().strip('"').strip("'")
        if len(key) < 20:
            raise AnalyzerError(
                "That doesn't look like an API key. It is too short.")

        # Gate 1. who issued this key?
        provider, base, label = self._detect_provider(key)

        # Gate 2. what models does this provider actually offer right now?
        candidates = self._rank_models(base, key)
        if not candidates:
            raise AnalyzerError(
                f"{label} accepted the key, but no usable chat models were "
                "listed for your account.")

        # Gates 3+4. prove key + endpoint + model together, live.
        last_error = ""
        for candidate in candidates[:3]:
            try:
                self._validate_api(base, key, candidate)
            except AnalyzerError as exc:
                last_error = str(exc)
                logger.info("Model candidate '%s' failed validation: %s",
                            candidate, exc)
                continue
            self._install_api(provider, base, key, candidate, label=label)
            return self.status()
        raise AnalyzerError(
            f"Connected to {label}, but none of its models passed a live "
            f"test (tried {', '.join(candidates[:3])}). Last error: {last_error}")

    def _detect_provider(self, key: str) -> Tuple[str, str, str]:
        """Returns (provider, base_url, label). Raises on failure."""
        # Format hints, confirmed live before being trusted.
        for provider, prefix in _KEY_PREFIX_HINTS:
            if key.startswith(prefix):
                base, label = _PROVIDER_ENDPOINTS[provider]
                state = self._auth_probe(base, key)
                if state in ("ok", "auth"):
                    return provider, base, label
                if state == "unreachable":
                    raise AnalyzerError(
                        f"Could not reach {label}. Check your connection.")
                raise AnalyzerError(
                    f"This looks like a {label} key, but {label} rejected it. "
                    "The key is invalid, revoked, or belongs to an unsupported "
                    "provider.")

        # No recognizable format. probe every supported provider.
        order = ["mistral", "groq", "openai", "openrouter"]
        if len(key) == 32 and key.isalnum():
            # Bare 32-char alphanumeric is Mistral's format. try it first.
            order = ["mistral"] + [p for p in order if p != "mistral"]
        for provider in order:
            base, label = _PROVIDER_ENDPOINTS[provider]
            if self._auth_probe(base, key) in ("ok", "auth"):
                return provider, base, label
        raise AnalyzerError(
            "This key was not accepted by any supported provider (Mistral, "
            "Groq, OpenAI, OpenRouter). Check the key, or use Advanced "
            "setup below for a custom endpoint.")

    @staticmethod
    def _auth_probe(base: str, key: str) -> str:
        """One cheap request that classifies the key:

        'ok'         . request fully succeeded (key valid)
        'auth'       . auth passed, only the (deliberately bogus) model
                        name was rejected. the key IS valid for this provider
        'no'         . 401/403: wrong key for this provider
        'unreachable'. network problem
        """
        try:
            response = requests.post(
                f"{base}/chat/completions",
                headers={"Authorization": f"Bearer {key}",
                         "Content-Type": "application/json"},
                json={"model": "vw-auth-probe",
                      "messages": [{"role": "user", "content": "hi"}],
                      "max_tokens": 1},
                timeout=12,
            )
        except requests.RequestException:
            return "unreachable"
        if response.status_code == 200:
            return "ok"
        if response.status_code in (401, 403):
            return "no"
        if response.status_code == 429:
            return "ok"                 # valid key, throttled
        if response.status_code in (400, 404, 422):
            return "auth"               # auth passed; model name was rejected
        return "no"

    @staticmethod
    def _rank_models(base: str, key: str) -> List[str]:
        """Fetch the provider's live model list, best chat model first."""
        try:
            response = requests.get(
                f"{base}/models",
                headers={"Authorization": f"Bearer {key}"},
                timeout=10,
            )
        except requests.RequestException:
            return []
        if response.status_code != 200:
            return []
        try:
            data = response.json()
        except ValueError:
            return []
        ids = []
        for item in data.get("data", []):
            if isinstance(item, dict) and item.get("id"):
                ids.append(item["id"])
        return pick_best_chat_model(ids)

    # -- manual flow (Advanced / custom endpoints) ------------------------------

    def apply(self, provider: str, api_base: str = "", api_key: str = "",
              model: str = "") -> AISettingsResponse:
        provider = (provider or "").strip().lower()
        if provider == "ollama":
            return self._apply_local()
        if provider not in _API_PROVIDERS:
            raise AnalyzerError(f"Unknown provider: {provider}")

        preset = PROVIDER_PRESETS[provider]
        base = (api_base or preset["api_base"]).strip().rstrip("/")
        key = (api_key or "").strip()
        chosen_model = (model or preset["model"]).strip()

        if not base:
            raise AnalyzerError("An API base URL is required.")
        if not chosen_model:
            raise AnalyzerError("A model name is required.")
        if not base.startswith(("http://", "https://")):
            raise AnalyzerError("API base URL must start with http:// or https://")
        if not key:
            raise AnalyzerError("An API key is required for API providers.")

        self._validate_api(base, key, chosen_model)
        self._install_api(provider, base, key, chosen_model)
        return self.status()

    def _apply_local(self) -> AISettingsResponse:
        analyzer = self._build_local()
        with self._lock:
            self._analyzer = analyzer
            self._provider = "ollama"
            self._provider_label = "Local Ollama"
            self._api_base = ""
            self._key = ""
        logger.info("AI provider switched to local Ollama (%s)", analyzer.model)
        return self.status()

    # -- internals ----------------------------------------------------------------

    def _install_api(self, provider: str, base: str, key: str, model: str,
                     label: Optional[str] = None) -> None:
        analyzer = OpenAICompatAnalyzer(
            base_url=base, api_key=key, model=model,
            timeout=min(self._settings.analyzer_timeout, 120),
            enable_ai=self._settings.enable_ai,
            max_tokens=self._settings.ai_max_tokens,
        )
        if label is None:
            label = _PROVIDER_ENDPOINTS.get(provider, (base, "API"))[1]
        with self._lock:
            self._analyzer = analyzer
            self._provider = "api"
            self._provider_label = label
            self._api_base = base
            self._key = key
        logger.info("AI provider connected: %s (%s)", label, model)

    def _build_local(self) -> OllamaAnalyzer:
        return OllamaAnalyzer(
            base_url=self._settings.ollama_base_url,
            model=self._settings.mistral_model,
            timeout=self._settings.analyzer_timeout,
            enable_ai=self._settings.enable_ai,
            num_predict=self._settings.ai_max_tokens,
        )

    @staticmethod
    def _validate_api(base: str, key: str, model: str) -> None:
        try:
            response = requests.post(
                f"{base}/chat/completions",
                headers={"Authorization": f"Bearer {key}",
                         "Content-Type": "application/json"},
                json={"model": model,
                      "messages": [{"role": "user",
                                    "content": "Reply with the single word: OK"}],
                      "max_tokens": 16, "temperature": 0},
                timeout=30,
            )
        except requests.RequestException as exc:
            raise AnalyzerError(f"Could not reach {base}: {exc}") from exc
        if response.status_code == 200:
            return
        if response.status_code in (401, 403):
            raise AnalyzerError("The API key was rejected by the provider.")
        if response.status_code == 404:
            raise AnalyzerError(
                f"Model '{model}' was not found at this provider. "
                "check the model name.")
        if response.status_code == 429:
            raise AnalyzerError(
                "Rate limited. The key works, but the provider is "
                "throttling. Try again in a moment.")
        raise AnalyzerError(
            f"Provider returned HTTP {response.status_code}: "
            f"{(response.text or '')[:200]}")
