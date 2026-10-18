"""Any provider speaking the OpenAI chat-completions protocol.

Works with Mistral, Groq, OpenRouter, OpenAI, Together, DeepSeek and self-hosted
gateways such as vLLM or LiteLLM. Answers arrive in seconds rather than minutes,
but finding text, including scanned code, is sent to the provider.
"""
from __future__ import annotations

import requests

from backend.ai.analyzers.base import BaseAnalyzer, Generation, Readiness, TransientAnalyzerError
from backend.exceptions import AnalyzerError


class OpenAICompatAnalyzer(BaseAnalyzer):
    provider = "api"
    max_concurrency = 4

    def __init__(self, base_url: str, api_key: str, model: str, label: str = "API", **kwargs) -> None:
        kwargs.setdefault("readiness_ttl", 60.0)
        kwargs.setdefault("retry_backoff", 1.0)
        super().__init__(model=model, **kwargs)
        self.base_url = base_url.rstrip("/")
        self.api_key = (api_key or "").strip()
        self._label = label

    @property
    def provider_label(self) -> str:
        return self._label

    @property
    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}

    def _probe_readiness(self) -> Readiness:
        if not self.api_key:
            return Readiness(False, "API mode is selected but no key is set.")
        try:
            response = requests.get(f"{self.base_url}/models", headers=self._headers, timeout=8)
        except requests.RequestException:
            return Readiness(False, f"{self._label} is unreachable. Check the network connection.")
        if response.status_code in (401, 403):
            return Readiness(False, f"{self._label} rejected the API key.")
        return Readiness(True, f"API mode ({self._label}). Finding text is sent to the provider.")

    def _complete(self, prompt: str, system: str | None, max_tokens: int) -> Generation:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        try:
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers=self._headers,
                json={"model": self.model, "messages": messages,
                      "temperature": 0.2, "max_tokens": max_tokens},
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise TransientAnalyzerError(str(exc)) from exc

        status = response.status_code
        if status != 200:
            detail = (response.text or "")[:300]
            if status in (401, 403):
                raise AnalyzerError(f"The API key was rejected (HTTP {status}).")
            if status == 404:
                raise AnalyzerError(f"Model '{self.model}' was not found at this provider.")
            if status == 429 or status >= 500:
                raise TransientAnalyzerError(f"HTTP {status}: {detail}")
            raise AnalyzerError(f"Provider returned HTTP {status}: {detail}")

        try:
            choice = (response.json().get("choices") or [{}])[0]
        except (ValueError, AttributeError) as exc:
            raise TransientAnalyzerError("invalid JSON from provider") from exc
        text = ((choice.get("message") or {}).get("content") or "").strip()
        return Generation(text=text, truncated=choice.get("finish_reason") == "length")
