"""OpenAI-compatible API analyzer. fast cloud brains for Secura.

Works with any provider speaking the OpenAI chat-completions protocol:
Mistral's own API, Groq, OpenRouter, OpenAI, Together, DeepSeek, and
self-hosted gateways (vLLM, LiteLLM). Inherits the full v2 quality stack
from OllamaAnalyzer. grounding, sanitization, depth and truncation
retries. and swaps only the transport.

Trade-off vs local Ollama: answers arrive in seconds instead of minutes,
but finding text (which contains scanned source code) is sent to the
provider. Choose per deployment, and disclose it to users if public.
"""
import logging
from typing import Optional
from urllib.parse import urlparse

import requests

from backend.ai.analyzer import OllamaAnalyzer, _TransientOllamaError
from backend.exceptions import AnalyzerError, OllamaNotAvailable

logger = logging.getLogger("secura.ai.remote")


class OpenAICompatAnalyzer(OllamaAnalyzer):
    """Same brain, faster transport."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        timeout: int = 90,
        enable_ai: bool = True,
        max_tokens: int = 700,
        retry_backoff: float = 1.0,
        cache_ttl: float = 5.0,
    ) -> None:
        super().__init__(
            base_url=base_url, model=model, timeout=timeout,
            enable_ai=enable_ai, retry_backoff=retry_backoff,
            cache_ttl=cache_ttl, num_predict=max_tokens,
        )
        self.api_key = (api_key or "").strip()

    # -- health ---------------------------------------------------------------

    @property
    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.api_key}"}

    def is_available(self) -> bool:
        return bool(self.api_key)

    def server_version(self) -> Optional[str]:
        host = urlparse(self.base_url).netloc
        return host or "api"

    def _probe_model_installed(self) -> bool:
        if not self.api_key:
            return False
        try:
            response = requests.get(
                f"{self.base_url}/models", headers=self._headers, timeout=5
            )
            if response.status_code in (401, 403, 422):
                return False           # key rejected. definitely not ready
            return True                # tolerant: some providers lack /models
        except requests.RequestException:
            return False

    # -- generation (transport only; explain() inherited) ---------------------

    def generate(self, prompt: str, system: Optional[str] = None) -> str:
        if not self.api_key:
            raise AnalyzerError(
                "API mode is active but no key is set. Add one in AI Setup."
            )
        self._truncated_once = False
        last_error = ""
        for attempt in (1, 2):
            try:
                return self._generate_once(prompt, system)
            except _TransientOllamaError as exc:
                last_error = str(exc)
                if attempt == 1 and self.retry_backoff > 0:
                    import time
                    time.sleep(self.retry_backoff)
        raise OllamaNotAvailable(
            f"Provider did not return a usable response after retries: {last_error}"
        )

    def _generate_once(self, prompt: str, system: Optional[str]) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.2,
            "max_tokens": self._num_predict,
        }
        try:
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers={**self._headers, "Content-Type": "application/json"},
                json=payload,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise _TransientOllamaError(str(exc)) from exc

        if response.status_code != 200:
            snippet = (response.text or "")[:300]
            if response.status_code in (401, 403):
                raise AnalyzerError(
                    f"API key rejected by the provider (HTTP {response.status_code})."
                )
            if response.status_code == 404:
                raise AnalyzerError(
                    f"Model '{self.model}' not found at this provider. "
                    "Check the model name in AI Setup."
                )
            if response.status_code == 429:
                raise _TransientOllamaError("rate limited (HTTP 429)")
            if response.status_code >= 500:
                raise _TransientOllamaError(f"HTTP {response.status_code}: {snippet}")
            raise AnalyzerError(
                f"Provider returned HTTP {response.status_code}: {snippet}"
            )

        try:
            data = response.json()
            choice = (data.get("choices") or [{}])[0]
            text = ((choice.get("message") or {}).get("content") or "").strip()
            finish = choice.get("finish_reason")
        except ValueError as exc:
            raise AnalyzerError("Provider returned invalid JSON") from exc

        if text:
            if finish == "length" and not self._truncated_once:
                # Answer cut at the token cap. retry once with headroom.
                self._truncated_once = True
                self._num_predict = max(700, self._num_predict)
                raise _TransientOllamaError("truncated at token cap")
            return text
        raise _TransientOllamaError("empty response")
