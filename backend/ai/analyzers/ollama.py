"""Local inference through Ollama. Findings never leave the machine."""
from __future__ import annotations

import json

import requests

from backend.ai.analyzers.base import BaseAnalyzer, Generation, Readiness, TransientAnalyzerError
from backend.exceptions import AnalyzerError


def resolve_model(wanted: str, installed: list[str]) -> str | None:
    """Matches ``mistral`` to ``mistral:latest`` and tolerates registry prefixes."""
    if wanted in installed:
        return wanted
    base, _, tag = wanted.partition(":")
    for name in installed:
        name_base, _, name_tag = name.partition(":")
        if name_base.rsplit("/", 1)[-1] == base.rsplit("/", 1)[-1] and (
            name_tag == (tag or "latest") or (not tag and name_tag == "latest")
        ):
            return name
    return None


class OllamaAnalyzer(BaseAnalyzer):
    provider = "ollama"
    max_concurrency = 1

    def __init__(self, base_url: str, model: str, **kwargs) -> None:
        super().__init__(model=model, **kwargs)
        self.base_url = base_url.rstrip("/")
        self._resolved: str | None = None

    @property
    def provider_label(self) -> str:
        return "Ollama (local)"

    def list_models(self) -> list[str]:
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=3)
            if response.status_code != 200:
                return []
            models = response.json().get("models") or []
        except (requests.RequestException, ValueError):
            return []
        return sorted(str(m.get("name")) for m in models if m.get("name"))

    def _probe_readiness(self) -> Readiness:
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=3)
        except requests.RequestException:
            return Readiness(False, f"Local AI (Ollama) is not reachable at {self.base_url}. Start it with "
                             "ollama serve, or connect a cloud provider in Settings.")
        if response.status_code != 200:
            return Readiness(False, f"Ollama responded with HTTP {response.status_code}.")
        try:
            installed = [str(m.get("name")) for m in response.json().get("models") or []]
        except ValueError:
            return Readiness(False, "Ollama returned an unreadable model list.")
        resolved = resolve_model(self.model, installed)
        if resolved is None:
            return Readiness(False, f"Model '{self.model}' is not installed. Run: ollama pull {self.model}")
        self._resolved = resolved
        return Readiness(True, "Local mode. Findings never leave this machine.")

    def _complete(self, prompt: str, system: str | None, max_tokens: int) -> Generation:
        payload = {
            "model": self._resolved or self.model,
            "prompt": prompt,
            "stream": True,
            "options": {"num_predict": max_tokens, "temperature": 0.2},
        }
        if system:
            payload["system"] = system
        try:
            response = requests.post(
                f"{self.base_url}/api/generate", json=payload,
                timeout=(10, self.timeout), stream=True,
            )
        except requests.RequestException as exc:
            raise TransientAnalyzerError(str(exc)) from exc

        try:
            if response.status_code != 200:
                raise self._http_error(response.status_code, response.text or "")
            parts: list[str] = []
            truncated = False
            for raw in response.iter_lines():
                if not raw:
                    continue
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8", errors="replace")
                try:
                    chunk = json.loads(raw)
                except ValueError:
                    continue
                if chunk.get("response"):
                    parts.append(chunk["response"])
                if chunk.get("done"):
                    truncated = chunk.get("done_reason") == "length"
                    break
        except requests.RequestException as exc:
            raise TransientAnalyzerError(str(exc)) from exc
        finally:
            response.close()
        return Generation(text="".join(parts).strip(), truncated=truncated)

    def _http_error(self, status_code: int, body: str) -> Exception:
        detail = body[:300]
        try:
            data = json.loads(body)
            if isinstance(data, dict) and data.get("error"):
                detail = str(data["error"])[:300]
        except ValueError:
            pass
        lowered = detail.lower()
        if "not found" in lowered and "model" in lowered:
            return AnalyzerError(f"Model '{self.model}' is not installed. Run: ollama pull {self.model}")
        if status_code >= 500:
            return TransientAnalyzerError(f"HTTP {status_code}: {detail}")
        return AnalyzerError(f"Ollama returned HTTP {status_code}: {detail}")
