"""Ollama / Mistral 7B analysis engine — v2 (quality-tuned).

Quality levers:
  - curated knowledge-base guidance injected into every prompt, so the model
    elaborates on vetted remediation content instead of inventing fixes
  - generous token budget with automatic retry at 700 tokens when an answer
    is cut off at the cap (Ollama reports done_reason "length")
  - a depth retry when the FIX section comes back too thin
  - streaming generation: every token resets the read timeout
  - anti-hallucination and few-shot system prompt (see prompts.py)
"""
import json
import logging
import re
import threading
import time
from typing import Dict, Optional, Tuple

import requests

from backend.ai import prompts
from backend.ai.knowledge import fallback_explanation
from backend.api.schemas import Finding
from backend.exceptions import AnalyzerError, OllamaNotAvailable

logger = logging.getLogger("secura.ai")

_MARKER_RE = re.compile(r"<<<\s*(WHY|ATTACK|FIX)\s*>>>", re.IGNORECASE)


class _TransientOllamaError(Exception):
    """Internal: worth exactly one retry."""


def _clean_text(text: str, max_chars: int = 2400) -> str:
    """Normalize model output to safe plain text (no markdown, bounded)."""
    if not text:
        return ""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"```[a-zA-Z0-9_+-]*", "", text)          # code fences
    text = re.sub(r"`([^`\n]*)`", r"\1", text)              # inline code
    text = text.replace("**", "").replace("__", "")
    text = re.sub(r"^\s{0,3}#{1,6}\s*", "", text, flags=re.MULTILINE)
    text = re.sub(r"^\s*[-*+]\s+", "• ", text, flags=re.MULTILINE)
    text = re.sub(r"<<<[^>]*>>>", "", text)                 # echoed markers
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = text.strip()
    if len(text) > max_chars:
        cut = text[:max_chars]
        if " " in cut[-40:]:
            cut = cut[: cut.rfind(" ")]
        text = cut.rstrip() + " …"
    return text


def _fix_is_thin(fix: str) -> bool:
    """A good fix shows corrected code or concrete actions, with some length."""
    text = (fix or "").strip()
    if len(text) < 220:
        return True
    signals = ("(", "=", "use ", "Use ", "enable ", "Enable ", "replace ",
               "Replace ", "set ", "Set ", "add ", "Add ", "run ", "Run ",
               "install ", "upgrade ")
    return not any(signal in text for signal in signals)


class OllamaAnalyzer:
    def __init__(
        self,
        base_url: str,
        model: str,
        timeout: int = 240,
        enable_ai: bool = True,
        retry_backoff: float = 2.0,
        cache_ttl: float = 5.0,
        num_predict: int = 550,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout              # read timeout BETWEEN streamed tokens
        self.enable_ai = enable_ai
        self.retry_backoff = retry_backoff
        self._cache_ttl = cache_ttl
        self._num_predict = num_predict     # raised to 700 on truncation
        self._truncated_once = False
        self._cache: Dict[str, Tuple[float, object]] = {}
        self._cache_lock = threading.Lock()
        self._log = logging.getLogger("secura.ai.analyzer")

    # -- cached health probes (called from UI polling AND scan workers) -----

    def _cached(self, key: str, probe):
        now = time.monotonic()
        with self._cache_lock:
            hit = self._cache.get(key)
            if hit is not None and now - hit[0] < self._cache_ttl:
                return hit[1]
        value = probe()  # network call outside the lock
        with self._cache_lock:
            self._cache[key] = (now, value)
        return value

    def is_available(self) -> bool:
        return self._cached("available", self._probe_available)

    def _probe_available(self) -> bool:
        try:
            response = requests.get(f"{self.base_url}/api/version", timeout=3)
            return response.status_code == 200
        except requests.RequestException:
            return False

    def server_version(self) -> Optional[str]:
        return self._cached("server_version", self._probe_server_version)

    def _probe_server_version(self) -> Optional[str]:
        try:
            response = requests.get(f"{self.base_url}/api/version", timeout=3)
            if response.status_code == 200:
                return response.json().get("version")
        except (requests.RequestException, ValueError):
            pass
        return None

    def model_installed(self) -> bool:
        return self._cached("model_installed", self._probe_model_installed)

    def _probe_model_installed(self) -> bool:
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=3)
            if response.status_code != 200:
                return False
            names = {m.get("name", "") for m in response.json().get("models", [])}
            return self.model in names
        except (requests.RequestException, ValueError):
            return False

    def can_analyze(self) -> bool:
        return self.enable_ai and self.is_available() and self.model_installed()

    # -- generation ----------------------------------------------------------

    def generate(self, prompt: str, system: Optional[str] = None) -> str:
        self._truncated_once = False        # fresh retry allowance per call
        last_error = ""
        for attempt in (1, 2):
            try:
                return self._generate_once(prompt, system)
            except _TransientOllamaError as exc:
                last_error = str(exc)
                if attempt == 1 and self.retry_backoff > 0:
                    time.sleep(self.retry_backoff)
        raise OllamaNotAvailable(
            f"Ollama did not return a usable response after retries: {last_error}"
        )

    def _generate_once(self, prompt: str, system: Optional[str]) -> str:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": True,
            "options": {"num_predict": self._num_predict, "temperature": 0.2},
        }
        if system:
            payload["system"] = system
        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=(10, self.timeout),   # 10s connect; read = between tokens
                stream=True,
            )
        except requests.RequestException as exc:
            raise _TransientOllamaError(str(exc)) from exc

        try:
            if response.status_code != 200:
                raise self._http_error(response.status_code, response.text or "")

            parts = []
            for raw_line in response.iter_lines():
                if not raw_line:
                    continue
                if isinstance(raw_line, bytes):
                    raw_line = raw_line.decode("utf-8", errors="replace")
                try:
                    chunk = json.loads(raw_line)
                except ValueError:
                    continue  # tolerate one malformed line, keep the stream
                piece = chunk.get("response")
                if piece:
                    parts.append(piece)
                if chunk.get("done"):
                    if chunk.get("done_reason") == "length" and not self._truncated_once:
                        # Answer cut off at the token cap — the FIX section can
                        # be severed mid-sentence. Retry once with headroom.
                        self._truncated_once = True
                        self._num_predict = max(700, self._num_predict)  # at least 700, never lower
                        self._log.info("Answer hit the token cap — retrying with %d",
                                       self._num_predict)
                        raise _TransientOllamaError("truncated at token cap")
                    break
        except requests.RequestException as exc:
            raise _TransientOllamaError(str(exc)) from exc
        finally:
            response.close()

        text = "".join(parts).strip()
        if text:
            return text
        raise _TransientOllamaError("empty response")

    def _http_error(self, status_code: int, body: str) -> Exception:
        snippet = body[:300]
        try:
            data = json.loads(body)
            if isinstance(data, dict) and data.get("error"):
                snippet = str(data["error"])[:300]
        except ValueError:
            pass
        lowered = snippet.lower()
        if "not found" in lowered and "model" in lowered:
            # Guard: never let Ollama's implicit pull surprise the user.
            return AnalyzerError(
                f"Model '{self.model}' is not installed. Download it once with: "
                f"ollama pull {self.model}"
            )
        if status_code >= 500:
            return _TransientOllamaError(f"HTTP {status_code}: {snippet}")
        return AnalyzerError(f"Ollama returned HTTP {status_code}: {snippet}")

    # -- the explanation API used by the pipeline -----------------------------

    def explain(self, finding: Finding) -> Tuple[str, str]:
        """Returns (why_dangerous, how_to_fix) for one finding."""
        if not self.model_installed():
            raise AnalyzerError(
                f"AI model '{self.model}' is not reachable or not installed "
                "(Ollama may have stopped). Ensure `ollama serve` is running and "
                f"`ollama pull {self.model}` was executed."
            )

        # Ground the model in vetted guidance for this vulnerability class.
        reference_fix = ""
        try:
            _, reference_fix = fallback_explanation(finding)
        except Exception:
            reference_fix = ""

        started = time.monotonic()
        prompt = prompts.build_finding_prompt(finding, reference_fix=reference_fix)
        raw = self.generate(prompt, system=prompts.SYSTEM_PROMPT)
        sections = self._parse_sections(raw)
        why = _clean_text(sections.get("WHY", ""))
        attack = _clean_text(sections.get("ATTACK", ""))
        fix = _clean_text(sections.get("FIX", ""))
        if not why or not fix:
            raise AnalyzerError(
                "The model response did not contain the required sections."
            )

        notes = []
        if self._truncated_once:
            notes.append("resumed after token-cap retry")

        # Depth retry: one targeted second attempt when the FIX is too thin.
        if _fix_is_thin(fix):
            self._log.info("FIX section thin for '%s' — retrying for depth",
                           (finding.vulnerability_type or "?")[:60])
            try:
                raw2 = self.generate(prompt + prompts.FIX_DEPTH_ADDENDUM,
                                     system=prompts.SYSTEM_PROMPT)
                sections2 = self._parse_sections(raw2)
                fix2 = _clean_text(sections2.get("FIX", ""))
                why2 = _clean_text(sections2.get("WHY", ""))
                if why2 and len(fix2) > len(fix):
                    why, fix = why2, fix2
                    attack2 = _clean_text(sections2.get("ATTACK", ""))
                    attack = attack2 or attack
                    notes.append("deepened on retry")
            except AnalyzerError as exc:
                self._log.warning("Depth retry failed, keeping first answer: %s", exc)

        if attack:
            why = f"{why}\n\nAttacker impact: {attack}"
        elapsed = time.monotonic() - started
        suffix = f" ({', '.join(notes)})" if notes else ""
        self._log.info("Mistral explained '%s' in %.1fs%s",
                       (finding.vulnerability_type or "?")[:60], elapsed, suffix)
        return why, fix

    @staticmethod
    def _parse_sections(raw: str) -> Dict[str, str]:
        markers = list(_MARKER_RE.finditer(raw))
        if not markers:
            raise AnalyzerError("Unparseable model response (no section markers).")
        sections: Dict[str, str] = {}
        for index, marker in enumerate(markers):
            end = markers[index + 1].start() if index + 1 < len(markers) else len(raw)
            sections.setdefault(marker.group(1).upper(), raw[marker.end():end].strip())
        return sections
