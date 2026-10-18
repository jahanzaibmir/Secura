"""Analyzer contract and the provider-independent explanation logic.

Concrete analyzers only implement transport (``_complete``) and readiness probing.
All retry state is local to each call, so one analyzer instance can safely serve
many scans and many threads at once.
"""
from __future__ import annotations

import logging
import threading
import time
from abc import ABC, abstractmethod
from collections import OrderedDict
from dataclasses import dataclass

from backend.ai import prompts
from backend.ai.knowledge import explain_from_knowledge
from backend.ai.text import clean_text, fix_is_thin, parse_sections
from backend.exceptions import AnalyzerError, AnalyzerUnavailable
from backend.schemas import Finding

logger = logging.getLogger("secura.ai")


class TransientAnalyzerError(Exception):
    """A failure worth exactly one retry: timeouts, rate limits, 5xx, empty output."""


@dataclass(frozen=True)
class Generation:
    text: str
    truncated: bool = False


@dataclass(frozen=True)
class Readiness:
    ready: bool
    message: str


class _TTLValue:
    def __init__(self, ttl: float) -> None:
        self._ttl = ttl
        self._lock = threading.Lock()
        self._stamp = 0.0
        self._value = None

    def get(self, compute):
        now = time.monotonic()
        with self._lock:
            if self._value is not None and now - self._stamp < self._ttl:
                return self._value
        value = compute()
        with self._lock:
            self._value, self._stamp = value, time.monotonic()
        return value

    def clear(self) -> None:
        with self._lock:
            self._value = None


class BaseAnalyzer(ABC):
    provider: str = ""
    max_concurrency: int = 1
    _CACHE_SIZE = 256

    def __init__(
        self,
        model: str,
        enabled: bool = True,
        max_tokens: int = 600,
        timeout: int = 240,
        retry_backoff: float = 1.5,
        readiness_ttl: float = 10.0,
    ) -> None:
        self.model = model
        self.enabled = enabled
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.retry_backoff = retry_backoff
        self._readiness = _TTLValue(readiness_ttl)
        self._explanations: OrderedDict[tuple, tuple[str, str]] = OrderedDict()
        self._explanations_lock = threading.Lock()

    @property
    @abstractmethod
    def provider_label(self) -> str:
        """Human-readable provider name."""

    @abstractmethod
    def _probe_readiness(self) -> Readiness:
        """Checks reachability and model availability. Called at most once per TTL."""

    @abstractmethod
    def _complete(self, prompt: str, system: str | None, max_tokens: int) -> Generation:
        """Performs one completion. Raises TransientAnalyzerError or AnalyzerError."""

    def readiness(self) -> Readiness:
        if not self.enabled:
            return Readiness(False, "AI explanations are disabled (SECURA_AI_ENABLED=0).")
        return self._readiness.get(self._probe_readiness)

    def refresh(self) -> None:
        self._readiness.clear()

    def can_analyze(self) -> bool:
        return self.readiness().ready

    def generate(self, prompt: str, system: str | None = None) -> str:
        budget = self.max_tokens
        retried_transient = False
        retried_truncation = False
        while True:
            try:
                generation = self._complete(prompt, system, budget)
            except TransientAnalyzerError as exc:
                if retried_transient:
                    raise AnalyzerUnavailable(
                        f"{self.provider_label} did not return a usable response: {exc}") from exc
                retried_transient = True
                if self.retry_backoff > 0:
                    time.sleep(self.retry_backoff)
                continue
            if generation.truncated and not retried_truncation:
                retried_truncation = True
                budget = max(budget + budget // 2, 900)
                logger.info("Answer hit the token cap; retrying with %d tokens", budget)
                continue
            if not generation.text.strip():
                if retried_transient:
                    raise AnalyzerUnavailable(f"{self.provider_label} returned an empty response.")
                retried_transient = True
                continue
            return generation.text

    def explain(self, finding: Finding) -> tuple[str, str]:
        """Returns (why_dangerous, how_to_fix) for one finding."""
        cache_key = (self.model, finding.rule_id, finding.title, finding.snippet, finding.description)
        with self._explanations_lock:
            cached = self._explanations.get(cache_key)
            if cached is not None:
                self._explanations.move_to_end(cache_key)
                return cached

        started = time.monotonic()
        _, reference = explain_from_knowledge(finding)
        prompt = prompts.build_finding_prompt(finding, reference_fix=reference)
        sections = parse_sections(self.generate(prompt, system=prompts.SYSTEM_PROMPT))
        why = clean_text(sections.get("WHY", ""))
        attack = clean_text(sections.get("ATTACK", ""))
        fix = clean_text(sections.get("FIX", ""))
        if not why or not fix:
            raise AnalyzerError("The model response did not contain the required sections.")

        if fix_is_thin(fix):
            try:
                retry = parse_sections(self.generate(
                    prompt + prompts.FIX_DEPTH_ADDENDUM, system=prompts.SYSTEM_PROMPT))
                deeper_fix = clean_text(retry.get("FIX", ""))
                deeper_why = clean_text(retry.get("WHY", ""))
                if deeper_why and len(deeper_fix) > len(fix):
                    why, fix = deeper_why, deeper_fix
                    attack = clean_text(retry.get("ATTACK", "")) or attack
            except AnalyzerError as exc:
                logger.info("Depth retry failed; keeping the first answer: %s", exc)

        if attack:
            why = f"{why}\n\nImpact: {attack}"
        logger.info("%s explained '%s' in %.1fs", self.model, finding.title[:60],
                    time.monotonic() - started)

        with self._explanations_lock:
            self._explanations[cache_key] = (why, fix)
            while len(self._explanations) > self._CACHE_SIZE:
                self._explanations.popitem(last=False)
        return why, fix
