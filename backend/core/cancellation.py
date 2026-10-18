"""Cooperative cancellation shared between the API and a running scan."""
from __future__ import annotations

import threading

from backend.exceptions import ScanCancelled


class CancelToken:
    """A thread-safe flag that long-running work polls between steps."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def raise_if_cancelled(self) -> None:
        if self._event.is_set():
            raise ScanCancelled("The scan was cancelled.")

    def wait(self, seconds: float) -> bool:
        """Sleep up to ``seconds``; returns True if cancellation arrived meanwhile."""
        return self._event.wait(seconds)
