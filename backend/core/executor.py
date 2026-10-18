"""Bounded worker pool for scans.

Scans are CPU and I/O heavy (git clones, Bandit subprocesses, model calls), so
they run on a small dedicated pool instead of the web server's request threads.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor

logger = logging.getLogger("secura.executor")


class ScanExecutor:
    def __init__(self, max_workers: int) -> None:
        self._pool = ThreadPoolExecutor(
            max_workers=max(1, max_workers), thread_name_prefix="secura-scan",
        )

    def submit(self, fn: Callable[..., None], *args) -> Future:
        future = self._pool.submit(fn, *args)
        future.add_done_callback(self._log_failure)
        return future

    def shutdown(self, wait: bool = False) -> None:
        self._pool.shutdown(wait=wait, cancel_futures=True)

    @staticmethod
    def _log_failure(future: Future) -> None:
        if future.cancelled():
            return
        error = future.exception()
        if error is not None:
            logger.error("Scan worker crashed", exc_info=error)
