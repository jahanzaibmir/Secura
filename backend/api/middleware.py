"""Request context: request ids, timing, and baseline security headers."""
from __future__ import annotations

import logging
import time
import uuid

from fastapi import FastAPI, Request

logger = logging.getLogger("secura.http")

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def register_middleware(app: FastAPI) -> None:
    @app.middleware("http")
    async def request_context(request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:16]
        started = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = (time.perf_counter() - started) * 1000
        response.headers["X-Request-ID"] = request_id
        response.headers["Server-Timing"] = f"app;dur={elapsed_ms:.1f}"
        for header, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        if elapsed_ms > 2000:
            logger.info("%s %s took %.0f ms", request.method, request.url.path, elapsed_ms)
        return response
