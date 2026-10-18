"""Consistent JSON error responses: ``{"error": <name>, "detail": <message>}``."""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from backend.exceptions import SecuraError

logger = logging.getLogger("secura.api")


def _body(error: str, detail: str) -> dict:
    return {"error": error, "detail": detail}


def _validation_message(exc: RequestValidationError) -> str:
    messages = []
    for item in exc.errors()[:3]:
        location = ".".join(str(part) for part in item.get("loc", ()) if part != "body")
        message = item.get("msg", "invalid value")
        messages.append(f"{location}: {message}" if location else message)
    return "; ".join(messages) or "Invalid request."


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(SecuraError)
    async def handle_secura_error(_: Request, exc: SecuraError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content=_body(type(exc).__name__, str(exc)))

    @app.exception_handler(RequestValidationError)
    async def handle_validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(status_code=422, content=_body("RequestValidationError", _validation_message(exc)))

    @app.exception_handler(StarletteHTTPException)
    async def handle_http(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content=_body("HTTPException", str(exc.detail)),
                            headers=getattr(exc, "headers", None))

    @app.exception_handler(Exception)
    async def handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(status_code=500, content=_body("InternalError", "An unexpected error occurred."))
