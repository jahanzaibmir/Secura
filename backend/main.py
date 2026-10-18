"""FastAPI application factory.

Run with ``uvicorn backend.main:create_app --factory`` or ``uvicorn backend.main:app``.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.errors import register_error_handlers
from backend.api.middleware import register_middleware
from backend.api.routes import api_router
from backend.config import Settings
from backend.core.container import build_container
from backend.core.logging import configure_logging


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    configure_logging(settings)
    container = build_container(settings)
    logger = logging.getLogger("secura")

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        logger.info("Secura %s ready on http://%s:%d", settings.version, settings.host, settings.port)
        yield
        container.shutdown()
        logger.info("Secura shut down")

    app = FastAPI(
        title="Secura",
        version=settings.version,
        summary="A security scanner that explains every finding.",
        lifespan=lifespan,
    )
    app.state.container = container

    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["*"],
    )
    register_middleware(app)
    register_error_handlers(app)
    app.include_router(api_router)

    @app.get("/", include_in_schema=False)
    def root() -> dict:
        return {"service": "Secura", "version": settings.version, "docs": "/docs", "health": "/api/health"}

    return app


def __getattr__(name: str):
    if name == "app":
        application = create_app()
        globals()["app"] = application
        return application
    raise AttributeError(name)
