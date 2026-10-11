"""Secura FastAPI application entrypoint."""
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.api.routes import ai_settings, health, reports, scan, upload
from backend.config import settings
from backend.core.logger import configure_logging
from backend.exceptions import ReportNotFound, ValidationError, SecuraError

_STATUS_BY_ERROR = {
    ValidationError: 400,
    ReportNotFound: 404,
}


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings.ensure_dirs()
    logger = configure_logging()
    logger.info(
        "Secura backend v%s online at http://%s:%d",
        settings.app_version, settings.host, settings.port,
    )
    yield
    logger.info("Secura backend shutting down")


app = FastAPI(title="Secura", version=settings.app_version, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    # "null" covers the folder-picker component when the browser assigns
    # an opaque origin to the embedded iframe.
    allow_origins=["http://localhost:8501", "http://127.0.0.1:8501", "null"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.exception_handler(SecuraError)
async def secura_error_handler(_: Request, exc: SecuraError) -> JSONResponse:
    status_code = _STATUS_BY_ERROR.get(type(exc), 500)
    return JSONResponse(
        status_code=status_code,
        content={"error": type(exc).__name__, "detail": str(exc)},
    )


app.include_router(health.router)
app.include_router(scan.router)
app.include_router(upload.router)
app.include_router(reports.router)
app.include_router(ai_settings.router)


@app.get("/")
def root() -> dict:
    return {
        "service": "Secura",
        "version": settings.app_version,
        "docs": "/docs",
        "health": "/api/health",
    }
