"""Runtime configuration.

Every value can be overridden through the environment. Canonical variables use
the ``SECURA_`` prefix; the legacy ``VW_`` names are still honoured so existing
deployments keep working.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path

from backend import __version__

BASE_DIR = Path(__file__).resolve().parent.parent


def _raw(*names: str) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value is not None and value.strip() != "":
            return value.strip()
    return None


def _str(default: str, *names: str) -> str:
    value = _raw(*names)
    return value if value is not None else default


def _int(default: int, *names: str, minimum: int = 0) -> int:
    value = _raw(*names)
    if value is None:
        return default
    try:
        return max(minimum, int(value))
    except ValueError:
        return default


def _bool(default: bool, *names: str) -> bool:
    value = _raw(*names)
    if value is None:
        return default
    return value.lower() in ("1", "true", "yes", "on")


def _csv(default: tuple[str, ...], *names: str) -> tuple[str, ...]:
    value = _raw(*names)
    if value is None:
        return default
    return tuple(item.strip() for item in value.split(",") if item.strip())


@dataclass(frozen=True)
class Settings:
    app_name: str = "Secura"
    version: str = __version__

    host: str = "127.0.0.1"
    port: int = 8642
    cors_origins: tuple[str, ...] = ("http://localhost:8501", "http://127.0.0.1:8501")

    data_dir: Path = field(default_factory=lambda: BASE_DIR / "data")

    allow_local_paths: bool = False
    max_concurrent_scans: int = 2
    max_queued_scans: int = 16
    max_stored_jobs: int = 100

    git_clone_timeout: int = 180
    bandit_timeout: int = 600
    max_findings: int = 500
    max_scan_file_bytes: int = 2_000_000

    upload_max_files: int = 5000
    upload_max_file_bytes: int = 10 * 1024 * 1024
    upload_max_total_bytes: int = 200 * 1024 * 1024

    dependency_audit: bool = True
    osv_api_url: str = "https://api.osv.dev"
    osv_timeout: int = 20

    ai_enabled: bool = True
    ai_provider: str = "ollama"
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "mistral:7b"
    ai_api_base: str = "https://api.mistral.ai/v1"
    ai_api_key: str = ""
    ai_api_model: str = "mistral-small-latest"
    ai_timeout: int = 240
    ai_max_findings: int = 5
    ai_max_tokens: int = 600

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def workspace_dir(self) -> Path:
        return self.data_dir / "workspace"

    @property
    def logs_dir(self) -> Path:
        return self.data_dir / "logs"

    def ensure_dirs(self) -> None:
        for directory in (self.reports_dir, self.workspace_dir, self.logs_dir):
            directory.mkdir(parents=True, exist_ok=True)

    def with_overrides(self, **changes) -> Settings:
        return replace(self, **changes)

    @classmethod
    def from_env(cls) -> Settings:
        defaults = cls()
        data_dir = _raw("SECURA_DATA_DIR")
        return cls(
            host=_str(defaults.host, "SECURA_HOST", "VW_HOST"),
            port=_int(defaults.port, "SECURA_PORT", "VW_PORT", minimum=1),
            cors_origins=_csv(defaults.cors_origins, "SECURA_CORS_ORIGINS"),
            data_dir=Path(data_dir).expanduser() if data_dir else defaults.data_dir,
            allow_local_paths=_bool(defaults.allow_local_paths, "SECURA_ALLOW_LOCAL_PATHS"),
            max_concurrent_scans=_int(defaults.max_concurrent_scans, "SECURA_MAX_CONCURRENT_SCANS", minimum=1),
            max_queued_scans=_int(defaults.max_queued_scans, "SECURA_MAX_QUEUED_SCANS", minimum=1),
            max_stored_jobs=_int(defaults.max_stored_jobs, "SECURA_MAX_JOBS", "VW_MAX_JOBS", minimum=1),
            git_clone_timeout=_int(defaults.git_clone_timeout, "SECURA_GIT_CLONE_TIMEOUT",
                                   "VW_GIT_CLONE_TIMEOUT", minimum=10),
            bandit_timeout=_int(defaults.bandit_timeout, "SECURA_BANDIT_TIMEOUT", "VW_BANDIT_TIMEOUT", minimum=10),
            max_findings=_int(defaults.max_findings, "SECURA_MAX_FINDINGS", "VW_MAX_FINDINGS", minimum=1),
            max_scan_file_bytes=_int(defaults.max_scan_file_bytes, "SECURA_MAX_SCAN_FILE_BYTES", minimum=1024),
            upload_max_files=_int(defaults.upload_max_files, "SECURA_UPLOAD_MAX_FILES", minimum=1),
            upload_max_file_bytes=_int(defaults.upload_max_file_bytes, "SECURA_UPLOAD_MAX_FILE_BYTES", minimum=1024),
            upload_max_total_bytes=_int(defaults.upload_max_total_bytes, "SECURA_UPLOAD_MAX_TOTAL_BYTES", minimum=1024),
            dependency_audit=_bool(defaults.dependency_audit, "SECURA_DEPENDENCY_AUDIT"),
            osv_api_url=_str(defaults.osv_api_url, "SECURA_OSV_API_URL").rstrip("/"),
            osv_timeout=_int(defaults.osv_timeout, "SECURA_OSV_TIMEOUT", minimum=1),
            ai_enabled=_bool(defaults.ai_enabled, "SECURA_AI_ENABLED", "VW_ENABLE_AI"),
            ai_provider=_str(defaults.ai_provider, "SECURA_AI_PROVIDER", "VW_AI_PROVIDER").lower(),
            ollama_url=_str(defaults.ollama_url, "SECURA_OLLAMA_URL", "VW_OLLAMA_URL").rstrip("/"),
            ollama_model=_str(defaults.ollama_model, "SECURA_OLLAMA_MODEL", "VW_MISTRAL_MODEL"),
            ai_api_base=_str(defaults.ai_api_base, "SECURA_AI_API_BASE", "VW_AI_API_BASE").rstrip("/"),
            ai_api_key=_str(defaults.ai_api_key, "SECURA_AI_API_KEY", "VW_AI_API_KEY"),
            ai_api_model=_str(defaults.ai_api_model, "SECURA_AI_API_MODEL", "VW_AI_API_MODEL"),
            ai_timeout=_int(defaults.ai_timeout, "SECURA_AI_TIMEOUT", "VW_ANALYZER_TIMEOUT", minimum=5),
            ai_max_findings=_int(defaults.ai_max_findings, "SECURA_AI_MAX_FINDINGS", "VW_MAX_AI_FINDINGS"),
            ai_max_tokens=_int(defaults.ai_max_tokens, "SECURA_AI_MAX_TOKENS", "VW_AI_MAX_TOKENS", minimum=64),
        )
