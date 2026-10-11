"""Secura — central configuration. Every value is env-overridable."""
import os
from dataclasses import dataclass
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent  # project root


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    app_name: str = "Secura"
    app_version: str = "1.6.0"

    host: str = "127.0.0.1"
    port: int = 8642

    # --- ai provider ---
    # Startup default only — users switch providers at runtime via the
    # AI Setup page (POST /api/settings/ai), no restart needed.
    # "ollama": local, private, no key — findings never leave the machine.
    # "openai": any OpenAI-compatible chat API (Mistral, Groq, OpenRouter,
    #           OpenAI, vLLM...) — fast, but finding text goes to the provider.
    ai_provider: str = "ollama"
    ollama_base_url: str = "http://127.0.0.1:11434"
    mistral_model: str = "mistral:7b"
    ai_api_base: str = "https://api.mistral.ai/v1"
    ai_api_key: str = ""                    # VW_AI_API_KEY — never hardcode
    ai_api_model: str = "mistral-small-latest"
    # Read-timeout BETWEEN streamed tokens (ollama) / request timeout (api).
    analyzer_timeout: int = 240

    reports_dir: Path = BASE_DIR / "reports"
    workspace_dir: Path = BASE_DIR / "workspace"
    logs_dir: Path = BASE_DIR / "logs"

    max_stored_jobs: int = 50
    scan_timeout: int = 1800             # UI-side ceiling for one scan

    # --- network scanning ---
    nmap_top_ports: int = 200
    nmap_host_timeout: int = 240
    http_timeout_connect: int = 10
    http_timeout_read: int = 20
    http_max_body_bytes: int = 2_000_000

    # --- code scanning ---
    git_clone_timeout: int = 120
    bandit_timeout: int = 600
    max_findings_per_scan: int = 250

    # --- ai analysis ---
    enable_ai: bool = True
    max_ai_findings: int = 5
    ai_max_tokens: int = 550

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            host=os.getenv("VW_HOST", "127.0.0.1"),
            port=_env_int("VW_PORT", 8642),
            ai_provider=os.getenv("VW_AI_PROVIDER", "ollama").strip().lower(),
            ollama_base_url=os.getenv("VW_OLLAMA_URL", "http://127.0.0.1:11434"),
            mistral_model=os.getenv("VW_MISTRAL_MODEL", "mistral:7b"),
            ai_api_base=os.getenv("VW_AI_API_BASE", "https://api.mistral.ai/v1").rstrip("/"),
            ai_api_key=os.getenv("VW_AI_API_KEY", ""),
            ai_api_model=os.getenv("VW_AI_API_MODEL", "mistral-small-latest"),
            analyzer_timeout=_env_int("VW_ANALYZER_TIMEOUT", 240),
            scan_timeout=_env_int("VW_SCAN_TIMEOUT", 1800),
            max_stored_jobs=_env_int("VW_MAX_JOBS", 50),
            nmap_top_ports=_env_int("VW_NMAP_TOP_PORTS", 200),
            nmap_host_timeout=_env_int("VW_NMAP_HOST_TIMEOUT", 240),
            http_timeout_connect=_env_int("VW_HTTP_TIMEOUT_CONNECT", 10),
            http_timeout_read=_env_int("VW_HTTP_TIMEOUT_READ", 20),
            http_max_body_bytes=_env_int("VW_HTTP_MAX_BODY_BYTES", 2_000_000),
            git_clone_timeout=_env_int("VW_GIT_CLONE_TIMEOUT", 120),
            bandit_timeout=_env_int("VW_BANDIT_TIMEOUT", 600),
            max_findings_per_scan=_env_int("VW_MAX_FINDINGS", 250),
            enable_ai=_env_bool("VW_ENABLE_AI", True),
            max_ai_findings=_env_int("VW_MAX_AI_FINDINGS", 5),
            ai_max_tokens=_env_int("VW_AI_MAX_TOKENS", 550),
        )

    def ensure_dirs(self) -> None:
        for directory in (self.reports_dir, self.workspace_dir, self.logs_dir):
            directory.mkdir(parents=True, exist_ok=True)


settings = Settings.from_env()
