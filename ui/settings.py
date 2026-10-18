"""Interface configuration, read from the environment once."""
from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlparse


def _first(*names: str) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value and value.strip():
            return value.strip()
    return None


@dataclass(frozen=True)
class UISettings:
    api_url: str
    public_api_url: str | None
    request_timeout: int = 20
    poll_seconds: float = 1.0

    @classmethod
    def from_env(cls) -> UISettings:
        port = _first("SECURA_PORT", "VW_PORT") or "8642"
        api_url = (_first("SECURA_API_URL", "VW_API_URL") or f"http://127.0.0.1:{port}").rstrip("/")
        public = _first("SECURA_PUBLIC_API_URL", "VW_PUBLIC_API_URL")
        if public is None and (urlparse(api_url).hostname or "") in ("127.0.0.1", "localhost"):
            public = api_url
        return cls(api_url=api_url, public_api_url=public.rstrip("/") if public else None)


SETTINGS = UISettings.from_env()
