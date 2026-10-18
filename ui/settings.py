"""Interface configuration, read from the environment once."""
from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlparse

_LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def _first(*names: str) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value and value.strip():
            return value.strip()
    return None


def _hostname(host_header: str) -> str:
    """Extracts the hostname from a Host header value such as ``example.com:8501`` or ``[::1]:8501``."""
    value = (host_header or "").strip().lower()
    if value.startswith("["):
        return value[1:].split("]", 1)[0]
    return value.rsplit(":", 1)[0] if value.count(":") == 1 else value


@dataclass(frozen=True)
class UISettings:
    api_url: str
    public_api_url: str | None = None
    request_timeout: int = 20
    poll_seconds: float = 1.0

    @property
    def api_is_local(self) -> bool:
        return (urlparse(self.api_url).hostname or "") in _LOCAL_HOSTS

    def browser_api_url(self, viewer_host: str) -> str | None:
        """The API origin the viewer's browser can open directly, or None.

        A loopback API is only reachable when the viewer is on the same machine;
        hosted deployments need ``SECURA_PUBLIC_API_URL`` to offer browser links.
        """
        if self.public_api_url:
            return self.public_api_url
        if self.api_is_local and _hostname(viewer_host) in _LOCAL_HOSTS:
            return self.api_url
        return None

    @classmethod
    def from_env(cls) -> UISettings:
        port = _first("SECURA_PORT", "VW_PORT") or "8642"
        api_url = (_first("SECURA_API_URL", "VW_API_URL") or f"http://127.0.0.1:{port}").rstrip("/")
        public = _first("SECURA_PUBLIC_API_URL", "VW_PUBLIC_API_URL")
        return cls(api_url=api_url, public_api_url=public.rstrip("/") if public else None)


SETTINGS = UISettings.from_env()
