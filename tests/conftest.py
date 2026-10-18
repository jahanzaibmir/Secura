"""Shared fixtures. Every test runs isolated from the developer's environment.

Configuration variables are cleared, data goes to a temporary directory, AI and
the online dependency audit are disabled, and outbound HTTP through ``requests``
is blocked unless a test installs its own fake. A local Ollama or a flaky
network can therefore never change a test result.
"""
from __future__ import annotations

import json
import os
from collections.abc import Callable, Iterable
from pathlib import Path

import pytest
import requests

from backend.config import Settings


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch, tmp_path):
    for name in list(os.environ):
        if name.startswith(("SECURA_", "VW_")):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SECURA_DATA_DIR", str(tmp_path / "env-data"))
    monkeypatch.setenv("SECURA_AI_ENABLED", "0")
    monkeypatch.setenv("SECURA_DEPENDENCY_AUDIT", "0")

    def blocked(self, request, **kwargs):
        raise requests.ConnectionError(f"Network access is blocked in tests: {request.url}")

    monkeypatch.setattr(requests.sessions.Session, "send", blocked)


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        data_dir=tmp_path / "data",
        ai_enabled=False,
        dependency_audit=False,
        max_concurrent_scans=1,
    )


@pytest.fixture
def make_tree(tmp_path) -> Callable[[dict[str, str]], Path]:
    def build(files: dict[str, str], name: str = "project") -> Path:
        root = tmp_path / name
        root.mkdir(parents=True, exist_ok=True)
        for rel, content in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        return root
    return build


class FakeResponse:
    """A minimal stand-in for ``requests.Response``."""

    def __init__(self, status_code: int = 200, payload=None, text: str = "",
                 lines: Iterable | None = None) -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = text if text else (json.dumps(payload) if payload is not None else "")
        self._lines: list = list(lines or [])

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload

    def iter_lines(self):
        yield from self._lines

    def close(self) -> None:
        pass


@pytest.fixture
def fake_response():
    return FakeResponse
