"""Security engines. Each one analyses a different class of risk in the source tree."""
from __future__ import annotations

from backend.engines.bandit import BanditEngine
from backend.engines.base import Engine, EngineContext, EngineResult
from backend.engines.dependencies import DependencyEngine
from backend.engines.docker import DockerfileEngine
from backend.engines.javascript import JavaScriptEngine
from backend.engines.secrets import SecretsEngine


def default_engines() -> list[Engine]:
    return [
        BanditEngine(),
        JavaScriptEngine(),
        SecretsEngine(),
        DependencyEngine(),
        DockerfileEngine(),
    ]


__all__ = ["Engine", "EngineContext", "EngineResult", "default_engines"]
