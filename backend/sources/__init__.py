"""Source providers: where the code to scan comes from."""
from __future__ import annotations

from backend.exceptions import ValidationError
from backend.schemas import TargetType
from backend.sources.base import Source, SourceContext
from backend.sources.github import GitHubSource
from backend.sources.local import LocalSource


class SourceRegistry:
    def __init__(self) -> None:
        self._sources: dict[TargetType, Source] = {}

    def register(self, source: Source) -> None:
        for target_type in source.target_types:
            self._sources[target_type] = source

    def get(self, target_type: TargetType) -> Source:
        source = self._sources.get(target_type)
        if source is None:
            raise ValidationError(f"No source is registered for '{target_type.value}'.")
        return source

    def types(self) -> list[str]:
        return [target_type.value for target_type in self._sources]


def build_source_registry() -> SourceRegistry:
    registry = SourceRegistry()
    registry.register(GitHubSource())
    registry.register(LocalSource())
    return registry


__all__ = ["Source", "SourceContext", "SourceRegistry", "build_source_registry"]
