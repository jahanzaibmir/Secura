"""Folders that already exist on disk: local paths and materialised uploads."""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from backend.exceptions import SourceError
from backend.schemas import TargetType
from backend.sources.base import Source, SourceContext


class LocalSource(Source):
    target_types = (TargetType.LOCAL_PATH, TargetType.UPLOAD)
    label = "Local folder"

    @contextmanager
    def open(self, target: str, context: SourceContext) -> Iterator[Path]:
        root = Path(target)
        if not root.is_dir():
            raise SourceError(f"The folder is no longer available: {root.name}")
        context.progress("Folder ready", 1.0)
        yield root
