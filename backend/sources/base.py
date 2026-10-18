"""Source contract: turns a validated target into a directory on disk."""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from backend.config import Settings
from backend.core.cancellation import CancelToken
from backend.schemas import TargetType

ProgressFn = Callable[[str, float], None]


@dataclass
class SourceContext:
    settings: Settings
    token: CancelToken
    progress: ProgressFn


class Source(ABC):
    target_types: ClassVar[tuple[TargetType, ...]]
    label: ClassVar[str]

    @abstractmethod
    def open(self, target: str, context: SourceContext) -> AbstractContextManager[Path]:
        """Yields the root directory to scan and releases it on exit."""
