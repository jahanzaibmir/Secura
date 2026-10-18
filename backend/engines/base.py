"""Engine contract: a self-contained analyser that turns an inventory into findings."""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from backend.config import Settings
from backend.core.cancellation import CancelToken
from backend.engines.inventory import Inventory
from backend.schemas import EngineInfo, Finding


@dataclass
class EngineContext:
    root: Path
    inventory: Inventory
    settings: Settings
    token: CancelToken
    progress: Callable[[str, float], None] = lambda detail, fraction: None


@dataclass
class EngineResult:
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    detail: str = ""


class Engine(ABC):
    name: ClassVar[str]
    label: ClassVar[str]
    description: ClassVar[str]

    def availability(self, settings: Settings) -> tuple[bool, str]:
        """Whether the engine can run in this environment, with a reason if not."""
        return True, ""

    @abstractmethod
    def applies(self, inventory: Inventory) -> bool:
        """Whether the inventory contains anything this engine analyses."""

    @abstractmethod
    def run(self, context: EngineContext) -> EngineResult:
        """Analyses the source tree and returns findings."""

    def info(self, settings: Settings) -> EngineInfo:
        available, detail = self.availability(settings)
        return EngineInfo(
            name=self.name, label=self.label, description=self.description,
            available=available, detail=detail,
        )


def trim_snippet(lines: list[str], line_number: int, radius: int = 1, width: int = 240) -> str:
    """Returns the numbered source lines around ``line_number`` (1-based)."""
    if not lines or line_number < 1:
        return ""
    start = max(1, line_number - radius)
    end = min(len(lines), line_number + radius)
    pad = len(str(end))
    out = []
    for number in range(start, end + 1):
        text = lines[number - 1].rstrip()
        if len(text) > width:
            text = text[: width - 1] + "…"
        out.append(f"{str(number).rjust(pad)}  {text}")
    return "\n".join(out)


def optional_int(value) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None
