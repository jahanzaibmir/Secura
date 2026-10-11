"""Scanner contract — shared behaviour for all scanners."""
from abc import ABC, abstractmethod
from typing import Callable, ClassVar, List, Optional

from backend.api.schemas import Finding, TargetType

# (detail_message, progress_percent) reported by scanners mid-scan
ProgressCallback = Callable[[str, int], None]


class BaseScanner(ABC):
    target_type: ClassVar[TargetType]
    name: ClassVar[str] = "scanner"

    def __init__(self, target: str, progress: Optional[ProgressCallback] = None) -> None:
        self.target = target
        self.notes: List[str] = []        # surfaced into the report by the pipeline
        self._progress = progress if progress is not None else (lambda detail, pct: None)

    def report_progress(self, detail: str, pct: int = 0) -> None:
        self._progress(detail, pct)

    def add_note(self, note: str) -> None:
        self.notes.append(note)

    @abstractmethod
    def scan(self) -> List[Finding]:
        """Run the scan and return raw findings (no AI enrichment)."""
        raise NotImplementedError
