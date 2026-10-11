"""Scanner registry — maps target types to scanner classes.

Import-order hardened: this module never imports scanner code at runtime
(only under TYPE_CHECKING for type hints), so it is safe to import from
anywhere — including from scanner modules while the scanners package is
still initializing. A previous runtime import of backend.scanners.base
created a circular-import window in which scanner modules could see a
partially initialized registry and silently fail to register.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Callable, Dict, List, Optional, Type

from backend.api.schemas import TargetType

if TYPE_CHECKING:  # for type checkers only — never executed at runtime
    from backend.scanners.base import BaseScanner, ProgressCallback


class ScannerRegistry:
    def __init__(self) -> None:
        self._scanners: Dict[TargetType, Type[BaseScanner]] = {}

    def register(self, target_type: TargetType) -> Callable[[Type[BaseScanner]], Type[BaseScanner]]:
        def decorator(scanner_cls: Type[BaseScanner]) -> Type[BaseScanner]:
            self._scanners[target_type] = scanner_cls
            return scanner_cls
        return decorator

    def has(self, target_type: TargetType) -> bool:
        return target_type in self._scanners

    def create(
        self,
        target_type: TargetType,
        target: str,
        progress: Optional[ProgressCallback] = None,
    ) -> Optional[BaseScanner]:
        scanner_cls = self._scanners.get(target_type)
        if scanner_cls is None:
            return None
        return scanner_cls(target, progress=progress)

    def registered_types(self) -> List[str]:
        return [t.value for t in self._scanners]


# Module-level singleton — scanner modules import THIS, never core.context,
# which keeps the import graph acyclic.
registry = ScannerRegistry()
