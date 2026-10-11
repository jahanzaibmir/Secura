"""Scanner package — importing a module registers its scanner.

Each scanner module registers itself against the shared registry
(backend.core.registry.registry) via @registry.register(TargetType.X).
A missing optional dependency degrades gracefully: the scanner stays
unregistered and the pipeline reports it honestly. A module that imports
cleanly but registers nothing (a truncated or empty file) is surfaced
as a warning instead of failing silently.
"""
import importlib
import logging

from backend.core.registry import registry

log = logging.getLogger("secura.scanners")

_MODULES = ("code_scanner",)

for _name in _MODULES:
    _before = len(registry.registered_types())
    try:
        importlib.import_module(f"backend.scanners.{_name}")
    except ImportError as exc:
        log.warning(
            "Scanner module '%s' unavailable (%s). "
            "Install dependencies with: pip install -r requirements.txt",
            _name, exc,
        )
        continue
    if len(registry.registered_types()) == _before:
        log.warning(
            "Scanner module '%s' imported but registered no scanner — "
            "the file is likely truncated or empty. Re-paste its full content.",
            _name,
        )
