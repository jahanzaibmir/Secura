"""Python manifests: requirements files, Pipfile.lock, poetry.lock and uv.lock."""
from __future__ import annotations

import json
import re

from backend.engines.dependencies.models import ECOSYSTEM_PYPI, Dependency

try:
    import tomllib
except ModuleNotFoundError:
    tomllib = None

_REQUIREMENT_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)"
)


def parse_requirements(text: str, manifest: str) -> list[Dependency]:
    deps: list[Dependency] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http:", "https:", "file:")):
            continue
        line = line.split(";", 1)[0].strip()
        match = _REQUIREMENT_RE.match(line)
        if match:
            deps.append(Dependency(match.group(1), match.group(2), ECOSYSTEM_PYPI, manifest, number))
    return deps


def parse_pipfile_lock(text: str, manifest: str) -> list[Dependency]:
    data = json.loads(text)
    deps: list[Dependency] = []
    for section in ("default", "develop"):
        for name, spec in (data.get(section) or {}).items():
            version = str((spec or {}).get("version", ""))
            if version.startswith("=="):
                deps.append(Dependency(name, version[2:], ECOSYSTEM_PYPI, manifest))
    return deps


def parse_toml_lock(text: str, manifest: str) -> list[Dependency]:
    """Shared by poetry.lock and uv.lock, which both list [[package]] tables."""
    if tomllib is None:
        return []
    data = tomllib.loads(text)
    deps: list[Dependency] = []
    for package in data.get("package") or []:
        name, version = package.get("name"), package.get("version")
        source = package.get("source") or {}
        if not name or not version:
            continue
        if isinstance(source, dict) and any(k in source for k in ("editable", "virtual", "path", "directory")):
            continue
        deps.append(Dependency(str(name), str(version), ECOSYSTEM_PYPI, manifest))
    return deps
