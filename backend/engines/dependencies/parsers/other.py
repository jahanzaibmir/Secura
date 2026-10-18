"""Go, Rust, Ruby and PHP lockfiles."""
from __future__ import annotations

import json
import re

from backend.engines.dependencies.models import (
    ECOSYSTEM_CARGO,
    ECOSYSTEM_GO,
    ECOSYSTEM_PACKAGIST,
    ECOSYSTEM_RUBY,
    Dependency,
)

try:
    import tomllib
except ModuleNotFoundError:
    tomllib = None

_GEM_RE = re.compile(r"^ {4}([A-Za-z0-9_.-]+) \(([0-9][^)\s]*)\)$")


def parse_go_sum(text: str, manifest: str) -> list[Dependency]:
    seen = set()
    deps: list[Dependency] = []
    for raw in text.splitlines():
        parts = raw.split()
        if len(parts) < 2:
            continue
        module, version = parts[0], parts[1].split("/", 1)[0]
        version = version.replace("+incompatible", "").lstrip("v")
        if (module, version) in seen:
            continue
        seen.add((module, version))
        deps.append(Dependency(module, version, ECOSYSTEM_GO, manifest))
    return deps


def parse_cargo_lock(text: str, manifest: str) -> list[Dependency]:
    if tomllib is None:
        return []
    data = tomllib.loads(text)
    deps: list[Dependency] = []
    for package in data.get("package") or []:
        source = str(package.get("source", ""))
        if package.get("name") and package.get("version") and "crates.io" in source:
            deps.append(Dependency(package["name"], package["version"], ECOSYSTEM_CARGO, manifest))
    return deps


def parse_gemfile_lock(text: str, manifest: str) -> list[Dependency]:
    deps: list[Dependency] = []
    in_specs = False
    for number, raw in enumerate(text.splitlines(), start=1):
        if raw.strip() == "specs:":
            in_specs = True
            continue
        if raw and not raw.startswith(" "):
            in_specs = False
            continue
        if in_specs:
            match = _GEM_RE.match(raw)
            if match:
                deps.append(Dependency(match.group(1), match.group(2), ECOSYSTEM_RUBY, manifest, number))
    return deps


def parse_composer_lock(text: str, manifest: str) -> list[Dependency]:
    data = json.loads(text)
    deps: list[Dependency] = []
    for section in ("packages", "packages-dev"):
        for package in data.get(section) or []:
            name, version = package.get("name"), str(package.get("version", "")).lstrip("v")
            if name and version and version[0].isdigit():
                deps.append(Dependency(name, version, ECOSYSTEM_PACKAGIST, manifest))
    return deps
