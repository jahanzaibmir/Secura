"""Dependency records extracted from manifests and lockfiles."""
from __future__ import annotations

import re
from dataclasses import dataclass

ECOSYSTEM_PYPI = "PyPI"
ECOSYSTEM_NPM = "npm"
ECOSYSTEM_GO = "Go"
ECOSYSTEM_CARGO = "crates.io"
ECOSYSTEM_RUBY = "RubyGems"
ECOSYSTEM_PACKAGIST = "Packagist"


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str
    ecosystem: str
    manifest: str
    line: int | None = None

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.ecosystem, self.normalized_name, self.version)

    @property
    def normalized_name(self) -> str:
        if self.ecosystem == ECOSYSTEM_PYPI:
            return re.sub(r"[-_.]+", "-", self.name).lower()
        return self.name


def version_key(version: str) -> tuple:
    """A loose, total ordering for version strings (numeric parts compare as numbers)."""
    parts = re.split(r"[.\-+_]", version.lstrip("vV"))
    key = []
    for part in parts:
        match = re.match(r"^(\d+)(.*)$", part)
        if match:
            key.append((1, int(match.group(1)), match.group(2)))
        else:
            key.append((0, 0, part))
    return tuple(key)
