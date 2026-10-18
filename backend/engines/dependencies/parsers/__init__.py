"""Manifest parser registry keyed by file name."""
from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import PurePosixPath

from backend.engines.dependencies.models import Dependency
from backend.engines.dependencies.parsers import node, other, python

logger = logging.getLogger("secura.engines.dependencies")

Parser = Callable[[str, str], list[Dependency]]

_BY_NAME: dict[str, Parser] = {
    "pipfile.lock": python.parse_pipfile_lock,
    "poetry.lock": python.parse_toml_lock,
    "uv.lock": python.parse_toml_lock,
    "package-lock.json": node.parse_package_lock,
    "npm-shrinkwrap.json": node.parse_package_lock,
    "yarn.lock": node.parse_yarn_lock,
    "pnpm-lock.yaml": node.parse_pnpm_lock,
    "package.json": node.parse_package_json,
    "go.sum": other.parse_go_sum,
    "cargo.lock": other.parse_cargo_lock,
    "gemfile.lock": other.parse_gemfile_lock,
    "composer.lock": other.parse_composer_lock,
}

_NODE_LOCKS = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")


def parser_for(rel_path: str) -> Parser | None:
    name = PurePosixPath(rel_path).name.lower()
    if name.startswith("requirements") and name.endswith(".txt"):
        return python.parse_requirements
    return _BY_NAME.get(name)


def has_sibling_lock(rel_path: str, all_paths: list[str]) -> bool:
    """True when a package.json sits next to a lockfile, which is more precise."""
    parent = PurePosixPath(rel_path).parent
    siblings = {PurePosixPath(p).name.lower() for p in all_paths if PurePosixPath(p).parent == parent}
    return any(lock in siblings for lock in _NODE_LOCKS)


def parse_manifest(rel_path: str, text: str) -> list[Dependency]:
    parser = parser_for(rel_path)
    if parser is None:
        return []
    try:
        return parser(text, rel_path)
    except Exception as exc:
        logger.info("Could not parse %s: %s", rel_path, exc)
        return []
