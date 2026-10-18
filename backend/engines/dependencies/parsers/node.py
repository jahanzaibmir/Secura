"""Node manifests: package-lock.json, yarn.lock, pnpm-lock.yaml and package.json."""
from __future__ import annotations

import json
import re

from backend.engines.dependencies.models import ECOSYSTEM_NPM, Dependency

_EXACT_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
_YARN_VERSION_RE = re.compile(r"^\s+version:?\s+\"?([^\"\s]+)\"?")
_PNPM_KEY_RE = re.compile(r"^\s{2}['\"]?/?((?:@[^/@\s'\"]+/)?[^@\s'\"/(]+)@([0-9][^(:'\"\s]*)")


def parse_package_lock(text: str, manifest: str) -> list[Dependency]:
    data = json.loads(text)
    deps: list[Dependency] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, spec in packages.items():
            if not path or not isinstance(spec, dict) or spec.get("link"):
                continue
            name = spec.get("name") or path.rsplit("node_modules/", 1)[-1]
            version = str(spec.get("version", ""))
            if name and _EXACT_RE.match(version):
                deps.append(Dependency(name, version, ECOSYSTEM_NPM, manifest))
        return deps

    def walk(tree: dict) -> None:
        for name, spec in (tree or {}).items():
            if not isinstance(spec, dict):
                continue
            version = str(spec.get("version", ""))
            if _EXACT_RE.match(version):
                deps.append(Dependency(name, version, ECOSYSTEM_NPM, manifest))
            walk(spec.get("dependencies") or {})

    walk(data.get("dependencies") or {})
    return deps


def parse_yarn_lock(text: str, manifest: str) -> list[Dependency]:
    deps: list[Dependency] = []
    names: list[str] = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw.startswith(" ") and raw.rstrip().endswith(":"):
            names = []
            for spec in raw.rstrip()[:-1].split(","):
                spec = spec.strip().strip('"')
                if not spec or spec == "__metadata":
                    continue
                name = spec.rsplit("@", 1)[0] if spec.rfind("@") > 0 else spec
                names.append(name)
            continue
        match = _YARN_VERSION_RE.match(raw)
        if match and names:
            version = match.group(1)
            if _EXACT_RE.match(version):
                for name in dict.fromkeys(names):
                    deps.append(Dependency(name, version, ECOSYSTEM_NPM, manifest))
            names = []
    return deps


def parse_pnpm_lock(text: str, manifest: str) -> list[Dependency]:
    deps: list[Dependency] = []
    in_packages = False
    for raw in text.splitlines():
        if raw.startswith(("packages:", "snapshots:")):
            in_packages = raw.startswith("packages:")
            continue
        if raw and not raw.startswith(" "):
            in_packages = False
            continue
        if in_packages:
            match = _PNPM_KEY_RE.match(raw)
            if match and _EXACT_RE.match(match.group(2)):
                deps.append(Dependency(match.group(1), match.group(2), ECOSYSTEM_NPM, manifest))
    return deps


def parse_package_json(text: str, manifest: str) -> list[Dependency]:
    data = json.loads(text)
    deps: list[Dependency] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, version in (data.get(section) or {}).items():
            cleaned = str(version).strip().lstrip("=v")
            if _EXACT_RE.match(cleaned):
                deps.append(Dependency(name, cleaned, ECOSYSTEM_NPM, manifest))
    return deps
