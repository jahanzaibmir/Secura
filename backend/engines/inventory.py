"""File inventory: one walk over the source tree, shared by every engine.

The same relevance policy decides which uploaded files are kept, so the upload
filter and the scanners can never disagree about what is worth reading.
"""
from __future__ import annotations

import os
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from backend.core.cancellation import CancelToken

EXCLUDED_DIRS = frozenset({
    ".git", ".hg", ".svn", "__pycache__", "node_modules", "bower_components",
    "jspm_packages", "venv", ".venv", "env", ".tox", ".nox", ".eggs", "dist",
    "build", "site-packages", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".idea", ".vscode", ".next", ".nuxt", ".svelte-kit", ".turbo", ".cache",
    "coverage", ".gradle", ".terraform", "Pods", "DerivedData",
})
ALLOWED_DOT_DIRS = frozenset({".github", ".circleci", ".gitlab", ".devcontainer"})

LANGUAGES: dict[str, str] = {
    ".py": "Python", ".pyw": "Python",
    ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".mts": "TypeScript", ".cts": "TypeScript",
    ".vue": "JavaScript", ".svelte": "JavaScript",
    ".go": "Go", ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin", ".scala": "Scala",
    ".rb": "Ruby", ".php": "PHP", ".cs": "C#", ".rs": "Rust", ".swift": "Swift",
    ".c": "C/C++", ".h": "C/C++", ".cc": "C/C++", ".cpp": "C/C++", ".hpp": "C/C++",
    ".sh": "Shell", ".bash": "Shell", ".zsh": "Shell", ".ps1": "PowerShell",
    ".sql": "SQL", ".html": "HTML", ".htm": "HTML",
}

CONFIG_SUFFIXES = frozenset({
    ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".properties",
    ".xml", ".tf", ".tfvars", ".hcl", ".gradle", ".env", ".lock", ".sum",
})

MANIFEST_NAMES = frozenset({
    "requirements.txt", "pipfile.lock", "poetry.lock", "uv.lock", "package.json",
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "go.sum", "cargo.lock", "gemfile.lock", "composer.lock",
})

SECRET_FILE_NAMES = frozenset({
    ".env", ".npmrc", ".pypirc", ".netrc", ".htpasswd", "credentials",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
})
KEY_SUFFIXES = frozenset({".pem", ".key", ".ppk", ".p8", ".asc"})

KIND_DOCKERFILE = "Dockerfile"
KIND_MANIFEST = "Manifest"
KIND_CONFIG = "Config"
KIND_CREDENTIALS = "Credentials"


def is_excluded_dir(name: str) -> bool:
    if name in EXCLUDED_DIRS:
        return True
    return name.startswith(".") and name not in ALLOWED_DOT_DIRS


def classify(rel_path: str) -> str | None:
    """Returns the file's kind (a language or a category), or None if irrelevant."""
    name = PurePosixPath(rel_path).name
    lowered = name.lower()
    suffix = PurePosixPath(lowered).suffix

    if lowered in ("dockerfile", "containerfile") or lowered.startswith("dockerfile.") \
            or suffix == ".dockerfile":
        return KIND_DOCKERFILE
    if lowered in MANIFEST_NAMES or (lowered.startswith("requirements") and suffix == ".txt"):
        return KIND_MANIFEST
    if lowered in SECRET_FILE_NAMES or lowered.startswith(".env.") or suffix in KEY_SUFFIXES:
        return KIND_CREDENTIALS
    if suffix in LANGUAGES:
        return LANGUAGES[suffix]
    if suffix in CONFIG_SUFFIXES:
        return KIND_CONFIG
    return None


def is_relevant_path(rel_path: str) -> bool:
    parts = PurePosixPath(rel_path).parts
    if any(is_excluded_dir(part) for part in parts[:-1]):
        return False
    return classify(rel_path) is not None


def is_test_path(rel_path: str) -> bool:
    lowered = rel_path.lower()
    name = PurePosixPath(lowered).name
    parts = set(PurePosixPath(lowered).parts[:-1])
    return (
        bool(parts & {"test", "tests", "testing", "__tests__", "spec", "specs", "fixtures"})
        or name.startswith("test_")
        or name.endswith(("_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts",
                          ".test.tsx", ".spec.tsx", ".test.jsx"))
        or name == "conftest.py"
    )


@dataclass(frozen=True)
class SourceFile:
    path: Path
    rel: str
    size: int
    kind: str

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def suffix(self) -> str:
        return self.path.suffix.lower()


@dataclass
class Inventory:
    root: Path
    files: list[SourceFile] = field(default_factory=list)
    skipped: int = 0

    def of_kind(self, *kinds: str) -> list[SourceFile]:
        wanted = set(kinds)
        return [f for f in self.files if f.kind in wanted]

    def where(self, predicate: Callable[[SourceFile], bool]) -> list[SourceFile]:
        return [f for f in self.files if predicate(f)]

    @property
    def total_bytes(self) -> int:
        return sum(f.size for f in self.files)

    @property
    def languages(self) -> dict[str, int]:
        counts = Counter(f.kind for f in self.files)
        return dict(counts.most_common())


def build_inventory(
    root: Path,
    max_file_bytes: int,
    token: CancelToken | None = None,
    max_files: int = 100_000,
) -> Inventory:
    root = root.resolve()
    inventory = Inventory(root=root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        if token is not None:
            token.raise_if_cancelled()
        dirnames[:] = sorted(d for d in dirnames if not is_excluded_dir(d))
        base = Path(dirpath)
        for filename in sorted(filenames):
            path = base / filename
            rel = path.relative_to(root).as_posix()
            kind = classify(rel)
            if kind is None:
                continue
            try:
                if path.is_symlink() or not path.is_file():
                    inventory.skipped += 1
                    continue
                size = path.stat().st_size
            except OSError:
                inventory.skipped += 1
                continue
            if size > max_file_bytes or len(inventory.files) >= max_files:
                inventory.skipped += 1
                continue
            inventory.files.append(SourceFile(path=path, rel=rel, size=size, kind=kind))
    return inventory


def read_text(file: SourceFile) -> str | None:
    """Reads a file as UTF-8 text, returning None for binary content."""
    try:
        raw = file.path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:8192]:
        return None
    return raw.decode("utf-8", errors="replace")


def looks_minified(text: str) -> bool:
    lines = text.splitlines()[:40]
    if not lines:
        return False
    long_lines = sum(1 for line in lines if len(line) > 400)
    return long_lines >= max(1, len(lines) // 4)
