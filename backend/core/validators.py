"""Target validation and normalisation: the gate every scan passes through."""
from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

from backend.exceptions import ValidationError
from backend.schemas import TargetType

_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_SHORTHAND_RE = re.compile(r"^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$")
_GITHUB_HOSTS = {"github.com", "www.github.com"}

_GITHUB_HINT = "Expected a public GitHub repository, for example https://github.com/owner/repo"


def validate_github_repo(raw: str) -> str:
    """Accepts URLs, ``github.com/owner/repo``, SSH remotes, and ``owner/repo``.

    Deep links such as ``/tree/main/src`` are trimmed to the repository root.
    Returns the canonical ``https://github.com/owner/repo`` form.
    """
    value = (raw or "").strip()
    if not value:
        raise ValidationError(_GITHUB_HINT)

    if value.startswith("git@github.com:"):
        value = "https://github.com/" + value.split(":", 1)[1]
    elif _SHORTHAND_RE.match(value):
        value = f"https://github.com/{value}"
    elif not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = f"https://{value}"

    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or (parsed.hostname or "").lower() not in _GITHUB_HOSTS:
        raise ValidationError(_GITHUB_HINT)
    if parsed.username or parsed.password or parsed.port:
        raise ValidationError("Repository URLs must not contain credentials or ports.")

    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        raise ValidationError(_GITHUB_HINT)

    owner, repo = parts[0], parts[1]
    if repo.lower().endswith(".git"):
        repo = repo[:-4]
    if not _OWNER_RE.match(owner) or not _REPO_RE.match(repo) or repo in (".", ".."):
        raise ValidationError(f"'{owner}/{repo}' is not a valid GitHub repository name.")
    return f"https://github.com/{owner}/{repo}"


def validate_directory(raw: str) -> str:
    path = Path((raw or "").strip()).expanduser()
    if not str(path):
        raise ValidationError("A folder path is required.")
    if not path.exists():
        raise ValidationError(f"Path does not exist: {path}")
    if not path.is_dir():
        raise ValidationError(f"Path is not a folder: {path}")
    try:
        has_entries = any(path.iterdir())
    except PermissionError as exc:
        raise ValidationError(f"Cannot read folder: {path}") from exc
    if not has_entries:
        raise ValidationError(f"Folder is empty: {path}")
    return str(path.resolve())


_VALIDATORS = {
    TargetType.GITHUB_REPO: validate_github_repo,
    TargetType.LOCAL_PATH: validate_directory,
    TargetType.UPLOAD: validate_directory,
}


def validate_target(target_type: TargetType, target: str) -> str:
    validator = _VALIDATORS.get(target_type)
    if validator is None:
        raise ValidationError(f"Unsupported target type: {target_type}")
    return validator(target)
