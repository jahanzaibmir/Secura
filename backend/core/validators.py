"""Target validation & normalization — the gate every scan passes through."""
import re
from pathlib import Path

from backend.api.schemas import TargetType
from backend.exceptions import ValidationError

_GITHUB_RE = re.compile(
    r"^https?://(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)


def validate_github_repo(target: str) -> str:
    match = _GITHUB_RE.match(target.strip())
    if not match:
        raise ValidationError(
            "Not a valid GitHub repository URL. Expected: https://github.com/owner/repo"
        )
    owner, repo = match.group(1), match.group(2)
    return f"https://github.com/{owner}/{repo}"


def validate_local_path(target: str) -> str:
    path = Path(target.strip()).expanduser()
    if not path.exists():
        raise ValidationError(f"Path does not exist: {path}")
    if not path.is_dir():
        raise ValidationError(f"Path is not a folder: {path}")
    try:
        has_any = any(path.iterdir())
    except PermissionError as exc:
        raise ValidationError(f"Cannot read folder: {path}") from exc
    if not has_any:
        raise ValidationError(f"Folder is empty: {path}")
    return str(path.resolve())


VALIDATORS = {
    TargetType.GITHUB_REPO: validate_github_repo,
    TargetType.LOCAL_PATH: validate_local_path,
}


def validate_target(target_type: TargetType, target: str) -> str:
    validator = VALIDATORS.get(target_type)
    if validator is None:
        raise ValidationError(f"Unsupported target type: {target_type}")
    return validator(target)
