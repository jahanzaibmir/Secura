"""Presentation helpers: escaping, relative times, and severity metadata."""
from __future__ import annotations

import html
from datetime import UTC, datetime

from backend.schemas import JobStatus, Severity, TargetType


def esc(value: object) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def time_ago(moment: datetime | None) -> str:
    if moment is None:
        return ""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    seconds = int((datetime.now(UTC) - moment).total_seconds())
    if seconds < 10:
        return "just now"
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    if seconds < 86400 * 30:
        return f"{seconds // 86400}d ago"
    return moment.strftime("%b %d, %Y")


def timestamp(moment: datetime | None) -> str:
    return moment.strftime("%b %d, %Y · %H:%M UTC") if moment else ""


def duration(seconds: float | None) -> str:
    if seconds is None:
        return ""
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, rest = divmod(int(seconds), 60)
    return f"{minutes}m {rest:02d}s"


def display_target(target: str, target_type: TargetType) -> str:
    if target_type == TargetType.GITHUB_REPO:
        return target.removeprefix("https://github.com/")
    return target


def plural(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


TARGET_ICONS = {
    TargetType.GITHUB_REPO: "GitHub",
    TargetType.UPLOAD: "Upload",
    TargetType.LOCAL_PATH: "Folder",
}

STATUS_LABELS = {
    JobStatus.QUEUED: "Queued",
    JobStatus.RUNNING: "Running",
    JobStatus.COMPLETED: "Completed",
    JobStatus.FAILED: "Failed",
    JobStatus.CANCELLED: "Cancelled",
}

SEVERITIES = Severity.ordered()
