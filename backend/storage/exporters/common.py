"""Formatting helpers shared by every exporter."""
from __future__ import annotations

from datetime import datetime

from backend.schemas import ExplanationSource, Finding


def format_time(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M UTC") if value else "n/a"


def format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "n/a"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, rest = divmod(int(seconds), 60)
    return f"{minutes}m {rest:02d}s"


def source_label(finding: Finding) -> str:
    if finding.explanation_source == ExplanationSource.AI:
        return f"AI ({finding.explanation_model})" if finding.explanation_model else "AI"
    if finding.explanation_source == ExplanationSource.KNOWLEDGE_BASE:
        return "Knowledge base"
    return "None"
