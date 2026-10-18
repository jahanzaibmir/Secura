"""Report exporters: JSON, Markdown, HTML and SARIF."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from backend.exceptions import ValidationError
from backend.schemas import Report
from backend.storage.exporters.html import to_html
from backend.storage.exporters.markdown import to_markdown
from backend.storage.exporters.sarif import to_sarif


@dataclass(frozen=True)
class ExportFormat:
    extension: str
    media_type: str
    render: Callable[[Report], str]


FORMATS: dict[str, ExportFormat] = {
    "json": ExportFormat("json", "application/json", lambda r: r.model_dump_json(indent=2)),
    "md": ExportFormat("md", "text/markdown; charset=utf-8", to_markdown),
    "html": ExportFormat("html", "text/html; charset=utf-8", to_html),
    "sarif": ExportFormat("sarif", "application/sarif+json", to_sarif),
}


def export_report(report: Report, fmt: str) -> tuple:
    """Returns (content, filename, media_type)."""
    spec = FORMATS.get((fmt or "").lower())
    if spec is None:
        raise ValidationError(f"Unsupported export format: {fmt}")
    filename = f"secura-{report.report_id}.{spec.extension}"
    return spec.render(report), filename, spec.media_type


__all__ = ["FORMATS", "export_report", "to_html", "to_markdown", "to_sarif"]
