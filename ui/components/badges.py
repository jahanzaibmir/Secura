"""Small inline badges: grades, severity counts, and status indicators."""
from __future__ import annotations

from backend.schemas import JobStatus, RiskScore, ScanSummary
from ui.format import SEVERITIES, STATUS_LABELS, esc

_STATUS_DOT = {
    JobStatus.QUEUED: "is-off",
    JobStatus.RUNNING: "is-running",
    JobStatus.COMPLETED: "is-ok",
    JobStatus.FAILED: "is-failed",
    JobStatus.CANCELLED: "is-off",
}


def grade(risk: RiskScore | None, size: str = "") -> str:
    if risk is None:
        return ""
    css = f"sc-grade grade-{esc(risk.grade)}" + (f" is-{size}" if size else "")
    return f"<span class='{css}' title='Risk score {risk.score}/100 · {esc(risk.label)}'>{esc(risk.grade)}</span>"


def severity_counts(summary: ScanSummary | None, include_zero: bool = False) -> str:
    if summary is None:
        return ""
    chips = []
    for severity in SEVERITIES:
        count = summary.count(severity)
        if count or include_zero:
            chips.append(
                f"<span class='sc-count sev-{severity.value}' title='{severity.label}'>"
                f"<span class='sc-dot'></span>{count}</span>"
            )
    if not chips:
        return "<span class='sc-count sev-info' style='--sev: var(--sc-ok)'>No findings</span>"
    return f"<span class='sc-counts'>{''.join(chips)}</span>"


def status(job_status: JobStatus, progress: int | None = None) -> str:
    label = STATUS_LABELS[job_status]
    if job_status == JobStatus.RUNNING and progress is not None:
        label = f"{label} · {progress}%"
    return f"<span class='sc-status'><span class='sc-dot {_STATUS_DOT[job_status]}'></span>{esc(label)}</span>"


def dot(on: bool) -> str:
    return f"<span class='sc-dot {'is-ok' if on else 'is-off'}'></span>"
