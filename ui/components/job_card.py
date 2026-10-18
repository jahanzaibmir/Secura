"""Live scan card: progress bar and pipeline stages."""
from __future__ import annotations

from backend.schemas import JobStatus, JobView
from ui.components import badges
from ui.format import TARGET_ICONS, esc, time_ago


def _stage_rows(view: JobView) -> str:
    rows = []
    for stage in view.stages:
        rows.append(
            f"<li class='is-{stage.status.value}'><span class='sc-stage-icon'></span>"
            f"<span>{esc(stage.label)}</span><span class='sc-stage-detail'>{esc(stage.detail)}</span></li>"
        )
    return "".join(rows)


def job_card(view: JobView) -> str:
    source = TARGET_ICONS.get(view.target_type, "Scan")
    started = time_ago(view.started_at or view.created_at)
    failed = view.status in (JobStatus.FAILED, JobStatus.CANCELLED)
    progress = 100 if view.status == JobStatus.COMPLETED else view.progress
    error = ""
    if view.error and view.status == JobStatus.FAILED:
        error = f"<div class='sc-note' style='border-color: var(--sc-critical)'>{esc(view.error)}</div>"
    stages = f"<ol class='sc-stages'>{_stage_rows(view)}</ol>" if view.stages else ""
    return (
        "<div class='sc-card sc-job'>"
        "<div class='sc-job-head'><div>"
        f"<div class='sc-job-title'>{esc(view.label)}</div>"
        f"<div class='sc-job-sub'>{esc(source)} · started {esc(started)}</div></div>"
        f"{badges.status(view.status, view.progress)}</div>"
        f"<div class='sc-progress{' is-failed' if failed else ''}'><span style='width:{progress}%'></span></div>"
        f"{stages}{error}</div>"
    )


def completion_card(view: JobView) -> str:
    total = view.summary.total if view.summary else 0
    headline = "No issues found" if total == 0 else f"{total} finding{'s' if total != 1 else ''}"
    risk = view.risk
    score = f"Risk score {risk.score}/100 · {esc(risk.label)}" if risk else ""
    return (
        "<div class='sc-card sc-job'><div class='sc-provider'>"
        f"{badges.grade(view.risk, 'lg')}"
        "<div style='min-width:0'>"
        f"<div class='sc-job-sub'>Scan complete · {esc(view.label)}</div>"
        f"<div class='sc-score-value' style='margin:0.15rem 0 0.35rem'>{esc(headline)}</div>"
        f"<div style='display:flex;flex-wrap:wrap;gap:0.6rem;align-items:center'>"
        f"{badges.severity_counts(view.summary)}<span class='sc-muted sc-small'>{score}</span></div>"
        "</div></div></div>"
    )
