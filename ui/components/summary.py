"""Report summary blocks: score, severity tiles and distribution bar."""
from __future__ import annotations

from backend.schemas import Report, ScanSummary, TargetType
from ui.components import badges
from ui.format import SEVERITIES, display_target, duration, esc, plural, timestamp


def report_header(report: Report) -> str:
    risk = report.risk
    source = f"<b>{esc(report.target_type.label)}</b>"
    if report.target_type == TargetType.GITHUB_REPO and report.target.startswith("https://github.com/"):
        source = (f"<a href='{esc(report.target)}' target='_blank' rel='noopener noreferrer' "
                  f"style='color:inherit'><b>{esc(report.target_type.label)} ↗</b></a>")
    meta = [
        f"<span>{source}</span>",
        f"<span>{esc(timestamp(report.started_at))}</span>",
    ]
    if report.duration_seconds is not None:
        meta.append(f"<span>Took <b>{esc(duration(report.duration_seconds))}</b></span>")
    meta.append(f"<span><b>{report.stats.files_scanned}</b> files</span>")
    meta.append(f"<span class='sc-mono'>{esc(report.report_id)}</span>")
    return (
        "<div class='sc-report-head'><div style='min-width:0'>"
        f"<div class='sc-report-title'>{esc(display_target(report.target, report.target_type))}</div>"
        f"<div class='sc-meta'>{''.join(meta)}</div></div>"
        f"<div class='sc-score'>{badges.grade(risk, 'lg')}<div>"
        f"<div class='sc-score-value'>{risk.score}<span class='sc-muted' style='font-size:0.95rem'>/100</span></div>"
        f"<div class='sc-score-label'>{esc(risk.label)} risk posture</div></div></div></div>"
    )


def severity_tiles(summary: ScanSummary) -> str:
    tiles = []
    for severity in SEVERITIES:
        count = summary.count(severity)
        tiles.append(
            f"<div class='sc-tile sev-{severity.value}{' is-zero' if not count else ''}'>"
            f"<div class='sc-tile-value'>{count}</div>"
            f"<div class='sc-tile-label'><span class='sc-dot'></span>{severity.label}</div></div>"
        )
    return f"<div class='sc-tiles'>{''.join(tiles)}</div>"


def distribution(summary: ScanSummary) -> str:
    if not summary.total:
        return ""
    parts = "".join(
        f"<span class='sev-{s.value}' style='width:{summary.count(s) / summary.total * 100:.2f}%' "
        f"title='{s.label}: {summary.count(s)}'></span>"
        for s in SEVERITIES if summary.count(s)
    )
    return (
        f"<div class='sc-distribution'>{parts}</div>"
        f"<div class='sc-muted sc-small'>{plural(summary.total, 'finding')} in total</div>"
    )
