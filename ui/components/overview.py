"""Report overview: engine runs, language mix, and scanner notes."""
from __future__ import annotations

from backend.schemas import Report
from ui.format import duration, esc

_ENGINE_STATUS = {"completed": "is-ok", "failed": "is-failed", "skipped": "is-off"}


def engines_table(report: Report) -> str:
    if not report.engines:
        return "<div class='sc-empty'>No engines applied to this codebase.</div>"
    rows = "".join(
        f"<tr><td><span class='sc-status'><span class='sc-dot {_ENGINE_STATUS.get(e.status, 'is-off')}'></span>"
        f"{esc(e.label)}</span></td><td class='sc-muted'>{esc(e.detail)}</td>"
        f"<td class='num'>{e.findings}</td><td class='num sc-muted'>{esc(duration(e.duration_seconds))}</td></tr>"
        for e in report.engines
    )
    return (
        "<div class='sc-card' style='padding:0.4rem 0.8rem'><table class='sc-table'>"
        "<tr><th>Engine</th><th>Coverage</th><th style='text-align:right'>Findings</th>"
        "<th style='text-align:right'>Time</th></tr>"
        f"{rows}</table></div>"
    )


def languages(report: Report) -> str:
    items = list(report.stats.languages.items())
    if not items:
        return "<div class='sc-muted sc-small'>No files were indexed.</div>"
    top = max(count for _, count in items) or 1
    rows = "".join(
        f"<div class='sc-lang-row'><span>{esc(name)}</span>"
        f"<div class='sc-lang-bar'><span style='width:{count / top * 100:.1f}%'></span></div>"
        f"<span class='sc-lang-count'>{count}</span></div>"
        for name, count in items[:10]
    )
    return f"<div class='sc-card'><div class='sc-lang'>{rows}</div></div>"


def notes(report: Report) -> str:
    if not report.notes:
        return ""
    return "".join(f"<div class='sc-note'>{esc(note)}</div>" for note in report.notes)


def analysis(report: Report) -> str:
    info = report.analysis
    if info.explained_by_ai:
        text = (f"{info.explained_by_ai} finding(s) explained by {esc(info.model)} "
                f"({esc(info.provider)}); {info.explained_by_knowledge_base} by the knowledge base.")
    else:
        text = "All findings were explained by Secura's curated knowledge base."
    return f"<div class='sc-muted sc-small'>{text}</div>"
