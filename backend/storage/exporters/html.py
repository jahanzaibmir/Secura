"""Standalone HTML report: a single self-contained file, printable to PDF.

All CSS is inlined, every dynamic value is escaped, and the page honours the
reader's light or dark preference.
"""
from __future__ import annotations

import html
from functools import lru_cache
from pathlib import Path

from backend.schemas import ExplanationSource, Finding, Report, Severity
from backend.storage.exporters import richtext
from backend.storage.exporters.common import format_duration, format_time, source_label

_CSS_PATH = Path(__file__).with_name("report.css")


@lru_cache(maxsize=1)
def _css() -> str:
    return _CSS_PATH.read_text(encoding="utf-8")


def _e(value: object) -> str:
    return html.escape(str(value or ""), quote=True)


def _paragraphs(text: str, empty: str) -> str:
    if not text:
        return f"<p class='desc'>{_e(empty)}</p>"
    return richtext.to_html(text, empty, code_class="inline")


def _safe_url(url: str) -> str:
    return url if url.startswith(("https://", "http://")) else ""


def _finding(finding: Finding, index: int) -> str:
    sev = finding.severity.value
    tags: list[str] = []
    if finding.rule_id:
        tags.append(f"<span class='tag'>{_e(finding.rule_id)}</span>")
    if finding.cwe:
        tags.append(f"<span class='tag'>{_e(finding.cwe)}</span>")
    tags.append(f"<span class='tag'>{_e(finding.engine or 'scanner')}</span>")
    tags.append(f"<span class='tag'>confidence {int(round(finding.confidence * 100))}%</span>")
    if finding.explanation_source != ExplanationSource.NONE:
        css = "tag ai" if finding.explanation_source == ExplanationSource.AI else "tag"
        tags.append(f"<span class='{css}'>{_e(source_label(finding))}</span>")

    refs = [_safe_url(r) for r in finding.references[:4]]
    refs_html = ""
    if any(refs):
        links = " · ".join(
            f"<a href='{_e(r)}' rel='noopener noreferrer' target='_blank'>{_e(r)}</a>" for r in refs if r
        )
        refs_html = f"<div class='refs'><span class='label'>References</span><br>{links}</div>"

    snippet = f"<pre>{_e(finding.snippet)}</pre>" if finding.snippet else ""
    description = f"<p class='desc'>{_e(finding.description)}</p>" if finding.description else ""
    open_attr = " open" if finding.severity in (Severity.CRITICAL, Severity.HIGH) or index < 5 else ""
    return (
        f"<details class='finding'{open_attr}>"
        f"<summary><span class='sev'><span class='dot bg-{sev}'></span>{_e(finding.severity.label)}</span>"
        f"<span class='title'>{_e(finding.title)}</span>"
        f"<span class='loc'>{_e(finding.location)}</span></summary>"
        f"<div class='body'><div class='tags'>{''.join(tags)}</div>{description}{snippet}"
        f"<div class='cols'><div class='text'><div class='label'>Why it is dangerous</div>"
        f"{_paragraphs(finding.why_dangerous, 'No explanation recorded.')}</div>"
        f"<div class='text'><div class='label'>How to fix it</div>"
        f"{_paragraphs(finding.how_to_fix, 'No remediation recorded.')}</div></div>"
        f"{refs_html}</div></details>"
    )


def to_html(report: Report) -> str:
    summary = report.summary
    total = max(1, summary.total)
    bar = "".join(
        f"<span class='bg-{s.value}' style='width:{summary.count(s) / total * 100:.2f}%'></span>"
        for s in Severity.ordered() if summary.count(s)
    )
    counts = "".join(
        f"<div class='count'><b>{summary.count(s)}</b>"
        f"<span><span class='dot bg-{s.value}'></span>{s.label}</span></div>"
        for s in Severity.ordered()
    )
    engines = ""
    if report.engines:
        rows = "".join(
            f"<tr><td>{_e(e.label)}</td><td>{_e(e.status)}</td><td class='num'>{e.findings}</td>"
            f"<td>{_e(e.detail)}</td></tr>"
            for e in report.engines
        )
        engines = (
            "<h2>Engines</h2><div class='card' style='padding:6px 10px'><table>"
            "<tr><th>Engine</th><th>Status</th><th style='text-align:right'>Findings</th><th>Detail</th></tr>"
            f"{rows}</table></div>"
        )
    notes = ""
    if report.notes:
        notes = "<h2>Notes</h2><ul class='notes'>" + "".join(f"<li>{_e(n)}</li>" for n in report.notes) + "</ul>"
    if report.findings:
        findings = "".join(_finding(f, i) for i, f in enumerate(report.findings))
    else:
        findings = "<div class='card empty'>No findings were recorded for this scan.</div>"

    risk = report.risk
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>Secura report: {_e(report.target)}</title><style>{_css()}</style></head><body>"
        "<div class='wrap'>"
        "<div class='brand'><span class='brand-mark'></span>Secura security report</div>"
        f"<h1>{_e(report.target)}</h1>"
        "<div class='meta'>"
        f"<span><b>{_e(report.target_type.label)}</b></span>"
        f"<span>Started <b>{_e(format_time(report.started_at))}</b></span>"
        f"<span>Duration <b>{_e(format_duration(report.duration_seconds))}</b></span>"
        f"<span>Files <b>{report.stats.files_scanned}</b></span>"
        f"<span>ID <b>{_e(report.report_id)}</b></span></div>"
        "<div class='overview'>"
        f"<div class='card grade'><div class='grade-badge grade-{_e(risk.grade)}'>{_e(risk.grade)}</div>"
        f"<div><div class='grade-score'>{risk.score}/100</div>"
        f"<div class='grade-label'>{_e(risk.label)}</div></div></div>"
        f"<div class='card'><div class='grade-label'>{summary.total} finding(s)</div>"
        f"<div class='bar'>{bar}</div><div class='counts'>{counts}</div></div></div>"
        f"{engines}{notes}<h2>Findings</h2>{findings}"
        f"<footer>Generated by Secura {_e(report.tool_version)}. "
        "Scan only code you own or are authorised to test.</footer>"
        "</div></body></html>"
    )
