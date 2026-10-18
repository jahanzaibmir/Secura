"""Finding cards rendered as native, keyboard-accessible disclosure widgets."""
from __future__ import annotations

import re

from backend.schemas import ExplanationSource, Finding
from backend.storage.exporters import richtext
from ui.format import esc


def _paragraphs(text: str, fallback: str) -> str:
    if not text:
        return f"<p class='sc-muted'>{esc(fallback)}</p>"
    return richtext.to_html(text, fallback, code_class="sc-code")


def _tags(finding: Finding) -> str:
    tags: list[str] = []
    if finding.rule_id:
        tags.append(finding.rule_id)
    if finding.cwe:
        tags.append(finding.cwe)
    tags.append(finding.engine or "scanner")
    tags.append(f"{int(round(finding.confidence * 100))}% confidence")
    for key in ("fixed_version", "cvss"):
        if finding.metadata.get(key):
            label = "fixed in" if key == "fixed_version" else "CVSS"
            tags.append(f"{label} {finding.metadata[key]}")
    html = "".join(f"<span class='sc-tag'>{esc(tag)}</span>" for tag in tags)
    if finding.explanation_source == ExplanationSource.AI:
        model = f" · {finding.explanation_model}" if finding.explanation_model else ""
        html += f"<span class='sc-tag is-ai'>AI explained{esc(model)}</span>"
    elif finding.explanation_source == ExplanationSource.KNOWLEDGE_BASE:
        html += "<span class='sc-tag'>Knowledge base</span>"
    return f"<div class='sc-tags'>{html}</div>"


def _references(finding: Finding) -> str:
    links = [r for r in finding.references[:4] if r.startswith(("https://", "http://"))]
    if not links:
        return ""
    items = "".join(
        f"<a href='{esc(link)}' target='_blank' rel='noopener noreferrer'>{esc(_short(link))}</a>"
        for link in links
    )
    return f"<div class='sc-refs'><span>References</span>{items}</div>"


def _short(url: str) -> str:
    trimmed = re.sub(r"^https?://(www\.)?", "", url)
    return trimmed if len(trimmed) <= 60 else trimmed[:57] + "…"


def finding_card(finding: Finding, expanded: bool = False) -> str:
    sev = finding.severity.value
    snippet = f"<pre class='sc-code'>{esc(finding.snippet)}</pre>" if finding.snippet else ""
    description = f"<p class='sc-desc'>{esc(finding.description)}</p>" if finding.description else ""
    return (
        f"<details class='sc-finding sev-{sev}'{' open' if expanded else ''}>"
        f"<summary><span class='sc-sev'><span class='sc-dot'></span>{esc(finding.severity.label)}</span>"
        f"<span class='sc-finding-title' title='{esc(finding.title)}'>{esc(finding.title)}</span>"
        f"<span class='sc-finding-loc' title='{esc(finding.location)}'><bdi>{esc(finding.location)}</bdi></span>"
        "<span class='sc-chevron'></span></summary>"
        f"<div class='sc-finding-body'>{_tags(finding)}{description}{snippet}"
        "<div class='sc-explain'>"
        f"<section><h4>Why it matters</h4>{_paragraphs(finding.why_dangerous, 'No explanation recorded.')}</section>"
        f"<section><h4>How to fix</h4>{_paragraphs(finding.how_to_fix, 'No remediation recorded.')}</section>"
        f"</div>{_references(finding)}</div></details>"
    )


def finding_list(findings: list[Finding], expand_first: int = 1) -> str:
    return "".join(finding_card(f, expanded=i < expand_first) for i, f in enumerate(findings))
