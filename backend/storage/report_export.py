"""Report export — Markdown and a standalone printable HTML document (Phase 4).

The HTML export mirrors the interface's monochrome design system, inlines all
CSS, escapes every dynamic value, and includes print rules so "Open printable
report" → Ctrl+P yields a clean PDF.
"""
import html as _html
import re
from datetime import datetime, timezone
from typing import Tuple

from backend.api.schemas import Finding, Report, Severity, TargetType

TARGET_TYPE_LABELS = {
    TargetType.GITHUB_REPO: "GitHub repository",
    TargetType.LOCAL_PATH: "Uploaded codebase",
}

_SEV_LABEL = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Info",
}

_MEDIA = {
    "json": "application/json",
    "md": "text/markdown; charset=utf-8",
    "html": "text/html; charset=utf-8",
}


def export_report(report: Report, fmt: str) -> Tuple[str, str, str]:
    """Returns (content, filename, media_type) for json | md | html."""
    fmt = fmt.lower()
    if fmt not in _MEDIA:
        raise ValueError(f"Unsupported export format: {fmt}")
    filename = f"secura_{report.report_id}.{fmt}"
    if fmt == "json":
        return report.model_dump_json(indent=2), filename, _MEDIA["json"]
    if fmt == "md":
        return to_markdown(report), filename, _MEDIA["md"]
    return to_html(report), filename, _MEDIA["html"]


# ------------------------------- markdown --------------------------------- #

def to_markdown(report: Report) -> str:
    type_label = TARGET_TYPE_LABELS.get(report.target_type, report.target_type.value)
    started = report.started_at.strftime("%Y-%m-%d %H:%M UTC") if report.started_at else "—"
    finished = report.finished_at.strftime("%Y-%m-%d %H:%M UTC") if report.finished_at else "—"

    lines: list = [
        "# Secura Security Report",
        "",
        f"- **Target:** {report.target}",
        f"- **Target type:** {type_label}",
        f"- **Started:** {started}",
        f"- **Finished:** {finished}",
        f"- **Report ID:** {report.report_id}",
        "",
        "## Summary",
        "",
        "| Severity | Findings |",
        "|---|---|",
    ]
    summary = report.summary
    for label, count in (
        ("Critical", summary.critical), ("High", summary.high),
        ("Medium", summary.medium), ("Low", summary.low), ("Info", summary.info),
    ):
        lines.append(f"| {label} | {count} |")
    lines.append(f"| **Total** | **{summary.total}** |")

    if report.scanner_notes:
        lines += ["", "## Scanner notes", ""]
        lines += [f"- {note}" for note in report.scanner_notes]

    lines += ["", "## Findings", ""]
    if not report.findings:
        lines.append("_No findings were recorded for this scan._")
    for index, finding in enumerate(report.findings, start=1):
        sev = _SEV_LABEL.get(finding.severity, finding.severity.value.title())
        source = (
            "Mistral 7B" if finding.analyzed
            else ("knowledge base" if finding.analysis_source == "template" else "none")
        )
        lines += [
            f"### {index}. {finding.vulnerability_type} — {sev}",
            "",
            f"- **Location:** {finding.location or 'not specified'}",
            f"- **Confidence:** {int(round(finding.confidence * 100))}%",
            f"- **Explanation source:** {source}",
            "",
            "**What was found**",
            "",
        ]
        # Indented code block — immune to fence collisions in the evidence.
        evidence_lines = (finding.evidence or "(no raw evidence captured)").splitlines()
        lines += ["    " + line for line in evidence_lines]
        lines += [
            "",
            "**Why it is dangerous**",
            "",
            finding.why_dangerous or "_No explanation was recorded._",
            "",
            "**How to fix it**",
            "",
            finding.how_to_fix or "_No remediation was recorded._",
            "",
        ]

    lines += [
        "---",
        "Generated locally by Secura — a defensive security tool. "
        "Scan only targets you own or are authorized to test.",
    ]
    return "\n".join(lines) + "\n"


# --------------------------------- html ----------------------------------- #

_HTML_CSS = """
:root{--paper:#fff;--mist:#f6f6f5;--line:#e6e6e4;--ink:#0a0a0a;--charcoal:#2a2c30;--graphite:#54585e;--ash:#909499}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--charcoal);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Helvetica Neue",Arial,sans-serif}
.wrap{max-width:900px;margin:0 auto;padding:48px 28px 64px}
header{border:1px solid var(--line);border-radius:18px;padding:28px;box-shadow:0 10px 28px -14px rgba(10,10,10,.30);margin-bottom:28px}
.kicker{font-size:11px;font-weight:700;letter-spacing:.2em;text-transform:uppercase;color:var(--ash);margin-bottom:6px}
h1{margin:0 0 6px;color:var(--ink);font-size:28px;letter-spacing:-.02em}
.meta{font-size:13px;color:var(--graphite);line-height:1.7}
.metrics{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:28px}
.metric{border:1px solid var(--line);border-radius:14px;padding:14px 16px;box-shadow:0 1px 2px rgba(10,10,10,.06)}
.metric b{display:block;font-size:24px;color:var(--ink)}
.metric span{font-size:10px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:var(--ash)}
.notes{background:var(--mist);border:1px solid var(--line);border-radius:14px;padding:14px 18px;margin-bottom:28px;font-size:13px}
.notes ul{margin:0;padding-left:18px}
.finding{border:1px solid var(--line);border-radius:16px;padding:20px 22px;margin-bottom:18px;box-shadow:0 1px 2px rgba(10,10,10,.05),0 10px 28px -14px rgba(10,10,10,.30)}
.fhead{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding-bottom:12px;border-bottom:1px solid var(--line);margin-bottom:14px}
.sev{font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;padding:4px 10px;border-radius:99px}
.sev-critical{background:var(--ink);color:#fff}
.sev-high{background:var(--charcoal);color:#fff}
.sev-medium{background:var(--graphite);color:#fff}
.sev-low{background:var(--mist);color:var(--ink);border:1px solid var(--line)}
.sev-info{border:1px dashed var(--line);color:var(--ash)}
.ftype{font-weight:700;color:var(--ink)}
.floc{font-size:12px;color:var(--graphite);font-family:ui-monospace,Menlo,Consolas,monospace}
.fconf{margin-left:auto;font-size:11px;color:var(--ash)}
.src{font-size:9px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;border:1px solid var(--line);border-radius:99px;padding:2px 8px;color:var(--ash)}
.src-ai{background:var(--ink);color:#fff;border-color:var(--ink)}
.kick2{font-size:10px;font-weight:700;letter-spacing:.18em;text-transform:uppercase;color:var(--ash);margin:14px 0 6px}
pre.ev{background:#16171a;color:#e9e9e7;border-radius:12px;padding:14px 16px;font-size:12px;line-height:1.55;white-space:pre-wrap;word-break:break-word;overflow-x:auto;margin:0}
p.pre{white-space:pre-wrap;margin:0 0 10px;font-size:14px;line-height:1.6;color:var(--charcoal)}
.two{display:grid;grid-template-columns:1fr 1fr;gap:22px}
@media (max-width:720px){.two{grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,1fr)}}
footer{margin-top:36px;padding-top:16px;border-top:1px solid var(--line);font-size:11px;color:var(--ash);letter-spacing:.04em}
@media print{.finding{break-inside:avoid}body{background:#fff}.wrap{padding:0}}
"""


def _paras(text: str) -> str:
    if not text:
        return "<p class='pre' style='color:#909499'>No explanation was recorded.</p>"
    chunks = [c.strip() for c in re.split(r"\n\s*\n", text) if c.strip()]
    return "".join(
        f"<p class='pre'>{_html.escape(chunk)}</p>" for chunk in chunks
    )


def _finding_card(finding: Finding) -> str:
    e = _html.escape
    sev = _SEV_LABEL.get(finding.severity, finding.severity.value.title())
    sev_cls = "sev-" + finding.severity.value
    if finding.analyzed:
        src = "<span class='src src-ai'>Mistral 7B</span>"
    elif finding.analysis_source == "template":
        src = "<span class='src'>knowledge base</span>"
    else:
        src = ""
    conf = int(round(finding.confidence * 100))
    evidence = e(finding.evidence or "(no raw evidence captured)")
    return (
        f"<div class='finding'>\n<div class='fhead'>\n"
        f"<span class='sev {sev_cls}'>{e(sev)}</span>\n"
        f"<span class='ftype'>{e(finding.vulnerability_type)}</span>\n"
        f"<span class='floc'>{e(finding.location or '')}</span>\n{src}\n"
        f"<span class='fconf'>confidence {conf}%</span>\n</div>\n"
        f"<div class='kick2'>What was found</div>\n<pre class='ev'>{evidence}</pre>\n"
        f"<div class='two'>\n<div>\n<div class='kick2'>Why it is dangerous</div>\n"
        f"{_paras(finding.why_dangerous)}\n</div>\n"
        f"<div>\n<div class='kick2'>How to fix it</div>\n"
        f"{_paras(finding.how_to_fix)}\n</div>\n</div>\n</div>\n"
    )


def to_html(report: Report) -> str:
    e = _html.escape
    started = report.started_at.strftime("%Y-%m-%d %H:%M UTC") if report.started_at else "—"
    finished = report.finished_at.strftime("%Y-%m-%d %H:%M UTC") if report.finished_at else "—"
    type_label = TARGET_TYPE_LABELS.get(report.target_type, report.target_type.value)
    summary = report.summary
    metrics = "".join(
        f"<div class='metric'><b>{value}</b><span>{label}</span></div>"
        for label, value in (
            ("Critical", summary.critical), ("High", summary.high),
            ("Medium", summary.medium), ("Low", summary.low), ("Total", summary.total),
        )
    )
    notes = ""
    if report.scanner_notes:
        items = "".join(f"<li>{e(note)}</li>" for note in report.scanner_notes)
        notes = f"<div class='notes'><ul>{items}</ul></div>"
    if report.findings:
        cards = "".join(_finding_card(f) for f in report.findings)
    else:
        cards = "<div class='notes'>No findings were recorded for this scan.</div>"
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return (
        f"<!doctype html>\n<html lang='en'>\n<head>\n<meta charset='utf-8'>\n"
        f"<meta name='viewport' content='width=device-width, initial-scale=1'>\n"
        f"<title>Secura report · {e(report.target)}</title>\n"
        f"<style>{_HTML_CSS}</style>\n</head>\n<body>\n<div class='wrap'>\n"
        f"<header>\n<div class='kicker'>Secura security report</div>\n"
        f"<h1>{e(report.target)}</h1>\n"
        f"<div class='meta'>Target type: {e(type_label)}<br>\n"
        f"Started: {e(started)} · Finished: {e(finished)}<br>\n"
        f"Report ID: {e(report.report_id)}</div>\n</header>\n"
        f"<div class='metrics'>{metrics}</div>\n{notes}\n{cards}\n"
        f"<footer>Generated locally by Secura · {e(generated)} · a defensive "
        f"security tool — scan only targets you own or are authorized to test."
        f"</footer>\n</div>\n</body>\n</html>\n"
    )
