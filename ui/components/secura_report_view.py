"""Report rendering — metric tiles, scrollable findings, export row."""
import html as _html
from typing import List, Optional

import streamlit as st

from backend.api.schemas import Finding, Report, Severity
from ui.api_client import VulnWeaveClient

_SEV_CLASS = {
    Severity.CRITICAL: "vw-sev-critical",
    Severity.HIGH: "vw-sev-high",
    Severity.MEDIUM: "vw-sev-medium",
    Severity.LOW: "vw-sev-low",
    Severity.INFO: "vw-sev-info",
}
_SEV_LABEL = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Info",
}


def _esc(text: str) -> str:
    return _html.escape(text or "")


def _source_tag(finding: Finding) -> str:
    if finding.analyzed:
        return "<span class='vw-src vw-src-ai'>Mistral 7B</span>"
    if finding.analysis_source == "template":
        return "<span class='vw-src'>Knowledge base</span>"
    return ""


def _finding_html(finding: Finding) -> str:
    sev_class = _SEV_CLASS.get(finding.severity, "vw-sev-info")
    sev_label = _SEV_LABEL.get(finding.severity, finding.severity.value.title())
    confidence = int(round(finding.confidence * 100))
    why = finding.why_dangerous or "No explanation was recorded for this finding."
    fix = finding.how_to_fix or "No remediation was recorded for this finding."
    return f"""
        <div class="vw-card vw-finding">
          <div class="vw-finding-head">
            <span class="vw-sev {sev_class}">{sev_label}</span>
            <span class="vw-finding-type">{_esc(finding.vulnerability_type)}</span>
            <span class="vw-finding-loc">{_esc(finding.location) or "not specified"}</span>
            {_source_tag(finding)}
            <span class="vw-finding-conf">confidence {confidence}%</span>
          </div>
          <div class="vw-finding-body">
            <div class="vw-kicker">What was found</div>
            <pre class="vw-evidence">{_esc(finding.evidence) or "No raw evidence captured."}</pre>
            <div class="vw-two-col">
              <div>
                <div class="vw-kicker">Why it is dangerous</div>
                <p class="vw-muted">{_esc(why)}</p>
              </div>
              <div>
                <div class="vw-kicker">How to fix it</div>
                <p class="vw-muted">{_esc(fix)}</p>
              </div>
            </div>
          </div>
        </div>
        """


def _render_export_row(report: Report, client: Optional[VulnWeaveClient]) -> None:
    columns = st.columns([1, 1, 1, 2])
    columns[0].download_button(
        "Download JSON",
        data=report.model_dump_json(indent=2),
        file_name=f"secura_{report.report_id}.json",
        mime="application/json",
        key=f"vw_dl_json_{report.report_id}",
    )
    if client is None:
        return
    markdown = client.fetch_report_file(report.report_id, "md")
    if markdown is not None:
        columns[1].download_button(
            "Download Markdown",
            data=markdown[0],
            file_name=markdown[1].replace("vulnweave_", "secura_"),
            mime="text/markdown",
            key=f"vw_dl_md_{report.report_id}",
        )
    html_file = client.fetch_report_file(report.report_id, "html")
    if html_file is not None:
        columns[2].download_button(
            "Download HTML",
            data=html_file[0],
            file_name=html_file[1].replace("vulnweave_", "secura_"),
            mime="text/html",
            key=f"vw_dl_html_{report.report_id}",
        )
    columns[3].link_button(
        "Open printable report", client.report_view_url(report.report_id)
    )


def render_report(report: Report, client: Optional[VulnWeaveClient] = None) -> None:
    st.markdown(
        f"<div class='vw-report-head'><div class='vw-kicker'>Report · "
        f"{_esc(report.report_id)}</div><h2>{_esc(report.target)}</h2></div>",
        unsafe_allow_html=True,
    )

    summary = report.summary
    metrics = [
        ("Critical", summary.critical),
        ("High", summary.high),
        ("Medium", summary.medium),
        ("Low", summary.low),
        ("Total", summary.total),
    ]
    columns = st.columns(5)
    for column, (label, value) in zip(columns, metrics):
        column.markdown(
            f"<div class='vw-metric'><span class='vw-metric-num'>{value}</span>"
            f"<span class='vw-metric-label'>{label}</span></div>",
            unsafe_allow_html=True,
        )

    for note in report.scanner_notes:
        st.info(note)

    if not report.findings:
        st.markdown(
            "<div class='vw-empty'>No findings recorded for this scan.</div>",
            unsafe_allow_html=True,
        )
    else:
        # All findings inside one fixed-height scroll window.
        findings_html: List[str] = [_finding_html(f) for f in report.findings]
        st.markdown(
            "<div class='vw-scroll'>" + "".join(findings_html) + "</div>",
            unsafe_allow_html=True,
        )

    _render_export_row(report, client)
