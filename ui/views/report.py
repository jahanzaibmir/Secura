"""Report page: posture summary, filterable findings, coverage and exports."""
from __future__ import annotations

import streamlit as st

from backend.schemas import Finding, Report
from ui import navigation, services
from ui.client import ApiError
from ui.components import overview, summary
from ui.components.empty import empty_state
from ui.components.findings import finding_list
from ui.format import SEVERITIES, esc
from ui.settings import SETTINGS

PAGE_SIZE = 40

EXPORTS = (
    ("json", "JSON", "application/json", ":material/data_object:"),
    ("md", "Markdown", "text/markdown", ":material/article:"),
    ("html", "HTML", "text/html", ":material/language:"),
    ("sarif", "SARIF", "application/sarif+json", ":material/integration_instructions:"),
)


def render() -> None:
    report_id = st.query_params.get("id", "")
    report = None
    error = None
    if report_id:
        try:
            report = services.report(report_id)
        except ApiError as exc:
            error = exc

    with st.container(horizontal=True, horizontal_alignment="distribute", vertical_alignment="center"):
        st.page_link(navigation.page("reports"), label="All reports", icon=":material/arrow_back:")
        if report is not None:
            _actions(report)

    if report is None:
        if error is not None and error.status != 404:
            st.error(error.message, icon=":material/error:")
        elif report_id:
            empty_state("Report not found", " It may have been deleted.")
        else:
            empty_state("No report selected", " Pick one from the reports list.")
        return

    st.html(summary.report_header(report))
    st.html(summary.severity_tiles(report.summary) + summary.distribution(report.summary))
    st.write("")

    findings_tab, coverage_tab = st.tabs(
        [f"Findings · {report.summary.total}", "Coverage"], key=f"report.tabs.{report.report_id}",
    )
    with findings_tab:
        _findings(report)
    with coverage_tab:
        _coverage(report)


def _actions(report: Report) -> None:
    with st.container(horizontal=True, horizontal_alignment="right", gap="small", width="content"):
        with st.popover("Export", icon=":material/download:"):
            for fmt, label, mime, icon in EXPORTS:
                st.download_button(
                    label, data=lambda f=fmt: services.export(report.report_id, f),
                    file_name=f"secura-{report.report_id}.{fmt}", mime=mime, icon=icon,
                    key=f"report.export.{fmt}", width="stretch", on_click="ignore",
                )
            browser_api = SETTINGS.browser_api_url(st.context.headers.get("Host") or "")
            if browser_api:
                st.link_button("Printable view", f"{browser_api}/api/reports/{report.report_id}/view",
                               icon=":material/print:", width="stretch")
        with st.popover("", icon=":material/delete:", help="Delete report"):
            st.markdown("Delete this report permanently?")
            if st.button("Delete report", type="primary", key="report.delete", width="stretch"):
                try:
                    services.client().delete_report(report.report_id)
                except ApiError as exc:
                    st.error(exc.message)
                    return
                services.forget_report(report.report_id)
                navigation.go("reports")


def _findings(report: Report) -> None:
    if not report.findings:
        empty_state("No findings", " Every engine finished without reporting an issue.")
        return

    present = [s for s in SEVERITIES if report.summary.count(s)]
    engines = sorted({f.engine for f in report.findings if f.engine})
    key = report.report_id

    filter_col, engine_col, search_col = st.columns([3.2, 1.4, 2], vertical_alignment="bottom")
    selected = filter_col.pills(
        "Severity", options=present, default=present, selection_mode="multi",
        format_func=lambda s: f"{s.label} {report.summary.count(s)}",
        key=f"report.sev.{key}", label_visibility="collapsed",
    )
    engine = engine_col.selectbox(
        "Engine", ["All engines", *engines], key=f"report.engine.{key}", label_visibility="collapsed",
    )
    query = search_col.text_input(
        "Search", placeholder="Search title, file or rule", key=f"report.q.{key}",
        label_visibility="collapsed", icon=":material/search:",
    )

    visible = _filter(report.findings, set(selected or []), engine, query)
    limit_key = f"report.limit.{key}"
    limit = st.session_state.get(limit_key, PAGE_SIZE)
    if not visible:
        empty_state("Nothing matches these filters")
        return
    st.caption(f"Showing {min(limit, len(visible))} of {len(visible)} findings, most severe first.")
    st.html(finding_list(visible[:limit], expand_first=1))
    if len(visible) > limit:
        if st.button(f"Show {min(PAGE_SIZE, len(visible) - limit)} more", key=f"report.more.{key}",
                     icon=":material/expand_more:"):
            st.session_state[limit_key] = limit + PAGE_SIZE
            st.rerun()


def _filter(findings: list[Finding], severities: set, engine: str, query: str) -> list[Finding]:
    needle = query.strip().lower()
    result = []
    for finding in findings:
        if finding.severity not in severities:
            continue
        if engine != "All engines" and finding.engine != engine:
            continue
        if needle and needle not in " ".join(
            (finding.title, finding.location, finding.rule_id, finding.cwe or "", finding.description)
        ).lower():
            continue
        result.append(finding)
    return result


def _coverage(report: Report) -> None:
    left, right = st.columns([1.6, 1], gap="large")
    with left:
        st.html("<div class='sc-section-title' style='margin-top:0.5rem'>Engines</div>")
        st.html(overview.engines_table(report))
        if report.notes:
            st.html("<div class='sc-section-title'>Notes</div>")
            st.html(overview.notes(report))
    with right:
        st.html("<div class='sc-section-title' style='margin-top:0.5rem'>Files by type</div>")
        st.html(overview.languages(report))
        st.html("<div class='sc-section-title'>Explanations</div>")
        st.html(overview.analysis(report))
        stats = report.stats
        st.html(
            "<div class='sc-section-title'>Scope</div><dl class='sc-kv'>"
            f"<dt>Files scanned</dt><dd>{stats.files_scanned}</dd>"
            f"<dt>Files skipped</dt><dd>{stats.files_skipped}</dd>"
            f"<dt>Data read</dt><dd>{stats.bytes_scanned / 1024:.0f} KB</dd>"
            f"<dt>Secura version</dt><dd>{esc(report.tool_version)}</dd></dl>"
        )
