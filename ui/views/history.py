"""Reports page: every stored report, searchable."""
from __future__ import annotations

import streamlit as st

from backend.schemas import ReportMeta, TargetType
from ui import navigation, services
from ui.client import ApiError
from ui.components import badges
from ui.components.empty import backend_unreachable, empty_state
from ui.format import display_target, esc, plural, time_ago, timestamp

PAGE_SIZE = 20
_TYPES = {"all": "All sources", TargetType.GITHUB_REPO.value: "GitHub", TargetType.UPLOAD.value: "Uploads",
          TargetType.LOCAL_PATH.value: "Local folders"}


def render() -> None:
    try:
        reports = services.client().list_reports()
    except ApiError:
        backend_unreachable()
        return

    st.html(
        "<div class='sc-page-head'><h1>Reports</h1>"
        f"<p>{plural(len(reports), 'stored report')}. Reports are kept on the server until you delete them.</p></div>"
    )
    if not reports:
        empty_state("No reports yet", " Run a scan and the result will appear here.")
        if st.button("Start a scan", type="primary", icon=":material/radar:"):
            navigation.go("scan")
        return

    search_col, type_col = st.columns([3, 1], vertical_alignment="bottom")
    query = search_col.text_input("Search", placeholder="Search by target", label_visibility="collapsed",
                                  icon=":material/search:", key="history.q")
    kind = type_col.selectbox("Source", list(_TYPES), format_func=_TYPES.get, label_visibility="collapsed",
                              key="history.type")
    visible = _filter(reports, query, kind)
    if not visible:
        empty_state("Nothing matches this search")
        return

    limit = st.session_state.get("history.limit", PAGE_SIZE)
    with st.container(border=True):
        for index, meta in enumerate(visible[:limit]):
            if index:
                st.html("<div style='border-top:1px solid var(--sc-line);margin:0.1rem 0'></div>")
            _row(meta)
    if len(visible) > limit:
        if st.button(f"Show more ({len(visible) - limit} remaining)", icon=":material/expand_more:"):
            st.session_state["history.limit"] = limit + PAGE_SIZE
            st.rerun()


def _filter(reports: list[ReportMeta], query: str, kind: str) -> list[ReportMeta]:
    needle = query.strip().lower()
    return [
        r for r in reports
        if (kind == "all" or r.target_type.value == kind) and (not needle or needle in r.target.lower())
    ]


def _row(meta: ReportMeta) -> None:
    info_col, open_col = st.columns([9, 1.2], vertical_alignment="center")
    moment = meta.finished_at or meta.started_at
    info_col.html(
        f"<div class='sc-row'>{badges.grade(meta.risk)}"
        f"<div class='sc-row-main'><div class='sc-row-title'>{esc(display_target(meta.target, meta.target_type))}</div>"
        f"<div class='sc-row-sub'><span title='{esc(timestamp(moment))}'>{esc(meta.target_type.label)} · "
        f"{esc(time_ago(moment))} · score {meta.risk.score}</span>{badges.severity_counts(meta.summary)}"
        "</div></div></div>"
    )
    if open_col.button("Open", key=f"history.open.{meta.report_id}", icon=":material/chevron_right:",
                       icon_position="right", type="tertiary"):
        navigation.open_report(meta.report_id)
