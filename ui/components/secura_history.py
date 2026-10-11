"""History — browse and reopen past scans, cards in a scroll window."""
from html import escape as _esc

import streamlit as st

from backend.storage.report_export import TARGET_TYPE_LABELS
from ui.api_client import VulnWeaveClient
from ui.components.secura_report_view import render_report

_MAX_CARDS = 60
_SCROLL_HEIGHT = 460


def render_history(client: VulnWeaveClient) -> None:
    st.markdown(
        "<div class='vw-kicker'>Library</div><h2>Scan history</h2>",
        unsafe_allow_html=True,
    )
    if st.button("Refresh", key="vw_hist_refresh"):
        st.rerun()

    metas = client.list_reports()
    if not metas:
        st.markdown(
            "<div class='vw-empty'>No reports yet. Run your first scan from "
            "the Scanner tab.</div>",
            unsafe_allow_html=True,
        )
        return
    if len(metas) > _MAX_CARDS:
        st.info(f"Showing the {_MAX_CARDS} most recent of {len(metas)} stored reports.")
        metas = metas[:_MAX_CARDS]

    # Cards inside a fixed-height scroll window; the opened report
    # renders below it, outside the scroll area.
    with st.container(height=_SCROLL_HEIGHT, border=False):
        for meta in metas:
            _render_meta_card(client, meta)

    selected_id = st.session_state.get("vw_history_selected")
    if not selected_id:
        return
    report = client.get_report(selected_id)
    if report is None:
        st.error("That report could not be loaded. It may have been deleted "
                 "from the reports folder.")
        st.session_state.pop("vw_history_selected", None)
        return
    header, closer = st.columns([4, 1])
    with closer:
        if st.button("Close report", key="vw_hist_close"):
            st.session_state.pop("vw_history_selected", None)
            st.rerun()
    render_report(report, client)


def _render_meta_card(client: VulnWeaveClient, meta) -> None:
    date = (meta.finished_at.strftime("%Y %m %d · %H:%M UTC")
            if meta.finished_at else "unfinished")
    type_label = TARGET_TYPE_LABELS.get(meta.target_type, meta.target_type.value)
    chips = ""
    for count, label, css in (
        (meta.critical, "critical", "vw-chip-c"),
        (meta.high, "high", "vw-chip-h"),
        (meta.medium, "medium", "vw-chip-m"),
        (meta.low, "low", "vw-chip-l"),
    ):
        if count:
            chips += f"<span class='vw-chip {css}'>{count} {label}</span>"
    st.markdown(
        f"""
        <div class="vw-card vw-hist">
          <div class="vw-kicker">{_esc(date)} · {_esc(type_label)}</div>
          <div class="vw-hist-target">{_esc(meta.target)}</div>
          <div class="vw-hist-meta">{meta.total_findings} finding(s){chips}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    open_col, link_col, _ = st.columns([1, 1.4, 5])
    if open_col.button("Open report", key=f"vw_hist_open_{meta.report_id}"):
        st.session_state["vw_history_selected"] = meta.report_id
    link_col.link_button(
        "Printable HTML", client.report_view_url(meta.report_id)
    )
