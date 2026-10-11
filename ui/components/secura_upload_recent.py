"""Recent uploads — the persistence layer for folder scans.

Backend-driven, so it survives tab switches, component remounts, and
reloads. A fragment refreshes every two seconds while visible. Reports
render in the Results tab; this panel sets the report id and tells the
user where to look.
"""
from html import escape as _esc

import streamlit as st

from backend.api.schemas import JobStatus
from ui.api_client import VulnWeaveClient
from ui.components.secura_report_view import render_report

_MAX_SHOWN = 8
REPORT_ID_KEY = "vw_upload_report_id"
_REPORT_KEY = "vw_upload_report"
_AUTO_KEY = "vw_upload_auto_shown"
_HINT_KEY = "vw_upload_hint"

_client_holder: dict = {}


def _panel() -> None:
    client = _client_holder["client"]
    uploads = [j for j in client.list_jobs() if j.label][:_MAX_SHOWN]
    if not uploads:
        return

    if st.session_state.pop(_HINT_KEY, False):
        st.success("Report ready. Open the Results tab.")

    st.markdown("<div class='vw-kicker'>Recent uploads</div>",
                unsafe_allow_html=True)

    # Auto-reveal the newest completed report, once, never stealing
    # focus from a report the user picked manually.
    auto = st.session_state.setdefault(_AUTO_KEY, set())
    top = uploads[0]
    if (top.status == JobStatus.COMPLETED and top.report_id
            and top.report_id not in auto):
        auto.add(top.report_id)
        if st.session_state.get(REPORT_ID_KEY) != top.report_id:
            st.session_state[REPORT_ID_KEY] = top.report_id
            st.session_state[_HINT_KEY] = True
            st.rerun()

    for job in uploads:
        _render_job(job)


def _render_job(job) -> None:
    if job.status == JobStatus.RUNNING:
        state = f"{_esc(job.current_stage or 'running')} · {job.progress}%"
        on = False
    elif job.status == JobStatus.COMPLETED:
        state = "completed"
        on = True
    elif job.status == JobStatus.FAILED:
        state = _esc((job.error or "failed")[:120])
        on = False
    else:
        state = "queued"
        on = False
    st.markdown(
        f"<div class='vw-hist-meta' style='margin-bottom:0.35rem;'>"
        f"<span class='vw-pill'><span class='vw-dot "
        f"{'vw-dot-on' if on else 'vw-dot-off'}'></span>"
        f"{_esc(job.label or 'upload')}</span>"
        f"<span class='vw-finding-loc'>{state}</span></div>",
        unsafe_allow_html=True,
    )
    if job.status == JobStatus.COMPLETED and job.report_id:
        if st.button("View report", key=f"vw_up_view_{job.job_id}"):
            st.session_state.setdefault(_AUTO_KEY, set()).add(job.report_id)
            st.session_state[REPORT_ID_KEY] = job.report_id
            st.session_state[_HINT_KEY] = True
            st.rerun()


# One fragment instance, defined once at import time.
if hasattr(st, "fragment"):
    @st.fragment(run_every=2)
    def _auto_panel() -> None:
        _panel()
else:  # very old Streamlit — renders, just without auto-refresh
    def _auto_panel() -> None:
        _panel()


def render_recent_uploads(client: VulnWeaveClient) -> None:
    _client_holder["client"] = client
    _auto_panel()


def render_upload_report(client: VulnWeaveClient) -> None:
    """The persistent report area — re-fetched by id, never lost."""
    report_id = st.session_state.get(REPORT_ID_KEY)
    if not report_id:
        return
    report = st.session_state.get(_REPORT_KEY)
    if report is None or report.report_id != report_id:
        report = client.get_report(report_id)
        if report is None:
            st.error("That report is no longer available on the backend. "
                     "It may have restarted.")
            st.session_state.pop(REPORT_ID_KEY, None)
            st.session_state.pop(_REPORT_KEY, None)
            return
        st.session_state[_REPORT_KEY] = report
    if st.button("Clear this result", key="vw_upload_clear"):
        st.session_state.pop(REPORT_ID_KEY, None)
        st.session_state.pop(_REPORT_KEY, None)
        st.rerun()
    render_report(report, client)
