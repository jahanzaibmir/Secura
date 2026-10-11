"""Live scan progress — poll a job and render pipeline stages."""
import time
from html import escape as _esc
from typing import Optional

import streamlit as st

from backend.api.schemas import JobStatus, Report, ScanRequest
from backend.config import settings
from ui.api_client import VulnWeaveClient

_POLL_SECONDS = 1.2
_MAX_WAIT_SECONDS = settings.scan_timeout + 60

_STAGE_GLYPH = {"done": "●", "running": "◐", "pending": "○", "skipped": "◌"}


def _render_stages(view) -> str:
    rows = []
    for stage in view.stages:
        css = f"vw-step vw-step-{stage.status}"
        glyph = _STAGE_GLYPH.get(stage.status, "○")
        detail = (
            f"<span class='vw-step-detail'>{_esc(stage.detail)}</span>"
            if stage.detail else ""
        )
        rows.append(
            f"<div class='{css}'><span class='vw-step-glyph'>{glyph}</span>"
            f"<span class='vw-step-name'>{_esc(stage.name)}</span>{detail}</div>"
        )
    return "<div class='vw-steps'>" + "".join(rows) + "</div>"


def poll_job(client: VulnWeaveClient, job_id: str) -> Optional[Report]:
    """Poll an existing job until it completes; render live progress."""
    steps_box = st.empty()
    bar = st.progress(0, text="Queued…")
    deadline = time.time() + _MAX_WAIT_SECONDS

    while time.time() < deadline:
        view = client.get_job(job_id)
        if view is None:
            bar.empty()
            steps_box.empty()
            st.error("Lost track of the scan job. The backend may have "
                     "restarted, so run the scan again.")
            return None

        steps_box.markdown(_render_stages(view), unsafe_allow_html=True)
        label = view.current_stage or view.status.value
        bar.progress(min(view.progress, 100), text=f"{label} · {view.progress}%")

        if view.status == JobStatus.COMPLETED:
            bar.empty()
            steps_box.empty()
            if view.report is not None:
                return view.report
            st.error("Scan completed but no report was produced.")
            return None

        if view.status == JobStatus.FAILED:
            bar.empty()
            steps_box.empty()
            st.error(f"Scan failed: {view.error or 'unknown error'}")
            return None

        time.sleep(_POLL_SECONDS)

    bar.empty()
    steps_box.empty()
    st.warning("The browser stopped waiting, but the scan still runs "
               "on the backend. It will appear under History when it finishes.")
    return None


def run_scan_with_progress(client: VulnWeaveClient,
                           request: ScanRequest) -> Optional[Report]:
    accepted = client.start_scan(request)
    if accepted is None:
        st.error("Could not reach the Secura backend. Is it running?")
        return None
    return poll_job(client, accepted.job_id)
