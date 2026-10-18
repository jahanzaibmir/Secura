"""Scan page: choose a source, follow the live pipeline, open the result."""
from __future__ import annotations

import io
import zipfile
from pathlib import PurePosixPath

import streamlit as st

from backend.engines.inventory import is_relevant_path
from backend.schemas import HealthResponse, JobStatus, JobView, ReportMeta
from ui import navigation, services
from ui.client import ApiError
from ui.components import badges
from ui.components.empty import backend_unreachable
from ui.components.job_card import completion_card, job_card
from ui.format import TARGET_ICONS, display_target, duration, esc, time_ago

ACTIVE_JOB = "scan.active_job"
UPLOAD_NONCE = "scan.upload_nonce"

FOLDER_FILE_LIMIT_MB = 10

SOURCES = {
    "github": ":material/code: GitHub repository",
    "folder": ":material/folder_open: Folder",
    "archive": ":material/folder_zip: Zip archive",
}


def render() -> None:
    st.html(
        "<div class='sc-hero'>"
        "<div class='sc-eyebrow'><span class='sc-dot is-ok'></span>"
        "Static analysis · Secrets · Dependency audit · Containers</div>"
        "<h1>Find and fix security issues before they ship.</h1>"
        "<p>Point Secura at a repository or a folder. Five engines inspect the code, and every "
        "finding comes with a plain-language explanation and a concrete fix.</p></div>"
    )

    health = services.health()
    if health is None:
        backend_unreachable()
        return

    with st.container(border=True):
        source = st.segmented_control(
            "Source", options=list(SOURCES), format_func=SOURCES.get,
            default="github", required=True, key="scan.source", label_visibility="collapsed",
        )
        if source == "folder":
            _folder_form()
        elif source == "archive":
            _archive_form()
        else:
            _github_form()
        st.html(_capabilities(health))

    _active_panel()
    _recent_activity()


def _capabilities(health: HealthResponse) -> str:
    engines = "".join(
        f"<span class='sc-pill'>{badges.dot(e.available)}{esc(e.label)}</span>" for e in health.engines
    )
    ai = health.ai
    ai_label = f"{ai.provider_label} · {ai.model}" if ai.enabled else "AI disabled"
    ai_pill = f"<span class='sc-pill' title='{esc(ai.message)}'>{badges.dot(ai.ready)}{esc(ai_label)}</span>"
    return f"<div class='sc-engines'>{engines}{ai_pill}</div>"


def _start(action, *args) -> None:
    try:
        accepted = action(*args)
    except ApiError as exc:
        st.error(exc.message, icon=":material/error:")
        return
    st.session_state[ACTIVE_JOB] = accepted.job_id
    st.session_state[UPLOAD_NONCE] = st.session_state.get(UPLOAD_NONCE, 0) + 1
    st.rerun()


def _github_form() -> None:
    with st.form("scan.github", border=False, enter_to_submit=True):
        url_col, button_col = st.columns([5, 1], vertical_alignment="bottom")
        target = url_col.text_input(
            "Repository", placeholder="https://github.com/owner/repository  or  owner/repository",
            label_visibility="collapsed",
        )
        submitted = button_col.form_submit_button("Scan", type="primary", width="stretch",
                                                  icon=":material/arrow_forward:")
    st.caption("Public repositories only. A shallow clone is scanned in an isolated workspace and deleted afterwards.")
    if submitted:
        if not target.strip():
            st.warning("Enter a repository URL first.", icon=":material/info:")
        else:
            _start(services.client().start_scan, target.strip())


def _zip_files(files: list) -> tuple:
    buffer = io.BytesIO()
    kept = 0
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for upload in files:
            name = (upload.name or "").replace("\\", "/")
            if not is_relevant_path(name):
                continue
            archive.writestr(name, upload.getvalue())
            kept += 1
    return buffer.getvalue(), kept


def _folder_form() -> None:
    nonce = st.session_state.get(UPLOAD_NONCE, 0)
    files = st.file_uploader(
        "Folder", accept_multiple_files="directory", max_upload_size=FOLDER_FILE_LIMIT_MB,
        key=f"scan.folder.{nonce}", label_visibility="collapsed",
    )
    st.caption("Only source, configuration, Dockerfiles and lockfiles are kept, and uploads are deleted as soon "
               "as the scan finishes. For folders with node_modules or virtual environments, a zip or GitHub "
               "scan is faster.")
    if not files:
        return
    relevant = [f for f in files if is_relevant_path((f.name or "").replace("\\", "/"))]
    size = sum(f.size for f in relevant)
    root = PurePosixPath((files[0].name or "upload").replace("\\", "/")).parts[0]
    info_col, button_col = st.columns([5, 1], vertical_alignment="center")
    info_col.markdown(f"**{esc(root)}** · {len(relevant)} of {len(files)} files will be scanned · "
                      f"{size / 1_048_576:.1f} MB")
    if button_col.button("Scan", type="primary", width="stretch", icon=":material/arrow_forward:",
                         key="scan.folder.submit"):
        with st.spinner("Packaging files"):
            payload, kept = _zip_files(relevant)
        if kept == 0:
            st.warning("None of the selected files can be scanned.", icon=":material/info:")
            return
        _start(services.client().upload_archive, root, f"{root}.zip", payload)


def _archive_form() -> None:
    nonce = st.session_state.get(UPLOAD_NONCE, 0)
    upload = st.file_uploader("Archive", type=["zip"], key=f"scan.archive.{nonce}", label_visibility="collapsed")
    st.caption("Upload a .zip of your project. Paths are sanitised and unpacking is size-limited.")
    if upload is None:
        return
    name = PurePosixPath(upload.name).stem or "archive"
    info_col, button_col = st.columns([5, 1], vertical_alignment="center")
    info_col.markdown(f"**{esc(upload.name)}** · {upload.size / 1_048_576:.1f} MB")
    if button_col.button("Scan", type="primary", width="stretch", icon=":material/arrow_forward:",
                         key="scan.archive.submit"):
        _start(services.client().upload_archive, name, upload.name, upload.getvalue())


def _fetch(job_id: str) -> JobView | None:
    try:
        return services.client().get_scan(job_id)
    except ApiError:
        return None


def _active_panel() -> None:
    job_id = st.session_state.get(ACTIVE_JOB)
    if not job_id:
        return
    view = _fetch(job_id)
    if view is None:
        st.session_state.pop(ACTIVE_JOB, None)
        return
    st.html("<div class='sc-section-title'>Current scan</div>")
    if view.status.is_terminal:
        _finished(view)
    else:
        _live_job()


@st.fragment(run_every=1.0)
def _live_job() -> None:
    job_id = st.session_state.get(ACTIVE_JOB)
    view = _fetch(job_id) if job_id else None
    if view is None:
        return
    if view.status.is_terminal:
        st.rerun()
    st.html(job_card(view))
    if st.button("Cancel scan", icon=":material/stop_circle:", key="scan.cancel", type="tertiary"):
        try:
            services.client().cancel_scan(view.job_id)
        except ApiError as exc:
            st.error(exc.message)


def _finished(view: JobView) -> None:
    if view.status == JobStatus.COMPLETED:
        st.html(completion_card(view))
        open_col, dismiss_col, _ = st.columns([1.3, 1, 4])
        if open_col.button("Open report", type="primary", icon=":material/description:",
                           width="stretch", key="scan.open"):
            st.session_state.pop(ACTIVE_JOB, None)
            navigation.open_report(view.report_id)
        if dismiss_col.button("New scan", width="stretch", key="scan.dismiss"):
            st.session_state.pop(ACTIVE_JOB, None)
            st.rerun()
        return
    st.html(job_card(view))
    if st.button("Dismiss", key="scan.dismiss.failed"):
        st.session_state.pop(ACTIVE_JOB, None)
        st.rerun()


def _recent_activity() -> None:
    client = services.client()
    try:
        jobs = client.list_scans()
        reports = client.list_reports(limit=6)
    except ApiError:
        return
    active = st.session_state.get(ACTIVE_JOB)
    running = [j for j in jobs if not j.status.is_terminal and j.job_id != active]
    if not running and not reports:
        return
    st.html("<div class='sc-section-title'>Recent</div>")
    with st.container(border=True):
        for index, job in enumerate(running):
            _divider(index)
            st.html(_job_row(job))
        for index, meta in enumerate(reports, start=len(running)):
            _divider(index)
            _report_row(meta)


def _divider(index: int) -> None:
    if index:
        st.html("<div style='border-top:1px solid var(--sc-line);margin:0.1rem 0'></div>")


def _job_row(job: JobView) -> str:
    return (
        "<div class='sc-row'><span class='sc-grade is-sm' style='--grade: var(--sc-running)'>…</span>"
        f"<div class='sc-row-main'><div class='sc-row-title'>{esc(job.label)}</div>"
        f"<div class='sc-row-sub'>{esc(TARGET_ICONS.get(job.target_type, ''))} · "
        f"{esc(job.current_stage or 'Queued')}</div></div>{badges.status(job.status, job.progress)}</div>"
    )


def _report_row(meta: ReportMeta) -> None:
    info_col, action_col = st.columns([8, 1], vertical_alignment="center")
    took = ""
    if meta.finished_at and meta.started_at:
        took = f" · {duration((meta.finished_at - meta.started_at).total_seconds())}"
    info_col.html(
        f"<div class='sc-row'>{badges.grade(meta.risk, 'sm')}"
        f"<div class='sc-row-main'><div class='sc-row-title'>{esc(display_target(meta.target, meta.target_type))}</div>"
        f"<div class='sc-row-sub'><span>{esc(TARGET_ICONS.get(meta.target_type, ''))} · "
        f"{esc(time_ago(meta.finished_at or meta.started_at))}{esc(took)}</span>"
        f"{badges.severity_counts(meta.summary)}</div></div></div>"
    )
    if action_col.button("Open", key=f"scan.recent.{meta.report_id}", type="tertiary",
                         icon=":material/chevron_right:", icon_position="right"):
        navigation.open_report(meta.report_id)
