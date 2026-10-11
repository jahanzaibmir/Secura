"""Secura — interface. Launch via `python run_secura.py`."""
import os
import sys
from html import escape as _esc
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st  # noqa: E402

from backend.api.schemas import ScanRequest, TargetType  # noqa: E402
from ui.api_client import VulnWeaveClient  # noqa: E402
from ui.components.secura_ai_setup import render_ai_setup  # noqa: E402
from ui.components.secura_folder_upload import render_folder_upload  # noqa: E402
from ui.components.secura_hero import render_hero  # noqa: E402
from ui.components.secura_history import render_history  # noqa: E402
from ui.components.secura_progress import run_scan_with_progress  # noqa: E402
from ui.components.secura_report_view import render_report  # noqa: E402
from ui.components.secura_target_input import render_target_form  # noqa: E402
from ui.components.secura_upload_recent import (  # noqa: E402
    REPORT_ID_KEY, render_recent_uploads, render_upload_report,
)
from ui.theme import inject_theme  # noqa: E402

BACKEND_URL = os.getenv("VW_API_URL", "http://127.0.0.1:8642")

GITHUB_REPORT_KEY = "vw_report_github_repo"


def _public_origin() -> str:
    explicit = os.getenv("VW_PUBLIC_API_URL")
    if explicit:
        return explicit.rstrip("/")
    """Origin for URLs the browser opens (report links, uploads).
    In production (VW_PROD=1, behind nginx) the UI and API share one
    origin, so it is derived from the request headers. In development
    it is simply the backend URL."""
    if os.getenv("VW_PROD") != "1":
        return BACKEND_URL
    try:
        headers = st.context.headers
        host = headers.get("Host") or headers.get("host")
        if host:
            proto = "https" if headers.get("X-Forwarded-Proto") == "https" else "http"
            return f"{proto}://{host}"
    except Exception:
        pass
    return BACKEND_URL


def render_status_strip(health: dict) -> None:
    ai = health.get("ollama") or {}
    provider = ai.get("provider", "ollama")
    reachable = bool(ai.get("reachable"))
    ai_ready = bool(ai.get("ai_ready"))
    model = str(ai.get("model") or "mistral:7b")
    pills = [
        (health.get("status") == "ok", "Backend"),
        (reachable, "API" if provider == "api" else "Ollama"),
        (ai_ready, _esc(model)),
    ]
    parts = "".join(
        f"<span class='vw-pill'><span class='vw-dot "
        f"{'vw-dot-on' if on else 'vw-dot-off'}'></span>{name}</span>"
        for on, name in pills
    )
    version_note = f"v{_esc(str(health.get('version', '')))}"
    if provider == "api":
        if not reachable:
            note = "API unreachable. Open Settings"
        elif not ai_ready:
            note = "API key problem. Open Settings"
        else:
            note = version_note
    elif not reachable:
        note = "Ollama not running. Start it with ollama serve"
    elif not ai.get("model_installed"):
        note = f"run once: ollama pull {_esc(model)}"
    elif not ai.get("ai_enabled", True):
        note = "AI explanations disabled (VW_ENABLE_AI=0)"
    else:
        note = version_note
    st.markdown(
        f"<div class='vw-strip'>{parts}"
        f"<span class='vw-strip-note'>{note}</span></div>",
        unsafe_allow_html=True,
    )


def main() -> None:
    st.set_page_config(
        page_title="Secura",
        page_icon="⬛",
        layout="wide",
        initial_sidebar_state="collapsed",
    )
    inject_theme()
    render_hero()

    client = VulnWeaveClient(BACKEND_URL, public_base=_public_origin())
    health = client.health()
    if health is None:
        st.error(
            "The Secura backend is not reachable. "
            "Start everything with `python run_secura.py`."
        )
        st.stop()
    render_status_strip(health)

    tab_scanner, tab_results, tab_history, tab_settings = st.tabs(
        ["Scanner", "Results", "History", "Settings"])

    # ── Scanner ────────────────────────────────────────────────────
    with tab_scanner:
        col_github, col_upload = st.columns(2, gap="large")

        with col_github:
            target, pressed = render_target_form(
                "GitHub Repository", TargetType.GITHUB_REPO.value,
                "https://github.com/owner/repo",
                "Any public GitHub repository URL.")
            if pressed:
                if not target:
                    st.warning("Enter a repository URL first.")
                else:
                    report = run_scan_with_progress(
                        client,
                        ScanRequest(target_type=TargetType.GITHUB_REPO,
                                    target=target),
                    )
                    if report is not None:
                        st.session_state[GITHUB_REPORT_KEY] = report
                        st.success("Scan complete. Open the Results tab.")

        with col_upload:
            st.markdown(
                "<div class='vw-target-card'>"
                "<div class='vw-kicker'>Upload a codebase</div>"
                "<p class='vw-target-help'>Pick a folder from this machine. "
                "Python and JavaScript files are uploaded, scanned, and then "
                "deleted automatically. Your scans stay listed below even "
                "after switching tabs or reloading.</p></div>",
                unsafe_allow_html=True,
            )
            render_folder_upload(BACKEND_URL, _public_origin())

        render_recent_uploads(client)

    # ── Results ────────────────────────────────────────────────────
    with tab_results:
        github_report = st.session_state.get(GITHUB_REPORT_KEY)
        upload_ready = bool(st.session_state.get(REPORT_ID_KEY))
        if github_report is None and not upload_ready:
            st.markdown(
                "<div class='vw-empty'>Nothing here yet. Run a scan from "
                "the Scanner tab, then open Results.</div>",
                unsafe_allow_html=True,
            )
        if github_report is not None:
            st.markdown("<div class='vw-kicker'>GitHub scan</div>",
                        unsafe_allow_html=True)
            render_report(github_report, client)
        if upload_ready:
            render_upload_report(client)

    # ── History ────────────────────────────────────────────────────
    with tab_history:
        render_history(client)

    # ── Settings ───────────────────────────────────────────────────
    with tab_settings:
        render_ai_setup(client)

    st.markdown(
        "<div class='vw-foot'><span>Secura · a defensive security tool</span>"
        "<span>Scan only code you own or are authorized to test</span></div>",
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
