"""Secura interface entry point. Launch everything with ``python run_secura.py``."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st  # noqa: E402

from ui import navigation  # noqa: E402
from ui.theme import apply_theme  # noqa: E402
from ui.views import history, report, scan, settings  # noqa: E402

ASSETS = Path(__file__).resolve().parent / "assets"


def main() -> None:
    st.set_page_config(
        page_title="Secura",
        page_icon=str(ASSETS / "mark-light.svg"),
        layout="wide",
        initial_sidebar_state="collapsed",
    )
    apply_theme()

    theme = "dark" if getattr(st.context.theme, "type", "light") == "dark" else "light"
    logo = str(ASSETS / f"logo-{theme}.svg")
    st.logo(logo, icon_image=logo, size="large")

    pages = {
        "scan": st.Page(scan.render, title="Scan", icon=":material/radar:", url_path="scan", default=True),
        "reports": st.Page(history.render, title="Reports", icon=":material/folder_open:", url_path="reports"),
        "report": st.Page(report.render, title="Report", icon=":material/description:", url_path="report",
                          visibility="hidden"),
        "settings": st.Page(settings.render, title="Settings", icon=":material/tune:", url_path="settings"),
    }
    for name, page in pages.items():
        navigation.register(name, page)

    st.navigation(list(pages.values()), position="top").run()


main()
