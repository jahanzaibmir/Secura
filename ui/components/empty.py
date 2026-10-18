"""Empty and error states."""
from __future__ import annotations

import streamlit as st

from ui.format import esc


def empty_state(title: str, body: str = "") -> None:
    st.html(f"<div class='sc-empty'><strong>{esc(title)}</strong>{esc(body)}</div>")


def backend_unreachable() -> None:
    st.error(
        "The Secura backend is not reachable. Start everything with `python run_secura.py`, "
        "or point the interface at your API with `SECURA_API_URL`.",
        icon=":material/cloud_off:",
    )
