"""Page registry, so views can link to each other without import cycles."""
from __future__ import annotations

import streamlit as st

_PAGES: dict[str, st.Page] = {}


def register(name: str, page) -> None:
    _PAGES[name] = page


def page(name: str):
    return _PAGES[name]


def go(name: str, **query: str) -> None:
    st.switch_page(_PAGES[name], query_params=query or None)


def open_report(report_id: str | None) -> None:
    if report_id:
        go("report", id=report_id)
