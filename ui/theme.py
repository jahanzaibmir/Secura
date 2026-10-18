"""Loads the stylesheet layers and injects them into the page."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import streamlit as st

_STYLES = Path(__file__).resolve().parent / "styles"
_LAYERS = ("tokens.css", "chrome.css", "components.css", "report.css")


@lru_cache(maxsize=4)
def _stylesheet(version: tuple) -> str:
    return "\n".join((_STYLES / name).read_text(encoding="utf-8") for name in _LAYERS)


def apply_theme() -> None:
    version = tuple((_STYLES / name).stat().st_mtime_ns for name in _LAYERS)
    st.html(f"<style>{_stylesheet(version)}</style>")
