"""Injects the Secura monochrome design system into Streamlit."""
from pathlib import Path

import streamlit as st

_ASSETS = Path(__file__).resolve().parent / "assets"


def inject_theme() -> None:
    css = (_ASSETS / "secura_style.css").read_text(encoding="utf-8")
    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)
