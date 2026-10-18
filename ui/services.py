"""Cached access to backend resources shared across pages and reruns."""
from __future__ import annotations

import streamlit as st

from backend.schemas import HealthResponse, Report
from ui.client import ApiError, SecuraClient
from ui.settings import SETTINGS


@st.cache_resource(show_spinner=False)
def client() -> SecuraClient:
    return SecuraClient(SETTINGS.api_url, timeout=SETTINGS.request_timeout)


@st.cache_data(ttl=600, max_entries=64, show_spinner=False)
def report(report_id: str) -> Report:
    return client().get_report(report_id)


@st.cache_data(ttl=600, max_entries=128, show_spinner=False)
def export(report_id: str, fmt: str) -> bytes:
    return client().export_report(report_id, fmt)


@st.cache_data(ttl=10, show_spinner=False)
def health() -> HealthResponse | None:
    try:
        return client().health()
    except ApiError:
        return None


def forget_report(report_id: str) -> None:
    report.clear()
    export.clear()
