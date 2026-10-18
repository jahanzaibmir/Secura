"""Settings page: AI provider, engines and environment."""
from __future__ import annotations

import streamlit as st

from backend.schemas import AISettingsResponse
from ui import services
from ui.client import ApiError
from ui.components import badges
from ui.components.empty import backend_unreachable
from ui.format import esc
from ui.settings import SETTINGS


def render() -> None:
    client = services.client()
    try:
        ai = client.ai_settings()
    except ApiError:
        backend_unreachable()
        return
    health = services.health()

    st.html("<div class='sc-page-head'><h1>Settings</h1>"
            "<p>Choose how findings are explained and review what this server can scan.</p></div>")

    st.html("<div class='sc-section-title' style='margin-top:0'>AI explanations</div>")
    st.html(_provider_card(ai))

    local_tab, cloud_tab, custom_tab = st.tabs(["Local (Ollama)", "Cloud API key", "Custom endpoint"],
                                               key="settings.ai.tabs")
    with local_tab:
        _local(ai)
    with cloud_tab:
        _cloud()
    with custom_tab:
        _custom()

    if health is not None:
        st.html("<div class='sc-section-title'>Engines</div>")
        rows = "".join(
            f"<tr><td><span class='sc-status'>{badges.dot(e.available)}{esc(e.label)}</span></td>"
            f"<td class='sc-muted'>{esc(e.detail or e.description)}</td></tr>"
            for e in health.engines
        )
        st.html(f"<div class='sc-card' style='padding:0.4rem 0.8rem'><table class='sc-table'>{rows}</table></div>")

        st.html(
            "<div class='sc-section-title'>Environment</div><dl class='sc-kv'>"
            f"<dt>Secura</dt><dd>{esc(health.version)}</dd>"
            f"<dt>Backend</dt><dd class='sc-mono'>{esc(SETTINGS.api_url)}</dd>"
            f"<dt>Active scans</dt><dd>{health.active_scans} running · {health.queued_scans} queued</dd>"
            f"<dt>Server folders</dt><dd>{'Allowed' if health.allow_local_paths else 'Disabled (uploads only)'}</dd>"
            "</dl>"
        )


def _provider_card(ai: AISettingsResponse) -> str:
    key = f" · key {esc(ai.key_masked)}" if ai.key_set else ""
    state = "Ready" if ai.ready else "Not ready"
    return (
        "<div class='sc-card'><div class='sc-provider'>"
        f"<div style='flex:1;min-width:0'><div class='sc-provider-name'>{esc(ai.provider_label)}</div>"
        f"<div class='sc-provider-sub sc-mono'>{esc(ai.model)}{key}</div></div>"
        f"<span class='sc-status'>{badges.dot(ai.ready)}{state}</span></div>"
        f"<div class='sc-note' style='margin-top:0.8rem'>{esc(ai.message)}</div></div>"
    )


def _apply(action, *args, success: str) -> None:
    try:
        with st.spinner("Verifying with the provider"):
            result = action(*args)
    except ApiError as exc:
        st.error(exc.message, icon=":material/error:")
        return
    services.health.clear()
    st.toast(f"{success}: {result.provider_label} · {result.model}", icon=":material/check_circle:")
    st.rerun()


def _local(ai: AISettingsResponse) -> None:
    st.caption("Runs on this machine with Ollama. Findings never leave the server.")
    if not ai.local_models:
        st.info("No local models found. Install Ollama, then run `ollama pull mistral:7b` and `ollama serve`.",
                icon=":material/info:")
        return
    current = ai.model if ai.provider == "ollama" and ai.model in ai.local_models else ai.local_models[0]
    model_col, button_col = st.columns([4, 1], vertical_alignment="bottom")
    model = model_col.selectbox("Model", ai.local_models, index=ai.local_models.index(current),
                                key="settings.local.model")
    if button_col.button("Use model", type="primary", width="stretch", key="settings.local.apply"):
        _apply(services.client().update_ai, "ollama", "", "", model, success="Switched")


def _cloud() -> None:
    st.caption("Paste a key from Mistral, Groq, OpenAI or OpenRouter. The provider and best model are detected "
               "and verified live. Keys stay in server memory only and are never written to disk.")
    with st.form("settings.cloud", border=False, clear_on_submit=True):
        key_col, button_col = st.columns([4, 1], vertical_alignment="bottom")
        key = key_col.text_input("API key", type="password", placeholder="gsk_… · sk-… · sk-or-…",
                                 autocomplete="off")
        submitted = button_col.form_submit_button("Connect", type="primary", width="stretch")
    st.caption("In API mode the text of each explained finding, including code snippets, is sent to the provider.")
    if submitted:
        if len(key.strip()) < 20:
            st.warning("That does not look like a complete API key.", icon=":material/info:")
        else:
            _apply(services.client().connect_key, key.strip(), success="Connected")


def _custom() -> None:
    st.caption("Any OpenAI-compatible endpoint, such as vLLM, LiteLLM or a private gateway.")
    with st.form("settings.custom", border=False, clear_on_submit=False):
        base = st.text_input("Base URL", placeholder="https://llm.internal.example/v1")
        model_col, key_col = st.columns(2)
        model = model_col.text_input("Model", placeholder="llama-3.1-8b-instruct")
        key = key_col.text_input("API key", type="password", autocomplete="off")
        submitted = st.form_submit_button("Save endpoint", type="primary")
    if submitted:
        if not (base.strip() and model.strip() and key.strip()):
            st.warning("Base URL, model and key are all required.", icon=":material/info:")
        else:
            _apply(services.client().update_ai, "custom", base.strip(), key.strip(), model.strip(), success="Connected")
