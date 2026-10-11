"""AI Setup — paste a key; the backend detects and verifies everything else."""
from html import escape as _esc

import streamlit as st


def render_ai_setup(client) -> None:
    st.markdown(
        "<div class='sc-kicker'>Configuration</div><h2>AI setup</h2>",
        unsafe_allow_html=True,
    )
    current = client.get_ai_settings()
    if current is None:
        st.error("The Secura backend is not reachable.")
        return

    _render_status_card(current)

    if current.provider == "api":
        if st.button("Switch back to local Ollama", key="sc_ai_local"):
            resp, err = client.set_ai_settings("ollama")
            if resp is not None:
                st.success("Back to local mode. Findings stay on this machine.")
                st.rerun()
            elif err:
                st.error(err)

    st.markdown("<div class='sc-kicker'>Connect an AI provider</div>",
                unsafe_allow_html=True)
    st.markdown(
        "<p class='sc-target-help'>Paste an API key. The provider, endpoint, "
        "and best model are detected and verified automatically. Free keys: "
        "console.groq.com · console.mistral.ai · openrouter.ai/keys</p>",
        unsafe_allow_html=True,
    )
    key = st.text_input(
        "API key", type="password", key="sc_ai_key_simple",
        placeholder="Works with Mistral, Groq, OpenAI, OpenRouter",
    )

    if st.button("Connect", key="sc_ai_connect", type="primary"):
        if not key.strip():
            st.warning("Paste an API key first.")
        else:
            with st.spinner(
                "Verifying key. Detecting provider, ranking models, "
                "and testing a live request…"
            ):
                resp, err = client.connect_api_key(key.strip())
            if resp is not None:
                st.success(
                    f"Connected: {resp.provider_label} · {resp.model}"
                    + (f" · key {resp.key_masked}" if resp.key_set else "")
                )
                st.session_state.pop("sc_ai_key_simple", None)
                st.rerun()
            elif err:
                st.error(err)

    with st.expander("Advanced · custom endpoint"):
        st.markdown(
            "<p class='sc-target-help'>For self hosted endpoints that speak "
            "the OpenAI format, auto detection is not possible. Base URL, "
            "model, and key are all required.</p>",
            unsafe_allow_html=True,
        )
        base = st.text_input("API base URL", key="sc_ai_base")
        model = st.text_input("Model", key="sc_ai_model")
        ckey = st.text_input("API key", type="password", key="sc_ai_key_adv")
        st.markdown(
            "<div class='sc-ai-warn'>In API mode the text of each finding, "
            "including the scanned source code, is sent to the chosen "
            "provider for analysis.</div>",
            unsafe_allow_html=True,
        )
        if st.button("Save custom endpoint", key="sc_ai_save_adv"):
            if not (base and model and ckey):
                st.warning("All three fields are required for custom endpoints.")
            else:
                resp, err = client.set_ai_settings("custom", base, ckey, model)
                if resp is not None:
                    st.success(
                        f"Connected: {resp.provider_label} · {resp.model}")
                    st.session_state.pop("sc_ai_key_adv", None)
                    st.rerun()
                elif err:
                    st.error(err)

    st.markdown(
        "<p class='sc-target-help'>Keys live in backend memory only. Enter "
        "the key again after a backend restart. Keys are never written to "
        "disk and never logged.</p>",
        unsafe_allow_html=True,
    )


def _render_status_card(current) -> None:
    dot = "sc-dot-on" if current.ready else "sc-dot-off"
    key_part = (f"<span class='sc-finding-conf'>key {current.key_masked}</span>"
                if current.key_set else "")
    st.markdown(
        f"""
        <div class="sc-card">
          <div class="sc-kicker">Active provider</div>
          <div class="sc-ai-current">
            <span class="sc-pill"><span class="sc-dot {dot}"></span>
              {_esc(current.provider_label)}</span>
            <span class="sc-finding-loc">{_esc(current.model)}</span>
            {key_part}
          </div>
          <p class="sc-target-help">{_esc(current.message)}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
