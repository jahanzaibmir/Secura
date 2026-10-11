"""Per-tab target input card."""
import streamlit as st


def render_target_form(title: str, key: str, placeholder: str, help_text: str):
    st.markdown(
        f"""
        <div class="sc-target-card">
          <div class="sc-kicker">{title}</div>
          <p class="sc-target-help">{help_text}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    target = st.text_input(
        label=f"{title} target",
        placeholder=placeholder,
        key=f"sc_input_{key}",
        label_visibility="collapsed",
    )
    pressed = st.button("Run scan", key=f"sc_scan_{key}", type="primary")
    return target.strip(), pressed
