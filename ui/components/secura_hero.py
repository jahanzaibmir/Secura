"""Hero header with the layered 3D Secura mark."""
import streamlit as st


def render_hero() -> None:
    st.markdown(
        """
        <div class="vw-hero">
          <div class="vw-hero-grid">
            <div class="vw-mark-wrap">
              <div class="vw-mark"><span></span><span></span><span></span></div>
              <div class="vw-mark-shadow"></div>
            </div>
            <div class="vw-hero-copy">
              <div class="vw-kicker">Local · Private · Defensive</div>
              <h1>Secura</h1>
              <p class="vw-hero-sub">Finds security holes in your code, explains
              every one in plain English, and shows exactly how to fix it.</p>
              <div class="vw-hero-tags">
                <span class="vw-hero-tag">GitHub repositories</span>
                <span class="vw-hero-tag">Folder uploads</span>
                <span class="vw-hero-tag">AI analysis</span>
                <span class="vw-hero-tag">Runs on your machine</span>
              </div>
            </div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
