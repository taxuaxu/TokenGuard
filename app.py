"""Streamlit UI for TokenGuard.

Run:  streamlit run app.py
"""
from __future__ import annotations

import json

import streamlit as st

from tokenguard import AnalysisConfig, analyze
from tokenguard.parser import TokenParseError, parse_token
from tokenguard.rules import ALL_GROUPS

SEV_COLOR = {"CRITICAL": "#b00020", "HIGH": "#d9534f", "MEDIUM": "#e0a800",
             "LOW": "#5bc0de", "INFO": "#6c757d"}

SAMPLE = ("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
          "eyJzdWIiOiJhbGljZSIsInJvbGUiOiJhZG1pbiJ9.")

st.set_page_config(page_title="TokenGuard", page_icon="🛡️", layout="wide")
st.title("🛡️ TokenGuard — JWT Security Analysis")
st.caption("Decodes and inspects a JWT without trusting its signature. For local/lab use.")

tab_static, tab_active = st.tabs(["Static analysis", "Active server test"])

with tab_static:
    with st.sidebar:
        st.header("Options")
        groups = st.multiselect("Rule groups", list(ALL_GROUPS), default=list(ALL_GROUPS))
        max_life_h = st.number_input("Max token lifetime (hours)", 1, 8760, 24)
        expected = st.text_input("Expected algorithms (comma-sep, optional)", "")

    token = st.text_area("Paste a JWT", height=140, placeholder="eyJ...")
    c1, c2 = st.columns([1, 6])
    if c1.button("Use sample (alg=none)"):
        token = SAMPLE
        st.session_state["_tok"] = SAMPLE
    token = token or st.session_state.get("_tok", "")

    if token.strip():
        try:
            parsed = parse_token(token)
        except TokenParseError as exc:
            st.error(f"Could not parse token: {exc}")
        else:
            cfg = AnalysisConfig(
                max_lifetime_seconds=int(max_life_h) * 3600,
                expected_algs=[a.strip() for a in expected.split(",") if a.strip()] or None,
            )
            findings = analyze(parsed, groups=groups or list(ALL_GROUPS), config=cfg)

            left, right = st.columns(2)
            left.subheader("Header")
            left.json(parsed.header)
            right.subheader("Payload")
            right.json(parsed.payload)

            st.subheader(f"Findings ({len(findings)})")
            if not findings:
                st.success("No issues found.")
            for f in findings:
                color = SEV_COLOR.get(str(f.severity), "#6c757d")
                st.markdown(
                    f"<span style='background:{color};color:#fff;padding:2px 8px;"
                    f"border-radius:4px;font-size:0.8em'>{f.severity}</span> "
                    f"**{f.title}** &nbsp;`{f.rule_id}` · _{f.part}_",
                    unsafe_allow_html=True,
                )
                st.write(f.explanation)
                if f.evidence:
                    st.code(f.evidence, language="text")
                st.divider()

            st.download_button("Download findings (JSON)",
                               json.dumps([f.to_dict() for f in findings], indent=2),
                               file_name="tokenguard_findings.json")

with tab_active:
    st.subheader("Active testing against a local lab server")
    st.caption("Sends crafted tokens to a locally hosted misconfigured server and records "
               "which attacks are accepted. Start it with `python vuln_server/app.py`.")
    target = st.text_input("Target (localhost only)", "http://127.0.0.1:5000")
    secret = st.text_input("Known HMAC secret (optional)", "")
    if st.button("Run active tests"):
        from tokenguard.active.runner import HttpClient, format_results, run_active_tests, summarize
        try:
            client = HttpClient(target)
            results = run_active_tests(client=client, secret=secret or None)
        except Exception as exc:  # noqa: BLE001
            st.error(f"{type(exc).__name__}: {exc}")
        else:
            rows = [{"endpoint": r.endpoint, "attack": r.attack, "status": r.status,
                     "accepted": r.accepted, "vulnerable": r.vulnerable, "note": r.note}
                    for r in results]
            st.dataframe(rows, use_container_width=True)
            st.subheader("Detected flaws per endpoint")
            for ep, flaws in summarize(results).items():
                st.write(f"**{ep}** → {', '.join(flaws) if flaws else '_no flaws detected_'}")
