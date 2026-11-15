"""TokenGuard control panel (Streamlit).

A visual dashboard to run and watch every part of TokenGuard:
  * Static analysis of a pasted JWT, with severity badges and a chart
  * Active testing against the local vulnerable server (endpoint x attack matrix)
  * The OAuth 2.1 MCP case study (secure vs misconfigured)
  * Evaluation scores (precision/recall/F1) and the jwt_tool baseline

Run:  streamlit run app.py
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pandas as pd
import streamlit as st

from tokenguard import AnalysisConfig, analyze
from tokenguard.parser import TokenParseError, parse_token
from tokenguard.rules import ALL_GROUPS

ROOT = Path(__file__).resolve().parent

SEV_COLOR = {"CRITICAL": "#b00020", "HIGH": "#d9534f", "MEDIUM": "#e0a800",
             "LOW": "#5bc0de", "INFO": "#6c757d"}
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

SAMPLE_NONE = ("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
               "eyJzdWIiOiJhbGljZSIsInJvbGUiOiJhZG1pbiJ9.")

# Lab servers the panel can launch. key -> (label, command, health path)
SERVERS = {
    "vuln": ("Vulnerable server :5000", [sys.executable, str(ROOT / "vuln_server" / "app.py")],
             "http://127.0.0.1:5000", "/endpoints"),
    "mcp_secure": ("MCP secure :7000",
                   [sys.executable, str(ROOT / "mcp_server" / "server.py"), "--port", "7000"],
                   "http://127.0.0.1:7000", "/.well-known/oauth-protected-resource"),
    "mcp_insecure": ("MCP misconfigured :7001",
                     [sys.executable, str(ROOT / "mcp_server" / "server.py"),
                      "--insecure", "--port", "7001"],
                     "http://127.0.0.1:7001", "/.well-known/oauth-protected-resource"),
}


# ----------------------------------------------------------------- server control

def _ping(base: str, path: str) -> bool:
    import requests
    try:
        requests.get(base + path, timeout=1.0)
        return True
    except requests.RequestException:
        return False


def is_up(key: str) -> bool:
    _, _, base, path = SERVERS[key]
    return _ping(base, path)


def start_server(key: str):
    if is_up(key):
        return
    _, cmd, _, _ = SERVERS[key]
    proc = subprocess.Popen(cmd, cwd=str(ROOT), stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    st.session_state.setdefault("procs", {})[key] = proc
    for _ in range(20):
        time.sleep(0.25)
        if is_up(key):
            break


def stop_server(key: str):
    proc = st.session_state.get("procs", {}).get(key)
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
    st.session_state.get("procs", {}).pop(key, None)


def server_controls():
    st.sidebar.header("Lab servers")
    for key, (label, _, _, _) in SERVERS.items():
        up = is_up(key)
        dot = "🟢" if up else "⚪"
        st.sidebar.markdown(f"{dot} **{label}**")
        c1, c2 = st.sidebar.columns(2)
        c1.button("Start", key=f"start_{key}", disabled=up,
                  on_click=start_server, args=(key,), use_container_width=True)
        c2.button("Stop", key=f"stop_{key}", disabled=not up,
                  on_click=stop_server, args=(key,), use_container_width=True)
    st.sidebar.caption("Servers run only on 127.0.0.1 for local testing.")
    st.sidebar.divider()
    st.sidebar.caption("TokenGuard — JWT security analysis")


# ----------------------------------------------------------------- shared widgets

def severity_badge(sev: str) -> str:
    color = SEV_COLOR.get(sev, "#6c757d")
    return (f"<span style='background:{color};color:#fff;padding:2px 8px;"
            f"border-radius:4px;font-size:0.8em;font-weight:600'>{sev}</span>")


def render_findings(findings):
    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        counts[str(f.severity)] += 1

    cols = st.columns(len(SEV_ORDER))
    for col, sev in zip(cols, SEV_ORDER):
        col.markdown(
            f"<div style='text-align:center'>{severity_badge(sev)}"
            f"<div style='font-size:1.6em;font-weight:700'>{counts[sev]}</div></div>",
            unsafe_allow_html=True)

    nonzero = {s: counts[s] for s in SEV_ORDER if counts[s]}
    if nonzero:
        st.bar_chart(pd.DataFrame({"findings": nonzero}), color="#d9534f", height=200)

    for f in findings:
        st.markdown(
            f"{severity_badge(str(f.severity))} &nbsp;**{f.title}** &nbsp;"
            f"`{f.rule_id}` · _{f.part}_", unsafe_allow_html=True)
        st.write(f.explanation)
        if f.evidence:
            st.code(f.evidence, language="text")
        st.divider()


# ----------------------------------------------------------------- page

st.set_page_config(page_title="TokenGuard", page_icon="🛡️", layout="wide")
st.title("🛡️ TokenGuard — Control Panel")
server_controls()

tab_dash, tab_static, tab_active, tab_mcp, tab_eval = st.tabs(
    ["📊 Overview", "🔍 Static analysis", "🎯 Active testing", "🔌 MCP case study",
     "📈 Evaluation"])

# ---- Overview ----
with tab_dash:
    st.subheader("Lab server status")
    cols = st.columns(len(SERVERS))
    for col, (key, (label, _, _, _)) in zip(cols, SERVERS.items()):
        up = is_up(key)
        col.metric(label, "running" if up else "stopped")
    st.info("Use the sidebar to start/stop the local lab servers, then run the "
            "active and MCP tests in their tabs. The static analysis and evaluation "
            "tabs need no server.")
    st.markdown(
        "- **Static analysis** — paste a JWT and see findings by severity.\n"
        "- **Active testing** — send crafted tokens to the vulnerable server and see "
        "which attacks each endpoint accepts.\n"
        "- **MCP case study** — probe the OAuth 2.1 MCP server's authorization rules.\n"
        "- **Evaluation** — precision/recall/F1 and the jwt_tool baseline.")

# ---- Static analysis ----
with tab_static:
    st.subheader("Analyze a JWT")
    groups = st.multiselect("Rule groups", list(ALL_GROUPS), default=list(ALL_GROUPS))
    cc1, cc2 = st.columns(2)
    max_life_h = cc1.number_input("Max token lifetime (hours)", 1, 8760, 24)
    expected = cc2.text_input("Expected algorithms (comma-separated, optional)", "")

    token = st.text_area("Token", height=130, placeholder="eyJ...",
                         value=st.session_state.get("tok", ""))
    b1, _ = st.columns([1, 5])
    if b1.button("Load sample (alg=none)"):
        st.session_state["tok"] = SAMPLE_NONE
        st.rerun()

    if token.strip():
        try:
            parsed = parse_token(token)
        except TokenParseError as exc:
            st.error(f"Could not parse token: {exc}")
        else:
            cfg = AnalysisConfig(
                max_lifetime_seconds=int(max_life_h) * 3600,
                expected_algs=[a.strip() for a in expected.split(",") if a.strip()] or None)
            findings = analyze(parsed, groups=groups or list(ALL_GROUPS), config=cfg)
            left, right = st.columns(2)
            left.caption("Header"); left.json(parsed.header)
            right.caption("Payload"); right.json(parsed.payload)
            st.subheader(f"Findings ({len(findings)})")
            if not findings:
                st.success("No issues found.")
            else:
                render_findings(findings)
                st.download_button("Download findings (JSON)",
                                   json.dumps([f.to_dict() for f in findings], indent=2),
                                   file_name="tokenguard_findings.json")

# ---- Active testing ----
with tab_active:
    st.subheader("Active testing against the vulnerable server")
    up = is_up("vuln")
    st.markdown(("🟢 server is running" if up else
                 "⚪ server is stopped — start **Vulnerable server :5000** in the sidebar"))
    target = st.text_input("Target (localhost only)", "http://127.0.0.1:5000")
    secret = st.text_input("Known HMAC secret (optional)", "")
    if st.button("Run active tests", disabled=not up):
        from tokenguard.active.runner import HttpClient, run_active_tests, summarize
        try:
            results = run_active_tests(client=HttpClient(target), secret=secret or None)
        except Exception as exc:  # noqa: BLE001
            st.error(f"{type(exc).__name__}: {exc}")
        else:
            attacks = ["NO_TOKEN", "BASELINE_VALID", "ALG_NONE", "TAMPERED_SIGNATURE",
                       "EXPIRED_TOKEN", "WRONG_AUDIENCE", "WEAK_KEY_FORGERY"]
            endpoints = sorted({r.endpoint for r in results})
            cell = {(r.endpoint, r.attack): r for r in results}

            def html_cell(r):
                if r is None or r.status is None:
                    return "<td style='background:#e9ecef;color:#666;text-align:center'>–</td>"
                if r.expected_accept:
                    bg, txt = ("#198754", "ACCEPT") if r.accepted else ("#dc3545", "REJECT?")
                elif r.vulnerable:
                    bg, txt = "#dc3545", "VULN"
                else:
                    bg, txt = "#198754", "rejected"
                return (f"<td style='background:{bg};color:#fff;text-align:center;"
                        f"font-size:0.8em'>{txt}</td>")

            head = "".join(f"<th style='font-size:0.75em'>{a}</th>" for a in attacks)
            rows = ""
            for ep in endpoints:
                cells = "".join(html_cell(cell.get((ep, a))) for a in attacks)
                rows += f"<tr><td style='font-weight:600'>{ep}</td>{cells}</tr>"
            st.markdown(
                f"<table style='width:100%;border-collapse:collapse'>"
                f"<tr><th></th>{head}</tr>{rows}</table>", unsafe_allow_html=True)

            st.caption("🟥 VULN = insecure token accepted · 🟩 rejected/accept = correct behavior")
            st.subheader("Detected flaws per endpoint")
            for ep, flaws in summarize(results).items():
                icon = "🔴" if flaws else "🟢"
                st.write(f"{icon} **{ep}** → {', '.join(flaws) if flaws else 'no flaws detected'}")

# ---- MCP case study ----
with tab_mcp:
    st.subheader("OAuth 2.1 MCP server case study")
    c1, c2 = st.columns(2)
    for col, key, port in ((c1, "mcp_secure", 7000), (c2, "mcp_insecure", 7001)):
        up = is_up(key)
        col.markdown(("🟢" if up else "⚪") + f" {SERVERS[key][0]}")
    mcp_target = st.text_input("MCP server (localhost only)", "http://127.0.0.1:7000")
    if st.button("Run MCP probe"):
        from tokenguard.mcp_probe import run_mcp_probe, vulnerabilities
        try:
            results = run_mcp_probe(mcp_target)
        except Exception as exc:  # noqa: BLE001
            st.error(f"{type(exc).__name__}: {exc}")
        else:
            for r in results:
                if r.passed:
                    st.markdown(f"🟢 **{r.check}** — PASS  \n<small>{r.detail}</small>",
                                unsafe_allow_html=True)
                elif r.vulnerability:
                    st.markdown(f"🔴 **{r.check}** — {r.vulnerability}  \n<small>{r.detail}"
                                f"</small>", unsafe_allow_html=True)
                else:
                    st.markdown(f"🟠 **{r.check}** — FAIL  \n<small>{r.detail}</small>",
                                unsafe_allow_html=True)
            vulns = vulnerabilities(results)
            if vulns:
                st.error("Vulnerabilities: " + ", ".join(vulns))
            else:
                st.success("No authorization vulnerabilities detected.")

# ---- Evaluation ----
with tab_eval:
    st.subheader("Detection evaluation")
    jwt_tool_path = st.text_input("jwt_tool.py path (optional, for baseline)", "")
    if st.button("Generate dataset & evaluate"):
        import dataset.generate as gen
        from evaluation.evaluate import (ALL_GROUPS as EVAL_ALL, CONFIGS, LABELED, load,
                                         score, tokenguard_ids)
        from evaluation.baselines import OVERLAP_LABELS, JwtTool

        gen.main()
        records = load()
        pos = sum(1 for r in records if r["labels"])
        st.caption(f"Dataset: {len(records)} tokens ({pos} insecure, {len(records) - pos} secure)")

        table = {}
        for name, grp in CONFIGS.items():
            s = score(records, lambda rec, g=grp: tokenguard_ids(rec, g), LABELED)
            table[name] = {"precision": s["precision"], "recall": s["recall"],
                           "F1": s["f1"], "FP": s["fp"], "FN": s["fn"]}
        df = pd.DataFrame(table).T
        st.dataframe(df.style.format({"precision": "{:.3f}", "recall": "{:.3f}",
                                      "F1": "{:.3f}"}), use_container_width=True)
        st.bar_chart(df[["precision", "recall", "F1"]], height=260)

        jt = JwtTool.locate(jwt_tool_path or None)
        if jt.available:
            st.subheader(f"Head-to-head on {sorted(OVERLAP_LABELS)}")
            tg = score(records, lambda rec: tokenguard_ids(rec, EVAL_ALL), OVERLAP_LABELS)
            bl = score(records, lambda rec: jt.labels(rec["token"]), OVERLAP_LABELS)
            h2h = pd.DataFrame({
                "TokenGuard": {"precision": tg["precision"], "recall": tg["recall"], "F1": tg["f1"]},
                "jwt_tool": {"precision": bl["precision"], "recall": bl["recall"], "F1": bl["f1"]},
            }).T
            st.dataframe(h2h.style.format("{:.3f}"), use_container_width=True)
            st.bar_chart(h2h, height=240)
        elif jwt_tool_path:
            st.warning("jwt_tool not found at that path.")
        else:
            st.caption("Provide a jwt_tool.py path above to add the baseline comparison.")
