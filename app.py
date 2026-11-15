"""TokenGuard control panel (Streamlit).

A visual dashboard to run and watch every part of TokenGuard:
  * Overview with a one-click "run all" summary
  * Static analysis of a pasted JWT, with severity badges and an ordered chart
  * Active testing against the local vulnerable server (endpoint x attack matrix)
  * The OAuth 2.1 MCP case study (secure vs misconfigured)
  * Evaluation scores (precision/recall/F1) and the jwt_tool baseline

Run:  streamlit run app.py
"""
from __future__ import annotations

import html
import json
import subprocess
import sys
import time
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

from tokenguard import AnalysisConfig, analyze
from tokenguard.parser import TokenParseError, parse_token
from tokenguard.rules import ALL_GROUPS

ROOT = Path(__file__).resolve().parent

SEV_COLOR = {"CRITICAL": "#e03131", "HIGH": "#f26d4e", "MEDIUM": "#e0a800",
             "LOW": "#4dabf7", "INFO": "#868e96"}
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

GREEN, RED, AMBER, GREY = "#2b8a5a", "#c92a2a", "#b8860b", "#343a46"

SAMPLE_NONE = ("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
               "eyJzdWIiOiJhbGljZSIsInJvbGUiOiJhZG1pbiJ9.")

# Lab servers the panel can launch. key -> (label, command, base, health path)
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

CSS = """
<style>
.tg-header{background:linear-gradient(100deg,#15233f 0%,#0e1117 70%);
  padding:20px 24px;border-radius:14px;border:1px solid #243049;margin-bottom:14px}
.tg-header h1{margin:0;font-size:1.7rem;letter-spacing:-0.5px}
.tg-header p{margin:4px 0 0;color:#8e99ab;font-size:0.95rem}
.tg-card{background:#141a24;border:1px solid #222c3c;border-radius:12px;padding:16px 18px}
.tg-metric{background:#141a24;border:1px solid #222c3c;border-radius:12px;padding:14px 16px;text-align:center}
.tg-metric .v{font-size:1.9rem;font-weight:700;line-height:1.1}
.tg-metric .l{color:#8e99ab;font-size:0.8rem;margin-top:2px}
.tg-badge{color:#fff;padding:2px 9px;border-radius:5px;font-size:0.76em;font-weight:700;letter-spacing:0.3px}
.tg-finding{background:#141a24;border:1px solid #222c3c;border-radius:11px;
  padding:12px 15px;margin-bottom:10px}
.tg-finding b{font-size:1.02em}
.tg-rule{font-family:ui-monospace,Menlo,monospace;background:#1f2838;padding:1px 7px;
  border-radius:5px;font-size:0.78em;color:#aeb8c8}
.tg-part{color:#7f8a9c;font-style:italic;font-size:0.84em}
.tg-body{color:#c3ccda;margin-top:7px;font-size:0.92em;line-height:1.45}
.tg-ev{font-family:ui-monospace,Menlo,monospace;background:#0b0f16;border:1px solid #222c3c;
  border-radius:7px;padding:7px 10px;margin-top:8px;color:#8fd6a6;font-size:0.82em;display:block;
  overflow-x:auto}
.tg-matrix{width:100%;border-collapse:separate;border-spacing:4px;margin-top:6px}
.tg-matrix th{font-size:0.7rem;color:#8e99ab;font-weight:600;padding:3px 2px;text-align:center}
.tg-matrix td{text-align:center;border-radius:7px;font-size:0.76rem;padding:7px 5px;color:#fff;
  font-weight:600;line-height:1.25}
.tg-matrix td .s{display:block;font-weight:400;font-size:0.82em;opacity:0.85}
.tg-epname{text-align:left!important;color:#e2e7f0!important;background:#1b2230;font-weight:600}
.tg-dot{height:9px;width:9px;border-radius:50%;display:inline-block;margin-right:7px}
</style>
"""


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
        color = GREEN if up else "#555c68"
        st.sidebar.markdown(
            f"<span class='tg-dot' style='background:{color}'></span><b>{label}</b>  "
            f"<span style='color:#8e99ab;font-size:0.8em'>{'running' if up else 'stopped'}</span>",
            unsafe_allow_html=True)
        c1, c2 = st.sidebar.columns(2)
        c1.button("Start", key=f"start_{key}", disabled=up,
                  on_click=start_server, args=(key,), use_container_width=True)
        c2.button("Stop", key=f"stop_{key}", disabled=not up,
                  on_click=stop_server, args=(key,), use_container_width=True)
    st.sidebar.caption("Servers run only on 127.0.0.1 for local testing.")


# ----------------------------------------------------------------- widgets

def badge(sev: str) -> str:
    return (f"<span class='tg-badge' style='background:{SEV_COLOR.get(sev, GREY)}'>"
            f"{sev}</span>")


def metric_card(value, label, color="#e6e9ef") -> str:
    return (f"<div class='tg-metric'><div class='v' style='color:{color}'>{value}</div>"
            f"<div class='l'>{label}</div></div>")


def severity_chart(counts):
    data = pd.DataFrame({"severity": SEV_ORDER, "count": [counts[s] for s in SEV_ORDER]})
    chart = (alt.Chart(data).mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4)
             .encode(
                 x=alt.X("severity:N", sort=SEV_ORDER, title=None,
                         axis=alt.Axis(labelAngle=0)),
                 y=alt.Y("count:Q", title="findings", axis=alt.Axis(tickMinStep=1)),
                 color=alt.Color("severity:N",
                                 scale=alt.Scale(domain=SEV_ORDER,
                                                 range=[SEV_COLOR[s] for s in SEV_ORDER]),
                                 legend=None),
                 tooltip=["severity", "count"])
             .properties(height=230))
    st.altair_chart(chart, use_container_width=True)


def render_findings(findings):
    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        counts[str(f.severity)] += 1
    cols = st.columns(len(SEV_ORDER))
    for col, sev in zip(cols, SEV_ORDER):
        col.markdown(metric_card(counts[sev], sev, SEV_COLOR[sev]), unsafe_allow_html=True)
    st.write("")
    severity_chart(counts)
    st.write("")
    for f in findings:
        ev = (f"<span class='tg-ev'>{html.escape(f.evidence)}</span>") if f.evidence else ""
        st.markdown(
            f"<div class='tg-finding' style='border-left:4px solid {SEV_COLOR.get(str(f.severity), GREY)}'>"
            f"<div>{badge(str(f.severity))} &nbsp;<b>{html.escape(f.title)}</b> &nbsp;"
            f"<span class='tg-rule'>{f.rule_id}</span> &nbsp;<span class='tg-part'>{f.part}</span></div>"
            f"<div class='tg-body'>{html.escape(f.explanation)}</div>{ev}</div>",
            unsafe_allow_html=True)


# ----------------------------------------------------------------- page

st.set_page_config(page_title="TokenGuard", page_icon="🛡️", layout="wide")
st.markdown(CSS, unsafe_allow_html=True)
st.markdown(
    "<div class='tg-header'><h1>🛡️ TokenGuard</h1>"
    "<p>JWT Security Analysis — Control Panel</p></div>", unsafe_allow_html=True)
server_controls()

tab_dash, tab_static, tab_active, tab_mcp, tab_eval = st.tabs(
    ["Overview", "Static analysis", "Active testing", "MCP case study", "Evaluation"])


# ================================================================= Overview
def run_all():
    out = {}
    # Active testing
    if is_up("vuln"):
        from tokenguard.active.runner import HttpClient, run_active_tests, summarize
        try:
            res = run_active_tests(client=HttpClient("http://127.0.0.1:5000"))
            flaws = sum(len(v) for v in summarize(res).values())
            out["active"] = {"flaws": flaws, "endpoints": len(summarize(res))}
        except Exception as exc:  # noqa: BLE001
            out["active_error"] = str(exc)
    # MCP probes
    from tokenguard.mcp_probe import run_mcp_probe, vulnerabilities
    for key, port in (("mcp_secure", 7000), ("mcp_insecure", 7001)):
        if is_up(key):
            try:
                res = run_mcp_probe(f"http://127.0.0.1:{port}")
                out[key] = {"vulns": len(vulnerabilities(res))}
            except Exception as exc:  # noqa: BLE001
                out[f"{key}_error"] = str(exc)
    # Evaluation
    try:
        import dataset.generate as gen
        from evaluation.evaluate import CONFIGS, LABELED, load, score, tokenguard_ids
        gen.main()
        records = load()
        s = score(records, lambda rec: tokenguard_ids(rec, CONFIGS["all"]), LABELED)
        out["eval"] = {"recall": s["recall"], "precision": s["precision"],
                       "f1": s["f1"], "fp": s["fp"]}
    except Exception as exc:  # noqa: BLE001
        out["eval_error"] = str(exc)
    out["_ts"] = time.strftime("%H:%M:%S")
    return out


with tab_dash:
    st.subheader("Lab server status")
    cols = st.columns(len(SERVERS))
    for col, (key, (label, _, _, _)) in zip(cols, SERVERS.items()):
        up = is_up(key)
        col.markdown(metric_card("running" if up else "stopped", label,
                                 GREEN if up else "#868e96"), unsafe_allow_html=True)

    st.write("")
    st.subheader("One-click summary")
    st.caption("Runs active tests, both MCP probes, and the evaluation against whichever "
               "lab servers are up, then summarizes the results.")
    if st.button("▶  Run all tests", type="primary"):
        with st.spinner("Running all tests..."):
            st.session_state["runall"] = run_all()

    summary = st.session_state.get("runall")
    if summary:
        st.caption(f"Last run at {summary['_ts']}")
        c = st.columns(4)
        active = summary.get("active")
        c[0].markdown(metric_card(
            active["flaws"] if active else "—", "Active flaws found",
            RED if active and active["flaws"] else GREEN), unsafe_allow_html=True)
        ms = summary.get("mcp_secure")
        c[1].markdown(metric_card(
            ms["vulns"] if ms else "—", "MCP secure vulns",
            RED if ms and ms["vulns"] else GREEN), unsafe_allow_html=True)
        mi = summary.get("mcp_insecure")
        c[2].markdown(metric_card(
            mi["vulns"] if mi else "—", "MCP misconfig vulns",
            RED if mi and mi["vulns"] else "#868e96"), unsafe_allow_html=True)
        ev = summary.get("eval")
        c[3].markdown(metric_card(
            f"{ev['recall']:.2f}" if ev else "—", "Detection recall (all)",
            "#4dabf7"), unsafe_allow_html=True)
        downs = [k for k in ("vuln", "mcp_secure", "mcp_insecure") if not is_up(k)]
        if downs:
            st.info("Some servers were stopped, so parts were skipped: "
                    + ", ".join(SERVERS[k][0] for k in downs))

    st.write("")
    with st.expander("What each tab does"):
        st.markdown(
            "- **Static analysis** — paste a JWT and see findings by severity.\n"
            "- **Active testing** — send crafted tokens to the vulnerable server; the "
            "matrix shows which attacks each endpoint accepts.\n"
            "- **MCP case study** — probe the OAuth 2.1 MCP server's authorization rules.\n"
            "- **Evaluation** — precision/recall/F1 and the jwt_tool baseline.")


# ================================================================= Static
with tab_static:
    st.subheader("Analyze a JWT")
    groups = st.multiselect("Rule groups", list(ALL_GROUPS), default=list(ALL_GROUPS))
    cc1, cc2 = st.columns(2)
    max_life_h = cc1.number_input("Max token lifetime (hours)", 1, 8760, 24)
    expected = cc2.text_input("Expected algorithms (comma-separated, optional)", "")

    token = st.text_area("Token", height=120, placeholder="eyJ...", key="tok")
    st.button("Load sample (alg=none)",
              on_click=lambda: st.session_state.update(tok=SAMPLE_NONE))

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


# ================================================================= Active
def active_matrix(results):
    attacks = ["NO_TOKEN", "BASELINE_VALID", "ALG_NONE", "TAMPERED_SIGNATURE",
               "EXPIRED_TOKEN", "WRONG_AUDIENCE", "WEAK_KEY_FORGERY"]
    endpoints = sorted({r.endpoint for r in results})
    cell = {(r.endpoint, r.attack): r for r in results}

    def td(r):
        if r is None or r.status is None:
            return "<td style='background:#343a46;color:#9aa4b2'>–<span class='s'>skip</span></td>"
        note = html.escape(r.note) if r.note else ""
        if r.expected_accept:
            bg, txt = (GREEN, "accept") if r.accepted else (AMBER, "reject?")
        elif r.vulnerable:
            bg, txt = RED, "VULN"
        else:
            bg, txt = GREEN, "rejected"
        return (f"<td style='background:{bg}' title='{note}'>{txt}"
                f"<span class='s'>{r.status}</span></td>")

    head = "".join(f"<th>{a.replace('_', ' ')}</th>" for a in attacks)
    rows = ""
    for ep in endpoints:
        cells = "".join(td(cell.get((ep, a))) for a in attacks)
        rows += f"<tr><td class='tg-epname'>{ep}</td>{cells}</tr>"
    st.markdown(f"<table class='tg-matrix'><tr><th></th>{head}</tr>{rows}</table>",
                unsafe_allow_html=True)


with tab_active:
    st.subheader("Active testing against the vulnerable server")
    up = is_up("vuln")
    dot = GREEN if up else "#555c68"
    st.markdown(f"<span class='tg-dot' style='background:{dot}'></span>"
                + ("server running" if up else
                   "server stopped — start it from the sidebar"), unsafe_allow_html=True)
    target = st.text_input("Target (localhost only)", "http://127.0.0.1:5000")
    secret = st.text_input("Known HMAC secret (optional)", "")
    if st.button("Run active tests", disabled=not up, type="primary"):
        from tokenguard.active.runner import HttpClient, run_active_tests, summarize
        try:
            st.session_state["active_res"] = run_active_tests(
                client=HttpClient(target), secret=secret or None)
        except Exception as exc:  # noqa: BLE001
            st.error(f"{type(exc).__name__}: {exc}")
            st.session_state.pop("active_res", None)

    results = st.session_state.get("active_res")
    if results:
        from tokenguard.active.runner import summarize
        active_matrix(results)
        st.caption("🟥 VULN = insecure token accepted · 🟩 = correct behavior · "
                   "small number = HTTP status · hover a cell for its note")
        st.subheader("Detected flaws per endpoint")
        for ep, flaws in summarize(results).items():
            icon = "🔴" if flaws else "🟢"
            st.write(f"{icon} **{ep}** → {', '.join(flaws) if flaws else 'no flaws detected'}")
        st.download_button("Download results (JSON)",
                           json.dumps([r.to_dict() for r in results], indent=2),
                           file_name="tokenguard_active_results.json")


# ================================================================= MCP
with tab_mcp:
    st.subheader("OAuth 2.1 MCP server case study")
    c1, c2 = st.columns(2)
    for col, key in ((c1, "mcp_secure"), (c2, "mcp_insecure")):
        up = is_up(key)
        col.markdown(f"<span class='tg-dot' style='background:{GREEN if up else '#555c68'}'>"
                     f"</span>{SERVERS[key][0]} — {'running' if up else 'stopped'}",
                     unsafe_allow_html=True)
    mcp_target = st.text_input("MCP server (localhost only)", "http://127.0.0.1:7000")
    if st.button("Run MCP probe", type="primary"):
        from tokenguard.mcp_probe import run_mcp_probe, vulnerabilities
        try:
            st.session_state["mcp_res"] = run_mcp_probe(mcp_target)
        except Exception as exc:  # noqa: BLE001
            st.error(f"{type(exc).__name__}: {exc}")
            st.session_state.pop("mcp_res", None)

    results = st.session_state.get("mcp_res")
    if results:
        from tokenguard.mcp_probe import vulnerabilities
        for r in results:
            if r.passed:
                dot, tag = GREEN, "PASS"
            elif r.vulnerability:
                dot, tag = RED, r.vulnerability
            else:
                dot, tag = AMBER, "FAIL"
            st.markdown(
                f"<div class='tg-finding' style='border-left:4px solid {dot}'>"
                f"<b>{r.check}</b> &nbsp;<span class='tg-badge' style='background:{dot}'>{tag}"
                f"</span><div class='tg-body'>{html.escape(r.detail)}</div></div>",
                unsafe_allow_html=True)
        vulns = vulnerabilities(results)
        if vulns:
            st.error("Vulnerabilities: " + ", ".join(vulns))
        else:
            st.success("No authorization vulnerabilities detected.")


# ================================================================= Evaluation
with tab_eval:
    st.subheader("Detection evaluation")
    jwt_tool_path = st.text_input("jwt_tool.py path (optional, for baseline)", "")
    if st.button("Generate dataset & evaluate", type="primary"):
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
        melted = df[["precision", "recall", "F1"]].reset_index().melt(
            "index", var_name="metric", value_name="score")
        chart = (alt.Chart(melted).mark_bar()
                 .encode(x=alt.X("metric:N", title=None, axis=alt.Axis(labelAngle=0)),
                         y=alt.Y("score:Q", scale=alt.Scale(domain=[0, 1])),
                         color=alt.Color("index:N", title="config"),
                         xOffset="index:N", tooltip=["index", "metric", "score"])
                 .properties(height=260))
        st.altair_chart(chart, use_container_width=True)

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
        elif jwt_tool_path:
            st.warning("jwt_tool not found at that path.")
        else:
            st.caption("Provide a jwt_tool.py path above to add the baseline comparison.")
