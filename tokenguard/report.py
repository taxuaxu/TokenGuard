"""Reporting helpers: an overall risk verdict, a human-readable claim timeline,
per-rule remediation advice, and a Markdown report.

The engine output is canonical English; the dashboard localizes for display by
passing its own label set and a per-finding localizer to `to_markdown`.
"""
from __future__ import annotations

import datetime as _dt
import json
from typing import Callable, List, Optional

from .config import AnalysisConfig
from .models import Finding, Severity
from .parser import ParsedToken

# Overall risk = the highest finding severity (or OK when there are none).
RISK_BY_SEVERITY = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}

# Short, actionable fix for each rule (English, canonical).
REMEDIATION = {
    "ALG_NONE": "Reject alg=none; configure the library with an explicit allow-list of "
                "signing algorithms.",
    "ALG_MISSING": "Require an explicit 'alg' and validate it against an allow-list.",
    "ALG_UNKNOWN": "Accept only known algorithms from a fixed allow-list.",
    "ALG_UNEXPECTED": "Pin the exact algorithm(s) the application uses and reject any other "
                      "(prevents RS256→HS256 confusion).",
    "SIGNATURE_EMPTY": "Require a non-empty signature and verify it; never accept unsigned tokens.",
    "HEADER_JWK": "Never trust a key embedded in the token ('jwk'); use keys from a trusted "
                  "server-side source only.",
    "HEADER_KEY_URL": "Do not fetch keys from token-supplied URLs ('jku'/'x5u'); use a strict "
                      "allow-list of key sources.",
    "HEADER_KID_INJECTION": "Treat 'kid' as an opaque identifier; look it up in a fixed map, "
                            "never in a file path or SQL query.",
    "CRIT_HEADER": "Reject tokens whose 'crit' is malformed, names a registered header, or "
                   "names a header you do not support.",
    "DUPLICATE_KEYS": "Reject tokens whose header or payload JSON contains duplicate keys; use "
                      "a strict parser.",
    "MISSING_EXP": "Require an 'exp' claim and enforce it on every request.",
    "INVALID_EXP": "Require 'exp' to be a numeric date (seconds since epoch) and reject "
                   "malformed values.",
    "EXPIRED": "Reject expired tokens; verify 'exp' against the current time with minimal "
               "clock skew.",
    "LONG_LIFETIME": "Issue short-lived access tokens (minutes) and use refresh tokens for "
                     "longer sessions.",
    "MISSING_AUD": "Set and validate an 'aud' claim so a token is only accepted by its "
                   "intended service.",
    "MISSING_ISS": "Set and validate an 'iss' claim against the expected issuer.",
    "NOT_YET_VALID": "Validate 'nbf' and reject tokens that are not yet valid (check clock "
                     "synchronization).",
    "SENSITIVE_DATA": "Never put secrets or personal data in a JWT payload; it is only "
                      "Base64-encoded, not encrypted.",
    "WEAK_KEY": "Use a long, random HMAC secret (≥32 bytes) or switch to asymmetric keys; "
                "rotate the leaked secret.",
}


def risk_level(findings: List[Finding]) -> str:
    """Overall verdict: the highest severity present, or 'OK' when clean."""
    if not findings:
        return "OK"
    return RISK_BY_SEVERITY[max(f.severity for f in findings)]


def severity_counts(findings: List[Finding]) -> dict:
    counts = {name: 0 for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    for f in findings:
        counts[str(f.severity)] += 1
    return counts


def _is_number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _fmt_ts(ts) -> str:
    return _dt.datetime.utcfromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S UTC")


_UNITS = {"en": ("days", "hours", "minutes", "seconds"),
          "tr": ("gün", "saat", "dakika", "saniye")}


def _human_delta(seconds: float, lang: str = "en") -> str:
    seconds = abs(int(seconds))
    d, h, m, s = _UNITS.get(lang, _UNITS["en"])
    if seconds >= 86400:
        return f"{seconds / 86400:.1f} {d}"
    if seconds >= 3600:
        return f"{seconds / 3600:.1f} {h}"
    if seconds >= 60:
        return f"{seconds / 60:.0f} {m}"
    return f"{seconds} {s}"


def relative_phrase(claim: str, delta: float, lang: str = "en") -> str:
    """Human phrase for a claim's time relative to now."""
    hd = _human_delta(delta, lang)
    if lang == "tr":
        if claim == "exp":
            return f"{hd} önce doldu" if delta < 0 else f"{hd} içinde dolacak"
        if claim == "nbf":
            return f"{hd} içinde geçerli olacak" if delta > 0 else f"{hd} önce başladı"
        return f"{hd} önce verildi" if delta <= 0 else f"{hd} içinde"
    if claim == "exp":
        return f"expired {hd} ago" if delta < 0 else f"expires in {hd}"
    if claim == "nbf":
        return f"not valid for another {hd}" if delta > 0 else f"active since {hd} ago"
    return f"issued {hd} ago" if delta <= 0 else f"issued in {hd}"


def claim_timeline(payload: dict, now: float) -> List[dict]:
    """Structured iat/nbf/exp info: {claim, label, when, epoch, delta, state}."""
    rows = []
    specs = [("iat", "Issued at"), ("nbf", "Not before"), ("exp", "Expires")]
    for claim, label in specs:
        v = payload.get(claim)
        if not _is_number(v):
            continue
        delta = v - now
        if claim == "exp":
            state = "expired" if delta < 0 else "valid"
        elif claim == "nbf":
            state = "not-yet-valid" if delta > 0 else "active"
        else:
            state = "info"
        rows.append({"claim": claim, "label": label, "when": _fmt_ts(v),
                     "epoch": int(v), "delta": delta, "state": state})
    return rows


# -------------------------------------------------------------- Markdown report

def to_markdown(parsed: ParsedToken, findings: List[Finding], now: float,
                labels: Optional[dict] = None,
                localize: Optional[Callable[[Finding], tuple]] = None,
                lang: str = "en") -> str:
    """Render a Markdown report.

    `labels` overrides section headings; `localize(f)` returns
    (title, explanation, part, remediation) for a finding; `lang` phrases the
    claim timeline. All default to English.
    """
    L = dict(_EN_LABELS)
    if labels:
        L.update(labels)
    counts = severity_counts(findings)
    risk = risk_level(findings)

    def loc(f):
        if localize:
            return localize(f)
        return f.title, f.explanation, f.part, REMEDIATION.get(f.rule_id, "")

    out = [f"# {L['report_title']}", ""]
    out.append(f"**{L['generated']}:** {_fmt_ts(now)}  ")
    out.append(f"**{L['overall_risk']}:** {L.get('risk_' + risk.lower(), risk)}  ")
    nonzero = ", ".join(f"{n} {s.lower()}" for s, n in counts.items() if n)
    out.append(f"**{L['findings']}:** {len(findings)}"
               + (f" ({nonzero})" if nonzero else ""))
    out.append("")

    # token summary
    out.append(f"## {L['token']}")
    out.append(f"- **{L['algorithm']}:** `{parsed.header.get('alg')}`")
    if parsed.header.get("typ") is not None:
        out.append(f"- **{L['type']}:** `{parsed.header.get('typ')}`")
    for row in claim_timeline(parsed.payload, now):
        rel = relative_phrase(row["claim"], row["delta"], lang)
        out.append(f"- **{L.get(row['claim'], row['label'])}:** {row['when']} ({rel})")
    out.append("")
    out.append(f"**{L['header']}**")
    out.append("```json\n" + json.dumps(parsed.header, indent=2) + "\n```")
    out.append(f"**{L['payload']}**")
    out.append("```json\n" + json.dumps(parsed.payload, indent=2) + "\n```")
    out.append("")

    # findings
    out.append(f"## {L['findings']}")
    if not findings:
        out.append(L["no_issues"])
    for f in findings:
        title, expl, part, remed = loc(f)
        sev = str(f.severity)
        out.append(f"### [{sev}] {title} — `{f.rule_id}` ({part})")
        out.append(expl)
        if f.evidence:
            out.append(f"- **{L['evidence']}:** `{f.evidence}`")
        if remed:
            out.append(f"- **{L['remediation']}:** {remed}")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


_EN_LABELS = {
    "report_title": "TokenGuard Analysis Report",
    "generated": "Generated",
    "overall_risk": "Overall risk",
    "findings": "Findings",
    "token": "Token",
    "algorithm": "Algorithm",
    "type": "Type",
    "iat": "Issued at", "nbf": "Not before", "exp": "Expires",
    "header": "Header", "payload": "Payload",
    "evidence": "Evidence", "remediation": "Remediation",
    "no_issues": "No issues found.",
    "risk_ok": "OK", "risk_critical": "CRITICAL", "risk_high": "HIGH",
    "risk_medium": "MEDIUM", "risk_low": "LOW", "risk_info": "INFO",
}


def report_for_cli(parsed: ParsedToken, findings: List[Finding],
                   cfg: AnalysisConfig) -> str:
    return to_markdown(parsed, findings, cfg.current_time())
