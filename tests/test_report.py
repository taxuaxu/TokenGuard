"""Tests for the reporting module."""
from __future__ import annotations

import jwt

from evaluation.evaluate import LABELED
from tokenguard import AnalysisConfig, analyze, parse_token
from tokenguard.models import Finding, Severity
from tokenguard.report import (REMEDIATION, claim_timeline, risk_level, relative_phrase,
                               to_markdown)

NOW = 1_800_000_000
STRONG = "k9$Vq2!xLr8#Tz4@pW7&nB1^mE6*hY3%"


def _finding(sev):
    return Finding("X", "t", "header", sev, "e")


def test_risk_level_empty_is_ok():
    assert risk_level([]) == "OK"


def test_risk_level_takes_max_severity():
    fs = [_finding(Severity.LOW), _finding(Severity.CRITICAL), _finding(Severity.MEDIUM)]
    assert risk_level(fs) == "CRITICAL"


def test_remediation_covers_every_labeled_rule():
    missing = LABELED - set(REMEDIATION)
    assert not missing, f"rules without remediation advice: {sorted(missing)}"


def test_claim_timeline_detects_expired():
    payload = {"iat": NOW - 7200, "exp": NOW - 3600}
    rows = {r["claim"]: r for r in claim_timeline(payload, NOW)}
    assert rows["exp"]["state"] == "expired"
    assert rows["iat"]["state"] == "info"


def test_relative_phrase_languages():
    assert "ago" in relative_phrase("exp", -3600, "en")
    assert "önce" in relative_phrase("exp", -3600, "tr")


def test_to_markdown_has_sections_and_remediation():
    tok = jwt.encode({"sub": "a", "iat": NOW - 60}, STRONG, algorithm="HS256")
    parsed = parse_token(tok)
    findings = analyze(parsed, config=AnalysisConfig(now=NOW))
    md = to_markdown(parsed, findings, NOW)
    assert "# TokenGuard Analysis Report" in md
    assert "Overall risk" in md
    assert "## Findings" in md
    # a MISSING_EXP finding should carry its remediation line
    assert "Remediation" in md


def test_to_markdown_localized_labels():
    tok = jwt.encode({"sub": "a"}, STRONG, algorithm="HS256")
    parsed = parse_token(tok)
    findings = analyze(parsed, config=AnalysisConfig(now=NOW))
    md = to_markdown(parsed, findings, NOW,
                     labels={"report_title": "Rapor", "overall_risk": "Genel risk"}, lang="tr")
    assert "# Rapor" in md
