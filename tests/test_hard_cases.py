"""The hand-labeled adversarial set: the tool should catch every real issue, yet
still over-flag some legitimate tokens (so this set, unlike the generated one,
does not score a perfect precision)."""
from __future__ import annotations

from dataset.hard_cases import records
from evaluation.evaluate import LABELED, score, tokenguard_ids
from tokenguard.parser import parse_token

ALL_GROUPS = ["algorithm", "claims", "weak_key"]
HARD = records()


def _score():
    return score(HARD, lambda rec: tokenguard_ids(rec, ALL_GROUPS), LABELED)


def test_hard_set_is_well_formed():
    assert any(r["labels"] for r in HARD), "no insecure cases"
    assert any(not r["labels"] for r in HARD), "no legitimate-but-suspicious cases"
    for r in HARD:
        parse_token(r["token"])  # every token parses


def test_tool_detects_most_real_issues_and_misses_only_unknown_sensitive_keys():
    # Recall stays high, but the keyword-based sensitive-data check has a known gap:
    # genuinely sensitive values stored under field names it does not know are missed.
    s = _score()
    assert s["recall"] >= 0.8
    # Every miss is a SENSITIVE_DATA case under an unusual key name.
    for _note, ids in s["false_negatives"]:
        assert ids == ["SENSITIVE_DATA"], f"unexpected miss: {_note} -> {ids}"


def test_hard_set_surfaces_false_positives():
    # This set is adversarial on purpose. The tool conservatively over-flags some
    # legitimate tokens (clock-skew nbf, long-lived tokens, a kid containing '--'),
    # so precision is below 1.0 here — a more honest signal than the generated
    # dataset. If these over-flags are later refined away, update this test.
    s = _score()
    assert s["fp"] >= 1, "expected at least one false positive on the hard set"
    assert s["precision"] < 1.0
