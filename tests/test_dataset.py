"""Integrity checks for the labeled evaluation dataset.

These guard against mislabeled records: under the full ('all') configuration,
TokenGuard's detection must reproduce each token's labels exactly — no missed
labels (false negatives) and no extra detections (false positives). If a rule
or a generator entry drifts, these tests fail instead of silently skewing the
evaluation metrics.
"""
from __future__ import annotations

import pytest

from dataset.generate import records
from evaluation.evaluate import LABELED
from tokenguard import AnalysisConfig, analyze

ALL_GROUPS = ["algorithm", "claims", "weak_key"]

# Exercise the exhaustive dataset (full wordlist) so every generated token is checked.
RECORDS = records(weak_sample=None)


def _detect(rec):
    cfg = AnalysisConfig(now=rec.get("now"), expected_algs=rec.get("expected_algs"))
    return {f.rule_id for f in analyze(rec["token"], groups=ALL_GROUPS, config=cfg)} & LABELED


@pytest.mark.parametrize("rec", RECORDS, ids=[r["note"] for r in RECORDS])
def test_each_token_matches_its_labels(rec):
    expected = set(rec["labels"]) & LABELED
    got = _detect(rec)
    assert got == expected, (
        f"{rec['note']!r}: expected {sorted(expected)}, detected {sorted(got)}")


def test_dataset_is_nonempty_and_has_both_classes():
    assert len(RECORDS) > 100
    assert any(r["labels"] for r in RECORDS), "no insecure examples"
    assert any(not r["labels"] for r in RECORDS), "no secure negatives"


def test_every_labeled_class_is_represented():
    seen = set()
    for r in RECORDS:
        seen |= set(r["labels"]) & LABELED
    missing = LABELED - seen
    assert not missing, f"labeled classes with no token: {sorted(missing)}"
