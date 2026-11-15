"""Evaluate TokenGuard's detection against the labeled dataset.

Compares three configurations (per the proposal):
  1. basic      : algorithm + claim checks
  2. basic+weak : basic plus weak-key detection
  3. all        : every rule group

Reports precision / recall / F1 and a false-positive count, computed on the
rule_ids the dataset labels (detection-level metrics).

Usage:  python evaluation/evaluate.py   (reads dataset/tokens.jsonl)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tokenguard import AnalysisConfig, analyze  # noqa: E402

DATA = Path(__file__).resolve().parent.parent / "dataset" / "tokens.jsonl"

CONFIGS = {
    "basic": ["algorithm", "claims"],
    "basic+weak": ["algorithm", "claims", "weak_key"],
    "all": ["algorithm", "claims", "weak_key"],
}

# Only score rule_ids that the dataset actually labels, so incidental findings
# (e.g. MISSING_ISS on a token labeled only WEAK_KEY) are not counted as errors.
LABELED = {"ALG_NONE", "MISSING_EXP", "MISSING_AUD", "MISSING_ISS", "EXPIRED",
           "LONG_LIFETIME", "WEAK_KEY", "SENSITIVE_DATA"}


def load(path=DATA):
    if not path.exists():
        raise SystemExit(f"dataset not found: {path}\nRun `python dataset/generate.py` first.")
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def detected_ids(token, groups):
    cfg = AnalysisConfig()
    return {f.rule_id for f in analyze(token, groups=groups, config=cfg)} & LABELED


def score(records, groups):
    tp = fp = fn = 0
    fp_detail, fn_detail = [], []
    for rec in records:
        expected = set(rec["labels"]) & LABELED
        got = detected_ids(rec["token"], groups)
        tp += len(expected & got)
        extra = got - expected
        missed = expected - got
        fp += len(extra)
        fn += len(missed)
        if extra:
            fp_detail.append((rec["note"], sorted(extra)))
        if missed:
            fn_detail.append((rec["note"], sorted(missed)))
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall,
            "f1": f1, "false_positives": fp_detail, "false_negatives": fn_detail}


def main():
    records = load()
    pos = sum(1 for r in records if r["labels"])
    print(f"Dataset: {len(records)} tokens ({pos} insecure, {len(records) - pos} secure)\n")
    print(f"{'config':<12}{'precision':>11}{'recall':>9}{'F1':>8}{'FP':>5}{'FN':>5}")
    print("-" * 50)
    results = {}
    for name, groups in CONFIGS.items():
        s = score(records, groups)
        results[name] = s
        print(f"{name:<12}{s['precision']:>11.3f}{s['recall']:>9.3f}{s['f1']:>8.3f}"
              f"{s['fp']:>5}{s['fn']:>5}")

    print("\nDetails for 'all':")
    allr = results["all"]
    if allr["false_positives"]:
        print("  False positives:")
        for note, ids in allr["false_positives"]:
            print(f"    - {note}: {ids}")
    else:
        print("  No false positives.")
    if allr["false_negatives"]:
        print("  False negatives (missed):")
        for note, ids in allr["false_negatives"]:
            print(f"    - {note}: {ids}")
    else:
        print("  No false negatives.")

    out = Path(__file__).resolve().parent / "results.json"
    out.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nSaved {out}")


if __name__ == "__main__":
    main()
