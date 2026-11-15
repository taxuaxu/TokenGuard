"""Evaluate TokenGuard's detection against the labeled dataset, and optionally
benchmark it head-to-head against the external `jwt_tool` baseline.

Configurations (per the proposal):
  1. basic      : algorithm + claim checks
  2. basic+weak : basic plus weak-key detection
  3. all        : every rule group

Metrics: precision / recall / F1 and a false-positive count, computed on the
rule_ids the dataset labels.

Usage:
  python dataset/generate.py            # first, to (re)create the dataset
  python evaluation/evaluate.py
  python evaluation/evaluate.py --jwt-tool /path/to/jwt_tool.py   # add baseline
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tokenguard import AnalysisConfig, analyze  # noqa: E402
from evaluation.baselines import OVERLAP_LABELS, JwtTool  # noqa: E402

DATA = Path(__file__).resolve().parent.parent / "dataset" / "tokens.jsonl"

CONFIGS = {
    "basic": ["algorithm", "claims"],
    "basic+weak": ["algorithm", "claims", "weak_key"],
    "all": ["algorithm", "claims", "weak_key"],
}

# Rule ids the dataset labels (full TokenGuard scoring space).
LABELED = {"ALG_NONE", "MISSING_EXP", "MISSING_AUD", "MISSING_ISS", "EXPIRED",
           "LONG_LIFETIME", "WEAK_KEY", "SENSITIVE_DATA"}


def load(path=DATA):
    if not path.exists():
        raise SystemExit(f"dataset not found: {path}\nRun `python dataset/generate.py` first.")
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def tokenguard_ids(token, groups):
    return {f.rule_id for f in analyze(token, groups=groups, config=AnalysisConfig())}


def score(records, detect_fn, label_space):
    """detect_fn(token) -> set of rule_ids. Scoring is restricted to label_space."""
    tp = fp = fn = 0
    fp_detail, fn_detail = [], []
    for rec in records:
        expected = set(rec["labels"]) & label_space
        got = detect_fn(rec["token"]) & label_space
        tp += len(expected & got)
        extra, missed = got - expected, expected - got
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


def _print_row(name, s):
    print(f"{name:<14}{s['precision']:>11.3f}{s['recall']:>9.3f}{s['f1']:>8.3f}"
          f"{s['fp']:>5}{s['fn']:>5}")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Evaluate TokenGuard (+ optional jwt_tool baseline)")
    ap.add_argument("--jwt-tool", help="path to jwt_tool.py to benchmark against")
    ap.add_argument("--python", default=sys.executable, help="interpreter used to run jwt_tool")
    args = ap.parse_args(argv)

    records = load()
    pos = sum(1 for r in records if r["labels"])
    print(f"Dataset: {len(records)} tokens ({pos} insecure, {len(records) - pos} secure)\n")

    print("TokenGuard configurations (all labeled checks):")
    print(f"{'config':<14}{'precision':>11}{'recall':>9}{'F1':>8}{'FP':>5}{'FN':>5}")
    print("-" * 52)
    results = {}
    for name, groups in CONFIGS.items():
        s = score(records, lambda t, g=groups: tokenguard_ids(t, g), LABELED)
        results[name] = s
        _print_row(name, s)

    allr = results["all"]
    print("\nDetails for 'all':")
    print("  False positives:", "none" if not allr["false_positives"] else "")
    for note, ids in allr["false_positives"]:
        print(f"    - {note}: {ids}")
    print("  False negatives:", "none" if not allr["false_negatives"] else "")
    for note, ids in allr["false_negatives"]:
        print(f"    - {note}: {ids}")

    # -------- optional head-to-head against jwt_tool --------
    jt = JwtTool.locate(args.jwt_tool, python_exe=args.python)
    baseline = None
    if jt.available:
        print(f"\nHead-to-head on shared checks {sorted(OVERLAP_LABELS)}:")
        print(f"(benchmarking against jwt_tool at {jt.path})")
        print(f"{'tool':<14}{'precision':>11}{'recall':>9}{'F1':>8}{'FP':>5}{'FN':>5}")
        print("-" * 52)
        tg = score(records, lambda t: tokenguard_ids(t, CONFIGS["all"]), OVERLAP_LABELS)
        _print_row("TokenGuard", tg)
        baseline = score(records, jt.labels, OVERLAP_LABELS)
        _print_row("jwt_tool", baseline)
        results["_head_to_head"] = {"TokenGuard": tg, "jwt_tool": baseline}
    else:
        print("\n[baseline] jwt_tool not provided; skipping head-to-head.")
        print("           Enable with:  python evaluation/evaluate.py --jwt-tool /path/to/jwt_tool.py")

    out = Path(__file__).resolve().parent / "results.json"
    out.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nSaved {out}")


if __name__ == "__main__":
    main()
