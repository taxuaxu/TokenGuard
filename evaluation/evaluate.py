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

# There are three rule groups, so "all checks" == "basic + weak-key". The two
# meaningful, distinct configurations are therefore basic (no weak-key detection)
# and all (with it); the jwt_tool benchmark below is the third point of comparison.
ALL_GROUPS = ["algorithm", "claims", "weak_key"]
CONFIGS = {
    "basic": ["algorithm", "claims"],
    "all": ALL_GROUPS,
}

# Rule ids the dataset labels (full TokenGuard scoring space).
LABELED = {"ALG_NONE", "ALG_MISSING", "ALG_UNKNOWN", "ALG_UNEXPECTED", "SIGNATURE_EMPTY",
           "HEADER_JWK", "HEADER_KEY_URL", "HEADER_KID_INJECTION", "CRIT_HEADER",
           "DUPLICATE_KEYS",
           "MISSING_EXP", "INVALID_EXP", "MISSING_AUD", "MISSING_ISS", "EXPIRED",
           "LONG_LIFETIME", "NOT_YET_VALID", "WEAK_KEY", "SENSITIVE_DATA"}


def load(path=DATA):
    if not path.exists():
        raise SystemExit(f"dataset not found: {path}\nRun `python dataset/generate.py` first.")
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def tokenguard_ids(rec, groups):
    # Analyze against the token's generation time, not the wall clock, so that
    # time-relative checks (EXPIRED, LONG_LIFETIME) are reproducible. When a
    # record pins accepted algorithms, pass them so ALG_UNEXPECTED (algorithm
    # confusion) is scored the way the target application would see it.
    cfg = AnalysisConfig(now=rec.get("now"), expected_algs=rec.get("expected_algs"))
    return {f.rule_id for f in analyze(rec["token"], groups=groups, config=cfg)}


def score(records, detect_fn, label_space):
    """detect_fn(record) -> set of rule_ids. Scoring is restricted to label_space."""
    tp = fp = fn = 0
    fp_detail, fn_detail = [], []
    for rec in records:
        expected = set(rec["labels"]) & label_space
        got = detect_fn(rec) & label_space
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


def per_class(records, detect_fn, label_space):
    """Per-rule support and precision/recall across the dataset."""
    stats = {rid: {"support": 0, "tp": 0, "fp": 0, "fn": 0} for rid in sorted(label_space)}
    for rec in records:
        expected = set(rec["labels"]) & label_space
        got = detect_fn(rec) & label_space
        for rid in expected:
            stats[rid]["support"] += 1
            stats[rid]["tp" if rid in got else "fn"] += 1
        for rid in got - expected:
            stats[rid]["fp"] += 1
    for s in stats.values():
        tp, fp, fn = s["tp"], s["fp"], s["fn"]
        s["precision"] = tp / (tp + fp) if tp + fp else 1.0
        s["recall"] = tp / (tp + fn) if tp + fn else 1.0
    return stats


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
        s = score(records, lambda rec, g=groups: tokenguard_ids(rec, g), LABELED)
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

    # -------- per-class breakdown (config 'all') --------
    pc = per_class(records, lambda rec: tokenguard_ids(rec, ALL_GROUPS), LABELED)
    allr["per_class"] = pc
    print("\nPer-class detection ('all'):")
    print(f"{'rule_id':<22}{'support':>8}{'TP':>4}{'FP':>4}{'FN':>4}{'prec':>7}{'recall':>8}")
    print("-" * 57)
    for rid, s in pc.items():
        print(f"{rid:<22}{s['support']:>8}{s['tp']:>4}{s['fp']:>4}{s['fn']:>4}"
              f"{s['precision']:>7.2f}{s['recall']:>8.2f}")

    # -------- optional head-to-head against jwt_tool --------
    jt = JwtTool.locate(args.jwt_tool, python_exe=args.python)
    baseline = None
    if jt.available:
        print(f"\nHead-to-head on shared checks {sorted(OVERLAP_LABELS)}:")
        print(f"(benchmarking against jwt_tool at {jt.path})")
        print(f"{'tool':<14}{'precision':>11}{'recall':>9}{'F1':>8}{'FP':>5}{'FN':>5}")
        print("-" * 52)
        tg = score(records, lambda rec: tokenguard_ids(rec, ALL_GROUPS), OVERLAP_LABELS)
        _print_row("TokenGuard", tg)
        baseline = score(records, lambda rec: jt.labels(rec["token"]), OVERLAP_LABELS)
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
