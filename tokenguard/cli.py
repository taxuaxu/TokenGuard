"""Command-line interface.

    python -m tokenguard analyze <jwt> [--groups algorithm claims weak_key] [--json]
    python -m tokenguard active --target http://127.0.0.1:5000
"""
from __future__ import annotations

import argparse
import json
import sys

from .config import AnalysisConfig
from .parser import TokenParseError, parse_token
from .rules import ALL_GROUPS, analyze


def _cmd_analyze(args) -> int:
    try:
        parsed = parse_token(args.token)
    except TokenParseError as exc:
        print(f"[!] Could not parse token: {exc}", file=sys.stderr)
        return 2
    cfg = AnalysisConfig(max_lifetime_seconds=args.max_lifetime,
                         expected_algs=args.expected_alg or None)
    if args.wordlist:
        from pathlib import Path
        cfg.wordlist_path = Path(args.wordlist)
    findings = analyze(parsed, groups=args.groups, config=cfg)

    if args.json:
        print(json.dumps({"header": parsed.header, "payload": parsed.payload,
                          "findings": [f.to_dict() for f in findings]}, indent=2))
        return 1 if findings else 0

    print("Header: ", json.dumps(parsed.header))
    print("Payload:", json.dumps(parsed.payload))
    print()
    if not findings:
        print("No issues found.")
        return 0
    for f in findings:
        print(f"[{f.severity}] {f.rule_id} ({f.part}): {f.title}")
        print(f"    {f.explanation}")
        if f.evidence:
            print(f"    evidence: {f.evidence}")
    return 1


def _cmd_active(args) -> int:
    from .active.runner import format_results, run_active_tests
    results = run_active_tests(args.target, secret=args.secret)
    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        print(format_results(results))
    return 1 if any(r.vulnerable for r in results) else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="tokenguard", description="JWT security analysis tool")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="statically analyze a token")
    a.add_argument("token")
    a.add_argument("--groups", nargs="+", choices=ALL_GROUPS, default=list(ALL_GROUPS))
    a.add_argument("--max-lifetime", type=int, default=24 * 3600, help="seconds")
    a.add_argument("--expected-alg", action="append", help="allowed algorithm (repeatable)")
    a.add_argument("--wordlist", help="path to secrets wordlist")
    a.add_argument("--json", action="store_true")
    a.set_defaults(func=_cmd_analyze)

    t = sub.add_parser("active", help="send crafted tokens to a local test server")
    t.add_argument("--target", default="http://127.0.0.1:5000")
    t.add_argument("--secret", default=None,
                   help="known/recovered HMAC secret used to sign attack tokens")
    t.add_argument("--json", action="store_true")
    t.set_defaults(func=_cmd_active)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
