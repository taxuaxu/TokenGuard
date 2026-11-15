"""Unit-tests for the jwt_tool output parser (no external tool required)."""
import json
import sys
import time
from pathlib import Path

import jwt
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from evaluation.baselines import jwt_tool_labels, parse_jwt_tool_output  # noqa: E402

# Representative snippets captured from jwt_tool 2.3.0 output.
NONE_DECODE = """
Token header values:
[+] alg = "none"
[+] typ = "JWT"
"""

EXPIRED_DECODE = """
[+] exp = 1794757062    ==> TIMESTAMP = 2026-11-15 18:37:42 (UTC)
Seen timestamps:
[-] TOKEN IS EXPIRED!
"""

HEALTHY_DECODE = """
Token header values:
[+] alg = "HS256"
[+] exp = 1999999999    ==> TIMESTAMP = 2033-05-18 (UTC)
"""

CRACK_HIT = '[+] secret is the CORRECT key!\nYou can tamper/fuzz ...'
CRACK_MISS = '[-] Key not in dictionary. Analysis complete.'

ANSI_NONE = '\x1b[36m[+] alg = "none"\x1b[0m'


def test_parse_none():
    assert parse_jwt_tool_output(NONE_DECODE) == {"ALG_NONE"}


def test_parse_expired():
    assert parse_jwt_tool_output(EXPIRED_DECODE) == {"EXPIRED"}


def test_parse_weak_key_crack_hit():
    assert parse_jwt_tool_output(HEALTHY_DECODE, CRACK_HIT) == {"WEAK_KEY"}


def test_parse_weak_key_crack_miss():
    assert parse_jwt_tool_output(HEALTHY_DECODE, CRACK_MISS) == set()


def test_parse_healthy_token_no_labels():
    assert parse_jwt_tool_output(HEALTHY_DECODE) == set()


def test_parser_tolerates_ansi_codes():
    assert parse_jwt_tool_output(ANSI_NONE) == {"ALG_NONE"}


def test_labels_skips_crack_for_non_hmac():
    """jwt_tool_labels must not invoke the crack runner for a none token."""
    calls = []

    def fake_runner(token, crack):
        calls.append(crack)
        return NONE_DECODE

    header = json.dumps({"alg": "none", "typ": "JWT"})
    import base64
    b = lambda d: base64.urlsafe_b64encode(d.encode()).rstrip(b"=").decode()
    tok = f"{b(header)}.{b(json.dumps({'sub': 'a'}))}."
    labels = jwt_tool_labels(tok, fake_runner)
    assert labels == {"ALG_NONE"}
    assert calls == [False]  # crack run never requested


def test_labels_runs_crack_for_hmac():
    now = int(time.time())
    tok = jwt.encode({"iss": "i", "exp": now + 60}, "secret", algorithm="HS256")

    def fake_runner(token, crack):
        return CRACK_HIT if crack else HEALTHY_DECODE

    assert jwt_tool_labels(tok, fake_runner) == {"WEAK_KEY"}
