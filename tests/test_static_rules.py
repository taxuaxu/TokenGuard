import json
import time

import jwt
import pytest

from tokenguard import AnalysisConfig, Severity, TokenParseError, analyze, parse_token
from tokenguard.parser import b64url_encode

NOW = 1_800_000_000
CFG = AnalysisConfig(now=NOW)
STRONG = "k9$Vq2!xLr8#Tz4@pW7&nB1^mE6*hY3%"


def make(payload=None, secret=STRONG, alg="HS256", headers=None):
    base = {"iss": "https://auth.local", "aud": "api.local", "sub": "alice",
            "iat": NOW - 60, "exp": NOW + 900}
    if payload is not None:
        base = payload
    return jwt.encode(base, secret, algorithm=alg, headers=headers)


def raw(header, payload, sig=""):
    enc = lambda d: b64url_encode(json.dumps(d).encode())
    return f"{enc(header)}.{enc(payload)}.{sig}"


def ids(token, **kw):
    return {f.rule_id for f in analyze(token, config=kw.pop("config", CFG), **kw)}


# ---------- parser ----------

def test_parser_decodes_parts():
    t = parse_token(make())
    assert t.header["alg"] == "HS256"
    assert t.payload["sub"] == "alice"
    assert len(t.signature) == 32


def test_parser_accepts_bearer_prefix():
    assert parse_token("Bearer " + make()).payload["sub"] == "alice"


@pytest.mark.parametrize("bad", ["abc", "a.b", "!!!.@@@.###", "e30.bm90anNvbg.x"])
def test_parser_rejects_malformed(bad):
    with pytest.raises(TokenParseError):
        parse_token(bad)


# ---------- secure token = no findings (negative example) ----------

def test_secure_token_has_no_findings():
    assert ids(make()) == set()


# ---------- algorithm ----------

@pytest.mark.parametrize("alg", ["none", "None", "NONE", "nOnE"])
def test_none_alg(alg):
    tok = raw({"alg": alg, "typ": "JWT"}, {"sub": "x", "exp": NOW + 60, "aud": "a", "iss": "i"})
    found = analyze(tok, config=CFG)
    assert found[0].rule_id == "ALG_NONE"
    assert found[0].severity == Severity.CRITICAL


def test_missing_alg():
    assert "ALG_MISSING" in ids(raw({"typ": "JWT"}, {"sub": "x"}))


def test_unknown_alg():
    assert "ALG_UNKNOWN" in ids(raw({"alg": "HS1"}, {"sub": "x"}, "abcd"))


def test_unexpected_alg_only_when_configured():
    tok = make()
    assert "ALG_UNEXPECTED" not in ids(tok)
    cfg = AnalysisConfig(now=NOW, expected_algs=["RS256"])
    assert "ALG_UNEXPECTED" in ids(tok, config=cfg)


def test_empty_signature():
    h, p, _ = make().split(".")
    assert "SIGNATURE_EMPTY" in ids(f"{h}.{p}.")


def test_key_injection_headers():
    tok = raw({"alg": "RS256", "jku": "http://evil/jwks", "kid": "../../dev/null",
               "jwk": {"kty": "RSA"}}, {"sub": "x"}, "abcd")
    assert {"HEADER_KEY_URL", "HEADER_KID_INJECTION", "HEADER_JWK"} <= ids(tok)


def test_normal_kid_not_flagged():
    assert "HEADER_KID_INJECTION" not in ids(make(headers={"kid": "key-2026-01"}))


# ---------- claims ----------

def test_missing_exp():
    assert "MISSING_EXP" in ids(make({"iss": "i", "aud": "a", "sub": "x"}))


def test_expired():
    assert "EXPIRED" in ids(make({"iss": "i", "aud": "a", "iat": NOW - 7200, "exp": NOW - 3600}))


def test_long_lifetime():
    tok = make({"iss": "i", "aud": "a", "iat": NOW, "exp": NOW + 365 * 86400})
    assert "LONG_LIFETIME" in ids(tok)


def test_short_lived_token_not_flagged():
    tok = make({"iss": "i", "aud": "a", "iat": NOW, "exp": NOW + 30})
    assert ids(tok) == set()


def test_missing_aud_and_iss():
    found = ids(make({"sub": "x", "iat": NOW, "exp": NOW + 600}))
    assert {"MISSING_AUD", "MISSING_ISS"} <= found


def test_sensitive_data_is_masked():
    tok = make({"iss": "i", "aud": "a", "exp": NOW + 60, "iat": NOW, "password": "hunter2hunter2"})
    f = [x for x in analyze(tok, config=CFG) if x.rule_id == "SENSITIVE_DATA"][0]
    assert "hunter2hunter2" not in f.evidence


def test_info_nbf_future():
    tok = make({"iss": "i", "aud": "a", "iat": NOW, "nbf": NOW + 100, "exp": NOW + 600})
    assert "NOT_YET_VALID" in ids(tok)


# ---------- weak key ----------

@pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
def test_weak_key_recovered_and_masked(alg):
    f = [x for x in analyze(make(secret="secret", alg=alg), config=CFG) if x.rule_id == "WEAK_KEY"]
    assert f and f[0].severity == Severity.CRITICAL
    assert "secret=" in f[0].evidence and "secret=secret" not in f[0].evidence


def test_strong_key_not_recovered():
    assert "WEAK_KEY" not in ids(make(secret=STRONG))


def test_groups_can_be_selected():
    tok = make({"sub": "x"}, secret="secret")
    assert "WEAK_KEY" not in ids(tok, groups=["algorithm", "claims"])
    assert ids(tok, groups=["weak_key"]) == {"WEAK_KEY"}


# ---------- robustness: malformed / non-string alg must not crash ----------

@pytest.mark.parametrize("bad_alg", [["HS256"], 123, True, {"x": 1}])
def test_non_string_alg_does_not_crash(bad_alg):
    # A non-string 'alg' (including an unhashable list/dict) must be reported
    # as malformed, not raise, even with the weak_key group enabled.
    tok = raw({"alg": bad_alg, "typ": "JWT"}, {"sub": "x"}, sig="ZHVtbXk")
    found = ids(tok, groups=["algorithm", "claims", "weak_key"])
    assert "ALG_UNKNOWN" in found
    assert "WEAK_KEY" not in found


# ---------- crit header (RFC 7515) ----------

def test_crit_names_registered_header_flagged():
    tok = raw({"alg": "HS256", "typ": "JWT", "crit": ["alg"]}, {"sub": "x"}, sig="ZHVtbXk")
    assert "CRIT_HEADER" in ids(tok)


def test_crit_names_absent_header_flagged():
    tok = raw({"alg": "HS256", "typ": "JWT", "crit": ["x-custom"]}, {"sub": "x"}, sig="ZHVtbXk")
    assert "CRIT_HEADER" in ids(tok)


def test_crit_malformed_flagged():
    tok = raw({"alg": "HS256", "typ": "JWT", "crit": "x"}, {"sub": "x"}, sig="ZHVtbXk")
    assert "CRIT_HEADER" in ids(tok)


def test_crit_wellformed_and_present_not_flagged():
    tok = raw({"alg": "HS256", "typ": "JWT", "crit": ["x-custom"], "x-custom": True},
              {"sub": "x"}, sig="ZHVtbXk")
    assert "CRIT_HEADER" not in ids(tok)


def test_no_crit_header_not_flagged():
    assert "CRIT_HEADER" not in ids(make())


# ---------- duplicate JSON keys (parser confusion) ----------

def test_duplicate_keys_in_payload_flagged():
    h = b64url_encode(b'{"alg":"HS256","typ":"JWT"}')
    p = b64url_encode(b'{"sub":"a","sub":"b"}')
    assert "DUPLICATE_KEYS" in ids(f"{h}.{p}.ZHVtbXk")


def test_duplicate_keys_in_header_flagged():
    h = b64url_encode(b'{"typ":"JWT","typ":"JWT","alg":"HS256"}')
    p = b64url_encode(b'{"sub":"x"}')
    assert "DUPLICATE_KEYS" in ids(f"{h}.{p}.ZHVtbXk")


def test_clean_token_has_no_duplicate_keys():
    assert "DUPLICATE_KEYS" not in ids(make())
