"""Generate a controlled, labeled dataset of secure and insecure JWTs.

Each record: {"token": "...", "labels": [...], "note": "...", "now": <epoch>}
An empty labels list marks a secure (negative) example.

Usage:  python dataset/generate.py            -> writes dataset/tokens.jsonl
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import warnings
from pathlib import Path

import jwt

warnings.filterwarnings("ignore")  # suppress PyJWT short-key warnings for weak samples

OUT = Path(__file__).resolve().parent / "tokens.jsonl"

ISSUER = "https://auth.lab.local"
AUDIENCE = "tokenguard-api"
STRONG = "k9$Vq2!xLr8#Tz4@pW7&nB1^mE6*hY3%ZaCdEf"  # 38 chars, not in wordlist
NOW = int(time.time())


def _b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()


def secure_claims(**over):
    c = {"iss": ISSUER, "aud": AUDIENCE, "sub": "user-1", "role": "user",
         "iat": NOW, "nbf": NOW, "exp": NOW + 900}
    c.update(over)
    return c


def _signed(claims, secret=STRONG, alg="HS256", headers=None):
    return jwt.encode(claims, secret, algorithm=alg, headers=headers)


def _manual_hs256(header, payload, secret=STRONG):
    """Build an HS256 token with full control of the raw payload (e.g. a
    malformed 'exp'), which jwt.encode would coerce or reject."""
    signing_input = f"{_b64(header)}.{_b64(payload)}".encode()
    sig = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()).rstrip(b"=").decode()
    return f"{signing_input.decode()}.{sig}"


def records():
    recs = []
    # Record the generation time with each token so the evaluator analyzes it
    # against a fixed reference time, not the wall clock. Otherwise short-lived
    # secure tokens (exp=NOW+60) would flip to EXPIRED when evaluated later.
    add = lambda token, labels, note: recs.append(
        {"token": token, "labels": labels, "note": note, "now": NOW})

    # ---- secure negative examples (labels = []) ----
    add(_signed(secure_claims()), [], "standard secure HS256")
    add(_signed(secure_claims(), alg="HS384"), [], "secure HS384")
    add(_signed(secure_claims(), alg="HS512"), [], "secure HS512")
    add(_signed(secure_claims(exp=NOW + 60)), [],
        "intentionally short-lived (must NOT be flagged LONG_LIFETIME)")
    add(_signed(secure_claims(exp=NOW + 86000)), [],
        "lifetime just under the 24h limit (boundary, must NOT be flagged)")
    add(_signed(secure_claims(nbf=NOW - 60)), [],
        "nbf slightly in the past (already valid, must NOT be flagged NOT_YET_VALID)")
    add(_signed(secure_claims(role="admin")), [], "admin role but otherwise sound")
    add(_signed(secure_claims(sub="svc", aud=["tokenguard-api", "reports-api"])), [],
        "multi-audience, both valid")
    add(_signed(secure_claims(sub="svc-account", role="service")), [],
        "service account, sound")

    # ---- alg=none (no signature) ----
    none_header = {"alg": "none", "typ": "JWT"}
    add(f"{_b64(none_header)}.{_b64(secure_claims())}.", ["ALG_NONE"], "none algorithm")
    add(f"{_b64({'alg': 'NONE', 'typ': 'JWT'})}.{_b64(secure_claims())}.", ["ALG_NONE"],
        "none algorithm, upper-case (case bypass attempt)")

    # ---- unknown / malformed algorithm ----
    add(f"{_b64({'alg': 'HS1', 'typ': 'JWT'})}.{_b64(secure_claims())}.ZHVtbXk",
        ["ALG_UNKNOWN"], "unknown signing algorithm")

    # ---- stripped signature (alg present, signature empty) ----
    add(f"{_b64({'alg': 'HS256', 'typ': 'JWT'})}.{_b64(secure_claims())}.",
        ["SIGNATURE_EMPTY"], "HS256 header but signature stripped")

    # ---- key-injection headers ----
    add(_signed(secure_claims(), headers={"jwk": {"kty": "oct", "k": "YXR0YWNrZXI"}}),
        ["HEADER_JWK"], "embedded attacker public key (jwk)")
    add(_signed(secure_claims(), headers={"jku": "https://evil.example/keys.json"}),
        ["HEADER_KEY_URL"], "remote key URL (jku) to attacker host")
    add(_signed(secure_claims(), headers={"x5u": "https://evil.example/cert.pem"}),
        ["HEADER_KEY_URL"], "remote cert URL (x5u) to attacker host")
    add(_signed(secure_claims(), headers={"kid": "../../../../dev/null"}),
        ["HEADER_KID_INJECTION"], "kid path traversal")
    add(_signed(secure_claims(), headers={"kid": "key1' OR '1'='1"}),
        ["HEADER_KID_INJECTION"], "kid SQL injection")

    # ---- not yet valid (nbf in the future) ----
    add(_signed(secure_claims(nbf=NOW + 3600)), ["NOT_YET_VALID"], "nbf 1h in the future")

    # ---- missing claims ----
    c = secure_claims(); c.pop("exp")
    add(_signed(c), ["MISSING_EXP"], "no exp")
    c = secure_claims(); c.pop("aud")
    add(_signed(c), ["MISSING_AUD"], "no aud")
    c = secure_claims(); c.pop("iss")
    add(_signed(c), ["MISSING_ISS"], "no iss")
    c = secure_claims(); c.pop("aud"); c.pop("iss")
    add(_signed(c), ["MISSING_AUD", "MISSING_ISS"], "no aud and no iss")

    # ---- expired ----
    add(_signed(secure_claims(iat=NOW - 7200, nbf=NOW - 7200, exp=NOW - 3600)),
        ["EXPIRED"], "expired 1h ago")
    add(_signed(secure_claims(iat=NOW - 960, nbf=NOW - 960, exp=NOW - 60)),
        ["EXPIRED"], "expired 1m ago (fresh, 15m lifetime)")

    # ---- excessive lifetime ----
    add(_signed(secure_claims(exp=NOW + 365 * 86400)), ["LONG_LIFETIME"], "valid for a year")
    add(_signed(secure_claims(exp=NOW + 7 * 86400)), ["LONG_LIFETIME"], "valid for a week")

    # ---- weak HMAC key (HS256/384/512, various wordlist hits) ----
    for secret in ("secret", "password", "123456", "changeme", "admin",
                   "letmein", "qwerty", "welcome", "keyboard cat"):
        add(_signed(secure_claims(), secret=secret), ["WEAK_KEY"],
            f"weak key ({secret[:3]}...)")
    add(_signed(secure_claims(), secret="password", alg="HS384"),
        ["WEAK_KEY"], "weak key on HS384")
    add(_signed(secure_claims(), secret="123456", alg="HS512"),
        ["WEAK_KEY"], "weak key on HS512")

    # ---- sensitive data in payload ----
    add(_signed(secure_claims(password="s3cr3tP@ss")), ["SENSITIVE_DATA"], "password in payload")
    add(_signed(secure_claims(api_key="AK-9c1f2e3d4b5a")), ["SENSITIVE_DATA"], "api_key in payload")
    add(_signed(secure_claims(ssn="123-45-6789")), ["SENSITIVE_DATA"], "ssn in payload")
    add(_signed(secure_claims(credit_card="4111111111111111")), ["SENSITIVE_DATA"],
        "credit_card in payload")
    add(_signed(secure_claims(private_key="-----BEGIN PRIVATE KEY-----...")),
        ["SENSITIVE_DATA"], "private_key in payload")

    # ---- combined issues ----
    c = secure_claims(); c.pop("exp"); c.pop("aud")
    add(f"{_b64(none_header)}.{_b64(c)}.", ["ALG_NONE", "MISSING_EXP", "MISSING_AUD"],
        "none + missing exp + missing aud")
    add(f"{_b64(none_header)}.{_b64(secure_claims(password='pw'))}.",
        ["ALG_NONE", "SENSITIVE_DATA"], "none + sensitive data")
    add(_signed(secure_claims(iat=NOW - 7200, nbf=NOW - 7200, exp=NOW - 3600), secret="password"),
        ["EXPIRED", "WEAK_KEY"], "expired AND weak key")
    c = secure_claims(); c.pop("aud")
    add(_signed(c, secret="secret"), ["MISSING_AUD", "WEAK_KEY"], "missing aud AND weak key")
    c = secure_claims(); c.pop("exp")
    add(_signed(c, headers={"jku": "https://evil.example/keys.json"}),
        ["HEADER_KEY_URL", "MISSING_EXP"], "jku key URL + missing exp")
    add(_signed(secure_claims(exp=NOW + 365 * 86400, api_key="AK-xyz")),
        ["LONG_LIFETIME", "SENSITIVE_DATA"], "long lifetime + api_key in payload")

    # ======================================================================
    # Extended set
    # ======================================================================

    # ---- more secure negatives (variety + boundaries) ----
    add(_signed(secure_claims(jti="a1b2c3", azp="web-client", scope="read write")), [],
        "secure with jti/azp/scope")
    add(_signed(secure_claims(exp=NOW + 86400)), [],
        "lifetime exactly at the 24h limit (boundary, must NOT be flagged)")
    add(_signed(secure_claims(aud=["tokenguard-api"])), [],
        "single-element audience list")
    add(_signed(secure_claims(department="eng", email="user@lab.local",
                              email_verified=True)), [], "secure with benign custom claims")
    add(_signed(secure_claims(scope="reports.read"), alg="HS384"), [],
        "secure HS384 with scope")
    add(_signed(secure_claims(sub="svc-2", role="service", jti="svc-token-1")), [],
        "second service account, sound")
    add(_signed(secure_claims(iat=NOW - 120, nbf=NOW - 120)), [],
        "issued 2m ago, still valid")

    # ---- missing 'alg' header ----
    add(f"{_b64({'typ': 'JWT'})}.{_b64(secure_claims())}.ZHVtbXk",
        ["ALG_MISSING"], "header without an 'alg' field")

    # ---- malformed 'exp' (not a NumericDate) ----
    add(_manual_hs256({"alg": "HS256", "typ": "JWT"}, secure_claims(exp="not-a-date")),
        ["INVALID_EXP"], "exp is a string, not a timestamp")
    add(_manual_hs256({"alg": "HS256", "typ": "JWT"}, secure_claims(exp="1700000000")),
        ["INVALID_EXP"], "exp is a numeric string, not a number")

    # ---- more header-injection variety ----
    add(_signed(secure_claims(), headers={"kid": "default|whoami"}),
        ["HEADER_KID_INJECTION"], "kid command-injection characters")
    add(_signed(secure_claims(), headers={"jku": "http://127.0.0.1:8000/jwks.json"}),
        ["HEADER_KEY_URL"], "jku over plain http")
    add(_signed(secure_claims(), headers={"jwk": {"kty": "RSA", "n": "0vx7...", "e": "AQAB"}}),
        ["HEADER_JWK"], "embedded RSA jwk")

    # ---- more weak keys (wordlist coverage, more algorithms) ----
    for secret in ("dragon", "P@ssw0rd", "abc123", "tokenguard"):
        add(_signed(secure_claims(), secret=secret), ["WEAK_KEY"],
            f"weak key ({secret[:3]}...)")
    add(_signed(secure_claims(), secret="admin", alg="HS384"), ["WEAK_KEY"],
        "weak key on HS384 (admin)")
    add(_signed(secure_claims(), secret="qwerty", alg="HS512"), ["WEAK_KEY"],
        "weak key on HS512 (qwerty)")

    # ---- more missing-claim combinations ----
    c = secure_claims(); c.pop("exp"); c.pop("iss")
    add(_signed(c), ["MISSING_EXP", "MISSING_ISS"], "no exp and no iss")
    c = secure_claims(); c.pop("exp"); c.pop("aud")
    add(_signed(c), ["MISSING_EXP", "MISSING_AUD"], "no exp and no aud")
    c = secure_claims(nbf=NOW + 3600); c.pop("aud")
    add(_signed(c), ["NOT_YET_VALID", "MISSING_AUD"], "not yet valid + no aud")

    # ---- more expired / lifetime variety ----
    add(_signed(secure_claims(iat=NOW - 10 * 86400, nbf=NOW - 10 * 86400,
                              exp=NOW - 9 * 86400)), ["EXPIRED"], "expired 9 days ago")
    add(_signed(secure_claims(iat=NOW - 960, nbf=NOW - 960, exp=NOW - 60,
                              password="leak")), ["EXPIRED", "SENSITIVE_DATA"],
        "expired + sensitive data")
    add(_signed(secure_claims(exp=NOW + 30 * 86400)), ["LONG_LIFETIME"], "valid for 30 days")
    add(_signed(secure_claims(exp=NOW + 30 * 86400), secret="secret"),
        ["LONG_LIFETIME", "WEAK_KEY"], "long lifetime + weak key")

    # ---- more sensitive-data keys ----
    add(_signed(secure_claims(passwd="hunter2")), ["SENSITIVE_DATA"], "passwd in payload")
    add(_signed(secure_claims(client_secret="cs-abc123")), ["SENSITIVE_DATA"],
        "client_secret in payload")
    add(_signed(secure_claims(apikey="key-xyz")), ["SENSITIVE_DATA"], "apikey in payload")
    add(_signed(secure_claims(password="pw", ssn="123-45-6789")), ["SENSITIVE_DATA"],
        "multiple sensitive keys (password + ssn)")

    # ---- more combined issues ----
    c = secure_claims(password="pw"); c.pop("iss")
    add(f"{_b64(none_header)}.{_b64(c)}.",
        ["ALG_NONE", "MISSING_ISS", "SENSITIVE_DATA"], "none + missing iss + sensitive data")
    add(_signed(secure_claims(), secret="password",
                headers={"jwk": {"kty": "oct", "k": "YXR0"}}),
        ["HEADER_JWK", "WEAK_KEY"], "embedded jwk + weak key")
    c = secure_claims(); c.pop("aud")
    add(f"{_b64({'alg': 'HS256', 'typ': 'JWT'})}.{_b64(c)}.",
        ["SIGNATURE_EMPTY", "MISSING_AUD"], "stripped signature + no aud")
    c = secure_claims(); c.pop("exp")
    add(f"{_b64({'alg': 'HS1', 'typ': 'JWT'})}.{_b64(c)}.ZHVtbXk",
        ["ALG_UNKNOWN", "MISSING_EXP"], "unknown alg + missing exp")
    add(_signed(secure_claims(), secret="secret", headers={"kid": "../../etc/passwd"}),
        ["HEADER_KID_INJECTION", "WEAK_KEY"], "kid traversal + weak key")

    return recs


def main():
    recs = records()
    with OUT.open("w", encoding="utf-8") as fh:
        for r in recs:
            fh.write(json.dumps(r) + "\n")
    pos = sum(1 for r in recs if r["labels"])
    print(f"Wrote {len(recs)} tokens to {OUT} ({pos} insecure, {len(recs) - pos} secure)")


if __name__ == "__main__":
    main()
