"""Generate a controlled, labeled dataset of secure and insecure JWTs.

Coverage is derived from TokenGuard's own rule definitions, so the dataset
exercises **every** known algorithm, **every** sensitive-claim key, and **every**
secret in the weak-key wordlist, alongside the full set of algorithm,
header-injection, and claim defects and a systematic set of multi-issue
combinations. It also includes a broad set of secure and boundary negatives.

Each record: {"token", "labels", "note", "now"[, "expected_algs"]}
An empty labels list marks a secure (negative) example. "expected_algs" pins the
algorithms the target application accepts (for algorithm-confusion scoring).

Usage:  python dataset/generate.py            -> writes dataset/tokens.jsonl
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
import time
import warnings
from pathlib import Path

import jwt

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tokenguard.config import DEFAULT_WORDLIST          # noqa: E402
from tokenguard.rules.algorithm import KNOWN_ALGS       # noqa: E402
from tokenguard.rules.claims import SENSITIVE_KEYS      # noqa: E402

warnings.filterwarnings("ignore")  # suppress PyJWT short-key warnings for weak samples

OUT = Path(__file__).resolve().parent / "tokens.jsonl"

ISSUER = "https://auth.lab.local"
AUDIENCE = "tokenguard-api"
STRONG = "k9$Vq2!xLr8#Tz4@pW7&nB1^mE6*hY3%ZaCdEf"  # 38 chars, not in wordlist
HMAC_ALGS = {"HS256", "HS384", "HS512"}
NOW = int(time.time())

# approximate raw signature sizes per asymmetric algorithm (bytes)
_ASYM_SIG_BYTES = {
    "RS256": 256, "RS384": 256, "RS512": 256,
    "PS256": 256, "PS384": 256, "PS512": 256,
    "ES256": 64, "ES256K": 64, "ES384": 96, "ES512": 132,
    "EdDSA": 64,
}


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()


def _dummy_sig(n: int) -> str:
    return base64.urlsafe_b64encode(b"\xa5" * n).rstrip(b"=").decode()


def secure_claims(**over):
    c = {"iss": ISSUER, "aud": AUDIENCE, "sub": "user-1", "role": "user",
         "iat": NOW, "nbf": NOW, "exp": NOW + 900}
    c.update(over)
    return c


def expired_claims(**over):
    base = dict(iat=NOW - 7200, nbf=NOW - 7200, exp=NOW - 3600)
    base.update(over)
    return secure_claims(**base)


def _signed(claims, secret=STRONG, alg="HS256", headers=None):
    return jwt.encode(claims, secret, algorithm=alg, headers=headers)


def _manual_hs256(header, payload, secret=STRONG):
    """HS256 token with full control of the raw payload (e.g. a malformed
    'exp'), which jwt.encode would coerce or reject."""
    signing_input = f"{_b64(header)}.{_b64(payload)}".encode()
    sig = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()).rstrip(b"=").decode()
    return f"{signing_input.decode()}.{sig}"


def _b64s(s: str) -> str:
    """Base64URL-encode a raw string (used to keep duplicate JSON keys intact,
    which json.dumps would collapse)."""
    return base64.urlsafe_b64encode(s.encode()).rstrip(b"=").decode()


def _raw_payload(header, payload_json: str, sig="ZHVtbXk") -> str:
    """Token with a hand-written (possibly duplicate-keyed) raw JSON payload."""
    return f"{_b64(header)}.{_b64s(payload_json)}.{sig}"


def _raw(header, payload, sig="ZHVtbXk") -> str:
    """Token with an arbitrary header and a placeholder signature. Used for
    cases jwt.encode refuses to build (alg=none, missing/unknown/non-string
    alg, stripped signature). TokenGuard analyzes structure, not signatures."""
    return f"{_b64(header)}.{_b64(payload)}.{sig}"


def _unverified(alg, claims):
    """Structurally valid token for an asymmetric algorithm with a placeholder
    signature (no key material needed)."""
    return _raw({"alg": alg, "typ": "JWT"}, claims, _dummy_sig(_ASYM_SIG_BYTES.get(alg, 64)))


def _secure_for_alg(alg):
    if alg in HMAC_ALGS:
        return _signed(secure_claims(), STRONG, alg)
    return _unverified(alg, secure_claims())


def sample_wordlist(words, n):
    """Deterministically pick n secrets spread evenly across the wordlist, so
    the sample spans its categories (common passwords, JWT/framework defaults,
    numeric and keyboard patterns) instead of clustering at the top."""
    if not n or n >= len(words):
        return list(words)
    step = len(words) / n
    return [words[int(i * step)] for i in range(n)]


def records(weak_sample=15):
    recs = []

    def add(token, labels, note, expected_algs=None):
        # Record the generation time with each token so the evaluator analyzes
        # it against a fixed reference, not the wall clock (keeps time-relative
        # checks reproducible). expected_algs pins the app's accepted algorithms.
        rec = {"token": token, "labels": labels, "note": note, "now": NOW}
        if expected_algs is not None:
            rec["expected_algs"] = expected_algs
        recs.append(rec)

    none_hdr = {"alg": "none", "typ": "JWT"}
    hs_hdr = {"alg": "HS256", "typ": "JWT"}

    # ==================================================================
    # 1. Secure negatives: one per known algorithm (+ boundaries/variants)
    # ==================================================================
    for alg in sorted(KNOWN_ALGS):
        add(_secure_for_alg(alg), [], f"secure {alg}")

    add(_signed(secure_claims(exp=NOW + 60)), [],
        "intentionally short-lived (must NOT be LONG_LIFETIME)")
    add(_signed(secure_claims(exp=NOW + 86400)), [],
        "lifetime exactly at the 24h limit (boundary)")
    add(_signed(secure_claims(exp=NOW + 86000)), [],
        "lifetime just under the 24h limit (boundary)")
    add(_signed(secure_claims(nbf=NOW - 60)), [], "nbf slightly in the past")
    add(_signed(secure_claims(nbf=NOW)), [], "nbf exactly now")
    add(_signed(secure_claims(aud=["tokenguard-api", "reports-api"])), [],
        "multi-audience, both valid")
    add(_signed(secure_claims(aud=["tokenguard-api"])), [], "single-element audience list")
    add(_signed(secure_claims(role="admin")), [], "admin role but otherwise sound")
    add(_signed(secure_claims(sub="svc", role="service")), [], "service account, sound")
    add(_signed(secure_claims(department="eng", email="user@lab.local",
                              email_verified=True)), [], "benign custom claims")
    add(_signed(secure_claims(jti="a1", azp="web", scope="read write",
                              amr=["pwd"], acr="1")), [], "many standard claims")
    add(_signed(secure_claims(scope="reports.read"), alg="HS384"), [], "secure HS384 w/ scope")
    add(_unverified("RS256", secure_claims()), [],
        "RS256, app pins RS256 (matches, must NOT be flagged)", expected_algs=["RS256"])

    # ==================================================================
    # 2. Algorithm defects
    # ==================================================================
    # alg=none and its case variations (case-bypass attempts)
    for alg in ("none", "None", "NONE", "nOnE"):
        add(_raw({"alg": alg, "typ": "JWT"}, secure_claims(), sig=""),
            ["ALG_NONE"], f"alg={alg!r} (unsigned)")
    # missing alg
    add(_raw({"typ": "JWT"}, secure_claims()), ["ALG_MISSING"], "no 'alg' header")
    # unknown string algs
    for alg in ("HS1", "RS1", "foobar", "A128KW"):
        add(_raw({"alg": alg, "typ": "JWT"}, secure_claims()),
            ["ALG_UNKNOWN"], f"unknown alg {alg!r}")
    # non-string algs (malformed)
    for bad in (123, ["HS256"], True):
        add(_raw({"alg": bad, "typ": "JWT"}, secure_claims()),
            ["ALG_UNKNOWN"], f"malformed alg {bad!r}")
    # stripped signature per HMAC alg + one asymmetric
    for alg in ("HS256", "HS384", "HS512"):
        add(_raw({"alg": alg, "typ": "JWT"}, secure_claims(), sig=""),
            ["SIGNATURE_EMPTY"], f"{alg} header, signature stripped")
    add(_raw({"alg": "RS256", "typ": "JWT"}, secure_claims(), sig=""),
        ["SIGNATURE_EMPTY"], "RS256 header, signature stripped")
    # algorithm confusion (app pins asymmetric, attacker downgrades)
    add(_signed(secure_claims()), ["ALG_UNEXPECTED"],
        "RS256-expecting app, forged HS256 (classic confusion)", expected_algs=["RS256"])
    add(_signed(secure_claims(), alg="HS384"), ["ALG_UNEXPECTED"],
        "RS384-expecting app, forged HS384", expected_algs=["RS384"])
    add(_signed(secure_claims()), ["ALG_UNEXPECTED"],
        "ES256-expecting app, forged HS256", expected_algs=["ES256"])
    add(_unverified("RS256", secure_claims()), ["ALG_UNEXPECTED"],
        "ES256-expecting app, receives RS256", expected_algs=["ES256"])

    # ==================================================================
    # 3. Header-injection defects
    # ==================================================================
    add(_signed(secure_claims(), headers={"jwk": {"kty": "oct", "k": "YXR0YWNrZXI"}}),
        ["HEADER_JWK"], "embedded jwk (oct)")
    add(_signed(secure_claims(), headers={"jwk": {"kty": "RSA", "n": "0vx7", "e": "AQAB"}}),
        ["HEADER_JWK"], "embedded jwk (RSA)")
    add(_signed(secure_claims(), headers={"jwk": {"kty": "EC", "crv": "P-256", "x": "f", "y": "g"}}),
        ["HEADER_JWK"], "embedded jwk (EC)")
    add(_signed(secure_claims(), headers={"jku": "https://evil.example/keys.json"}),
        ["HEADER_KEY_URL"], "jku https to attacker")
    add(_signed(secure_claims(), headers={"jku": "http://127.0.0.1:8000/jwks.json"}),
        ["HEADER_KEY_URL"], "jku over plain http")
    add(_signed(secure_claims(), headers={"x5u": "https://evil.example/cert.pem"}),
        ["HEADER_KEY_URL"], "x5u https to attacker")
    add(_signed(secure_claims(), headers={"x5u": "http://10.0.0.1/c.pem"}),
        ["HEADER_KEY_URL"], "x5u over plain http")
    for kid, note in [
        ("../../../../dev/null", "kid unix path traversal"),
        ("..\\..\\windows\\win.ini", "kid windows path traversal"),
        ("key1' OR '1'='1", "kid SQL injection"),
        ("a--b", "kid SQL comment"),
        ("default|whoami", "kid command injection"),
        ("n\x00ull", "kid null byte"),
    ]:
        add(_signed(secure_claims(), headers={"kid": kid}), ["HEADER_KID_INJECTION"], note)

    # ==================================================================
    # 4. Claim defects
    # ==================================================================
    c = secure_claims(); c.pop("exp"); add(_signed(c), ["MISSING_EXP"], "no exp")
    c = secure_claims(); c.pop("aud"); add(_signed(c), ["MISSING_AUD"], "no aud")
    c = secure_claims(); c.pop("iss"); add(_signed(c), ["MISSING_ISS"], "no iss")
    # malformed exp (not a NumericDate)
    for bad, note in [("not-a-date", "exp is a text string"),
                      ("1700000000", "exp is a numeric string"),
                      ([NOW + 900], "exp is a list"),
                      (True, "exp is a boolean")]:
        add(_manual_hs256(hs_hdr, secure_claims(exp=bad)), ["INVALID_EXP"], note)
    # expired
    add(_signed(expired_claims()), ["EXPIRED"], "expired 1h ago")
    add(_signed(secure_claims(iat=NOW - 960, nbf=NOW - 960, exp=NOW - 60)),
        ["EXPIRED"], "expired 1m ago (fresh, 15m lifetime)")
    add(_signed(secure_claims(iat=NOW - 10 * 86400, nbf=NOW - 10 * 86400,
                              exp=NOW - 9 * 86400)), ["EXPIRED"], "expired 9 days ago")
    # excessive lifetime
    for days, note in [(2, "2 days"), (7, "a week"), (30, "30 days"), (365, "a year")]:
        add(_signed(secure_claims(exp=NOW + days * 86400)), ["LONG_LIFETIME"],
            f"valid for {note}")
    # not yet valid
    add(_signed(secure_claims(nbf=NOW + 3600)), ["NOT_YET_VALID"], "nbf 1h in the future")
    add(_signed(secure_claims(nbf=NOW + 86400)), ["NOT_YET_VALID"], "nbf 1 day in the future")
    # sensitive data: one token per sensitive key the tool recognizes
    for key in sorted(SENSITIVE_KEYS):
        add(_signed(secure_claims(**{key: f"VALUE-{key}"})), ["SENSITIVE_DATA"],
            f"sensitive key {key!r} in payload")
    add(_signed(secure_claims(password="pw", ssn="123-45-6789",
                              credit_card="4111111111111111")), ["SENSITIVE_DATA"],
        "multiple sensitive keys at once")

    # ==================================================================
    # 5. Weak HMAC keys: a balanced sample of the wordlist (HS256) + other
    #    algs. weak_sample=None emits the full wordlist (--full-wordlist).
    # ==================================================================
    wordlist = [s for s in DEFAULT_WORDLIST.read_text(encoding="utf-8",
                                                      errors="ignore").splitlines() if s.strip()]
    for secret in sample_wordlist(wordlist, weak_sample):
        add(_signed(secure_claims(), secret=secret, alg="HS256"), ["WEAK_KEY"],
            f"weak key HS256 ({secret[:3]}...)")
    for secret in ("secret", "password", "123456", "admin", "qwerty", "changeme"):
        add(_signed(secure_claims(), secret=secret, alg="HS384"), ["WEAK_KEY"],
            f"weak key HS384 ({secret[:3]}...)")
        add(_signed(secure_claims(), secret=secret, alg="HS512"), ["WEAK_KEY"],
            f"weak key HS512 ({secret[:3]}...)")

    # ==================================================================
    # 6. Multi-issue combinations
    # ==================================================================
    c = secure_claims(); c.pop("exp")
    add(_raw(none_hdr, c, sig=""), ["ALG_NONE", "MISSING_EXP"], "none + no exp")
    c = secure_claims(); c.pop("aud")
    add(_raw(none_hdr, c, sig=""), ["ALG_NONE", "MISSING_AUD"], "none + no aud")
    c = secure_claims(); c.pop("iss")
    add(_raw(none_hdr, c, sig=""), ["ALG_NONE", "MISSING_ISS"], "none + no iss")
    add(_raw(none_hdr, secure_claims(password="pw"), sig=""),
        ["ALG_NONE", "SENSITIVE_DATA"], "none + sensitive data")
    c = secure_claims(); c.pop("exp"); c.pop("aud")
    add(_raw(none_hdr, c, sig=""), ["ALG_NONE", "MISSING_EXP", "MISSING_AUD"],
        "none + no exp + no aud")
    c = secure_claims(password="pw"); c.pop("iss")
    add(_raw(none_hdr, c, sig=""), ["ALG_NONE", "MISSING_ISS", "SENSITIVE_DATA"],
        "none + no iss + sensitive")
    add(_signed(expired_claims(), secret="password"), ["EXPIRED", "WEAK_KEY"],
        "expired + weak key")
    add(_signed(expired_claims(password="pw")), ["EXPIRED", "SENSITIVE_DATA"],
        "expired + sensitive data")
    c = expired_claims(); c.pop("aud")
    add(_signed(c), ["EXPIRED", "MISSING_AUD"], "expired + no aud")
    add(_signed(secure_claims(exp=NOW + 30 * 86400), secret="secret"),
        ["LONG_LIFETIME", "WEAK_KEY"], "long lifetime + weak key")
    add(_signed(secure_claims(exp=NOW + 365 * 86400, api_key="AK-x")),
        ["LONG_LIFETIME", "SENSITIVE_DATA"], "long lifetime + sensitive data")
    c = secure_claims(); c.pop("aud")
    add(_signed(c, secret="secret"), ["MISSING_AUD", "WEAK_KEY"], "no aud + weak key")
    c = secure_claims(); c.pop("exp"); c.pop("iss")
    add(_signed(c), ["MISSING_EXP", "MISSING_ISS"], "no exp + no iss")
    c = secure_claims(); c.pop("exp"); c.pop("aud")
    add(_signed(c), ["MISSING_EXP", "MISSING_AUD"], "no exp + no aud")
    c = secure_claims(nbf=NOW + 3600); c.pop("aud")
    add(_signed(c), ["NOT_YET_VALID", "MISSING_AUD"], "not yet valid + no aud")
    add(_signed(secure_claims(), secret="password",
                headers={"jwk": {"kty": "oct", "k": "YXR0"}}),
        ["HEADER_JWK", "WEAK_KEY"], "jwk + weak key")
    c = secure_claims(); c.pop("exp")
    add(_signed(c, headers={"jku": "https://evil.example/keys.json"}),
        ["HEADER_KEY_URL", "MISSING_EXP"], "jku + no exp")
    add(_signed(secure_claims(), secret="secret", headers={"kid": "../../etc/passwd"}),
        ["HEADER_KID_INJECTION", "WEAK_KEY"], "kid traversal + weak key")
    c = secure_claims(); c.pop("aud")
    add(_raw(hs_hdr, c, sig=""), ["SIGNATURE_EMPTY", "MISSING_AUD"],
        "stripped signature + no aud")
    c = secure_claims(); c.pop("exp")
    add(_raw({"alg": "HS1", "typ": "JWT"}, c), ["ALG_UNKNOWN", "MISSING_EXP"],
        "unknown alg + no exp")
    c = secure_claims(); c.pop("exp")
    add(_raw({"alg": 123, "typ": "JWT"}, c), ["ALG_UNKNOWN", "MISSING_EXP"],
        "malformed alg + no exp")
    add(_signed(expired_claims()), ["ALG_UNEXPECTED", "EXPIRED"],
        "confusion (HS256 vs RS256) + expired", expected_algs=["RS256"])
    c = secure_claims(); c.pop("aud")
    add(_signed(c, secret="secret"), ["ALG_UNEXPECTED", "MISSING_AUD", "WEAK_KEY"],
        "confusion + no aud + weak key", expected_algs=["RS256"])
    add(_signed(secure_claims(), headers={
        "jwk": {"kty": "oct", "k": "YXR0"},
        "jku": "https://evil.example/k.json",
        "kid": "../../etc/passwd",
    }), ["HEADER_JWK", "HEADER_KEY_URL", "HEADER_KID_INJECTION"], "header soup (jwk+jku+kid)")

    # ======================================================================
    # 'crit' header abuse (RFC 7515) and duplicate JSON keys (parser confusion)
    # ======================================================================
    add(_manual_hs256({"alg": "HS256", "typ": "JWT", "crit": ["alg"]}, secure_claims()),
        ["CRIT_HEADER"], "crit names a registered header (alg)")
    add(_manual_hs256({"alg": "HS256", "typ": "JWT", "crit": ["x-custom"]}, secure_claims()),
        ["CRIT_HEADER"], "crit names a header not present")
    add(_manual_hs256({"alg": "HS256", "typ": "JWT", "crit": "x"}, secure_claims()),
        ["CRIT_HEADER"], "crit is not an array")
    # well-formed crit (custom extension, present) must NOT be flagged
    add(_manual_hs256({"alg": "HS256", "typ": "JWT", "crit": ["x-custom"], "x-custom": True},
                      secure_claims()), [], "crit well-formed and present (secure)")

    dup_payload = ('{"iss":"' + ISSUER + '","aud":"' + AUDIENCE + '","sub":"a","sub":"b",'
                   + f'"iat":{NOW},"nbf":{NOW},"exp":{NOW + 900}' + '}')
    add(_raw_payload({"alg": "HS256", "typ": "JWT"}, dup_payload),
        ["DUPLICATE_KEYS"], "duplicate 'sub' in payload")
    dup_typ_header = '{"typ":"JWT","typ":"JWT","alg":"HS256"}'
    add(_b64s(dup_typ_header) + "." + _b64(secure_claims()) + ".ZHVtbXk",
        ["DUPLICATE_KEYS"], "duplicate 'typ' in header")
    # duplicate 'alg' smuggling: the last value (none) wins -> ALG_NONE + DUPLICATE_KEYS
    dup_alg_header = '{"alg":"HS256","alg":"none","typ":"JWT"}'
    add(_b64s(dup_alg_header) + "." + _b64(secure_claims()) + ".",
        ["ALG_NONE", "DUPLICATE_KEYS"], "duplicate 'alg' (HS256 then none) smuggling")

    return recs


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Generate the labeled JWT dataset.")
    ap.add_argument("--weak-sample", type=int, default=15, metavar="N",
                    help="number of wordlist secrets to include as weak-key samples "
                         "(default 15, spread across the wordlist)")
    ap.add_argument("--full-wordlist", action="store_true",
                    help="include a weak-key token for every secret in the wordlist "
                         "(exhaustive; overrides --weak-sample)")
    args = ap.parse_args(argv)

    weak_sample = None if args.full_wordlist else args.weak_sample
    recs = records(weak_sample=weak_sample)
    with OUT.open("w", encoding="utf-8") as fh:
        for r in recs:
            fh.write(json.dumps(r) + "\n")
    pos = sum(1 for r in recs if r["labels"])
    weak = sum(1 for r in recs if "WEAK_KEY" in r["labels"])
    print(f"Wrote {len(recs)} tokens to {OUT} ({pos} insecure, {len(recs) - pos} secure; "
          f"{weak} weak-key)")


if __name__ == "__main__":
    main()
