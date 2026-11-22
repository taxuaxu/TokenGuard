"""A small, hand-labeled adversarial test set — the honest counterpart to the
generated dataset.

Unlike dataset/generate.py, these tokens are NOT derived from TokenGuard's own
rule definitions. They are written by hand and labeled by human judgment of what
a security reviewer would actually consider a vulnerability. The set is built
around *hard negatives*: tokens that look suspicious but are legitimate (a
clock-skew nbf, a genuine long-lived refresh token, a kid that merely contains
'--', claims whose names resemble sensitive keys, a valid asymmetric token). It
deliberately probes for false positives, so a tool is expected to score below a
perfect 1.0 here — which is a more meaningful result than the generated set.

Each record: {"token", "labels", "note", "now"[, "expected_algs"]}.
`labels` is the human ground truth (empty = should NOT be flagged).
"""
from __future__ import annotations

import base64
import json
import time
import warnings

import jwt

warnings.filterwarnings("ignore")

ISS = "https://auth.lab.local"
AUD = "tokenguard-api"
STRONG = "k9$Vq2!xLr8#Tz4@pW7&nB1^mE6*hY3%ZaCdEf"
NOW = int(time.time())


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()


def claims(**over):
    c = {"iss": ISS, "aud": AUD, "sub": "user-1", "iat": NOW, "nbf": NOW, "exp": NOW + 900}
    c.update(over)
    return c


def _signed(c, secret=STRONG, alg="HS256", headers=None):
    return jwt.encode(c, secret, algorithm=alg, headers=headers)


def _unverified(alg, c, sig_bytes=256):
    header = {"alg": alg, "typ": "JWT"}
    sig = base64.urlsafe_b64encode(b"\xa5" * sig_bytes).rstrip(b"=").decode()
    return f"{_b64(header)}.{_b64(c)}.{sig}"


def records():
    recs = []

    def add(token, labels, note, expected_algs=None):
        rec = {"token": token, "labels": labels, "note": note, "now": NOW}
        if expected_algs is not None:
            rec["expected_algs"] = expected_algs
        recs.append(rec)

    # ===================== hard NEGATIVES (should NOT be flagged) =====================
    # Looks suspicious but is legitimate. Some of these the tool over-flags (true
    # false positives); others it correctly lets pass (showing it is not naive).

    # Clock skew: a token whose nbf is 30s in the future is normal with skew tolerance.
    add(_signed(claims(nbf=NOW + 30)), [],
        "clock-skew nbf (+30s) — legitimate, should not be flagged")
    # A genuine refresh token legitimately lives much longer than an access token.
    add(_signed(claims(exp=NOW + 30 * 86400, scope="offline_access", typ="refresh")), [],
        "legitimate 30-day refresh token (offline_access)")
    # A real key id is often base64url and may contain '--'; that is not SQL injection.
    add(_signed(claims(), headers={"kid": "Ab3--Xy9_v12"}), [],
        "legitimate base64url kid containing '--'")

    # Claim names that merely resemble sensitive keys but are harmless.
    add(_signed(claims(password_updated_at=NOW - 86400)), [],
        "benign claim 'password_updated_at' (a timestamp, not a secret)")
    add(_signed(claims(api_version="v2", discard_reason="none")), [],
        "benign claims 'api_version' / 'discard_reason' (resemble api_key/card)")
    # A structurally valid asymmetric token.
    add(_unverified("RS256", claims()), [], "valid RS256 token")
    add(_unverified("ES256", claims(), sig_bytes=64), [], "valid ES256 token")
    # Lifetime exactly at the 24h threshold must not be flagged as excessive.
    add(_signed(claims(exp=NOW + 86400)), [], "lifetime exactly 24h (boundary)")
    # Multi-audience and a versioned kid with a dot are both fine.
    add(_signed(claims(aud=[AUD, "reports-api"])), [], "multi-audience list, both valid")
    add(_signed(claims(), headers={"kid": "signing-key.v3"}), [],
        "versioned kid with a dot (no traversal)")

    # ===================== hard POSITIVES (should be flagged) =====================
    # Real issues, written by hand, to check the tool does not miss subtle cases.

    add(_signed(claims(iat=NOW - 900, nbf=NOW - 900, exp=NOW - 10)), ["EXPIRED"],
        "expired only 10 seconds ago")
    none_hdr = {"alg": "none", "typ": "JWT"}
    add(f"{_b64(none_hdr)}.{_b64(claims())}.", ["ALG_NONE"], "unsigned token (alg=none)")
    add(_signed(claims(context={"session": {"ssn": "123-45-6789"}})), ["SENSITIVE_DATA"],
        "ssn nested two levels deep in the payload")
    add(_signed(claims(), secret="changeme"), ["WEAK_KEY"], "weak HMAC key 'changeme'")
    add(_signed(claims()), ["ALG_UNEXPECTED"],
        "algorithm confusion: app pins RS256, token is HS256", expected_algs=["RS256"])

    return recs


def main():
    recs = records()
    pos = sum(1 for r in recs if r["labels"])
    print(f"{len(recs)} hand-labeled hard cases ({pos} insecure, {len(recs) - pos} "
          f"legitimate-but-suspicious)")


if __name__ == "__main__":
    main()
