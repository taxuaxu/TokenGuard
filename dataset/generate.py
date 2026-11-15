"""Generate a controlled, labeled dataset of secure and insecure JWTs.

Each record: {"token": "...", "labels": [...], "note": "..."}
An empty labels list marks a secure (negative) example.

Usage:  python dataset/generate.py            -> writes dataset/tokens.jsonl
"""
from __future__ import annotations

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
WEAK = "secret"
NOW = int(time.time())


def _b64(obj: dict) -> str:
    import base64
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()


def secure_claims(**over):
    c = {"iss": ISSUER, "aud": AUDIENCE, "sub": "user-1", "role": "user",
         "iat": NOW, "nbf": NOW, "exp": NOW + 900}
    c.update(over)
    return c


def records():
    recs = []
    add = lambda token, labels, note: recs.append({"token": token, "labels": labels, "note": note})

    # ---- secure negative examples (labels = []) ----
    add(jwt.encode(secure_claims(), STRONG, algorithm="HS256"), [], "standard secure HS256")
    add(jwt.encode(secure_claims(exp=NOW + 60), STRONG, algorithm="HS256"), [],
        "intentionally short-lived (must NOT be flagged LONG_LIFETIME)")
    add(jwt.encode(secure_claims(role="admin"), STRONG, algorithm="HS256"), [],
        "admin role but otherwise sound")
    add(jwt.encode(secure_claims(sub="svc", aud=["tokenguard-api", "reports-api"]),
                   STRONG, algorithm="HS256"), [], "multi-audience, both valid")

    # ---- alg=none (no signature) ----
    header = {"alg": "none", "typ": "JWT"}
    add(f"{_b64(header)}.{_b64(secure_claims())}.", ["ALG_NONE"], "none algorithm")

    # ---- missing claims ----
    c = secure_claims(); c.pop("exp")
    add(jwt.encode(c, STRONG, algorithm="HS256"), ["MISSING_EXP"], "no exp")
    c = secure_claims(); c.pop("aud")
    add(jwt.encode(c, STRONG, algorithm="HS256"), ["MISSING_AUD"], "no aud")
    c = secure_claims(); c.pop("iss")
    add(jwt.encode(c, STRONG, algorithm="HS256"), ["MISSING_ISS"], "no iss")

    # ---- expired ----
    add(jwt.encode(secure_claims(iat=NOW - 7200, nbf=NOW - 7200, exp=NOW - 3600),
                   STRONG, algorithm="HS256"), ["EXPIRED"], "expired 1h ago")

    # ---- excessive lifetime ----
    add(jwt.encode(secure_claims(exp=NOW + 365 * 86400), STRONG, algorithm="HS256"),
        ["LONG_LIFETIME"], "valid for a year")

    # ---- weak HMAC key ----
    for secret in ("secret", "password", "123456", "changeme"):
        add(jwt.encode(secure_claims(), secret, algorithm="HS256"), ["WEAK_KEY"],
            f"weak key ({secret[:2]}...)")

    # ---- sensitive data ----
    add(jwt.encode(secure_claims(password="s3cr3tP@ss"), STRONG, algorithm="HS256"),
        ["SENSITIVE_DATA"], "password in payload")

    # ---- combined issues ----
    header = {"alg": "none", "typ": "JWT"}
    c = secure_claims(); c.pop("exp"); c.pop("aud")
    add(f"{_b64(header)}.{_b64(c)}.", ["ALG_NONE", "MISSING_EXP", "MISSING_AUD"],
        "none + missing exp + missing aud")
    add(jwt.encode(secure_claims(iat=NOW - 7200, nbf=NOW - 7200, exp=NOW - 3600), "password",
                   algorithm="HS256"), ["EXPIRED", "WEAK_KEY"], "expired AND weak key")

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
