"""Deliberately misconfigured JWT server for TokenGuard's active testing mode.

!!! FOR LOCAL LAB USE ONLY. Every endpoint except /api/secure has an intentional flaw. !!!

Run:  python vuln_server/app.py          (listens on 127.0.0.1:5000)

The server also plays the role of a tiny token issuer (/login) so the tester can
obtain legitimately issued tokens (a valid one, an already-expired one, and one
issued for a different audience) without knowing any server secret.
"""
from __future__ import annotations

import os
import time

import jwt
from flask import Flask, jsonify, request

ISSUER = "http://127.0.0.1:5000"
AUDIENCE = "tokenguard-lab-api"
OTHER_AUDIENCE = "some-other-service"
STRONG_SECRET = os.environ.get("LAB_STRONG_SECRET") or os.urandom(32).hex()
WEAK_SECRET = "secret"  # intentionally guessable

# name -> (intended flaw, used only as ground truth for evaluation)
ENDPOINTS = {
    "secure": None,
    "accepts-none": "ALG_NONE",
    "no-signature-check": "NO_SIGNATURE_CHECK",
    "no-exp-check": "NO_EXP_CHECK",
    "no-aud-check": "NO_AUD_CHECK",
    "weak-secret": "WEAK_KEY",
}

app = Flask(__name__)


def _secret_for(endpoint: str) -> str:
    return WEAK_SECRET if endpoint == "weak-secret" else STRONG_SECRET


def _bearer():
    auth = request.headers.get("Authorization", "")
    return auth[7:].strip() if auth.lower().startswith("bearer ") else None


def _unauthorized(reason: str):
    resp = jsonify({"accepted": False, "error": reason})
    resp.status_code = 401
    resp.headers["WWW-Authenticate"] = f'Bearer error="invalid_token", error_description="{reason}"'
    return resp


def _ok(claims: dict):
    return jsonify({"accepted": True, "sub": claims.get("sub"), "role": claims.get("role")})


def _strict_decode(token: str, secret: str, **options) -> dict:
    opts = {"require": ["exp", "aud", "iss"]}
    opts.update(options)
    return jwt.decode(token, secret, algorithms=["HS256"], audience=AUDIENCE,
                      issuer=ISSUER, options=opts)


# ---------------------------------------------------------------- issuer

@app.get("/login")
def login():
    """Issue a token for `endpoint`. scenario: valid | expired | other-aud"""
    endpoint = request.args.get("endpoint", "secure")
    scenario = request.args.get("scenario", "valid")
    if endpoint not in ENDPOINTS:
        return jsonify({"error": "unknown endpoint"}), 404
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": "alice", "role": "user",
              "iat": now, "exp": now + 900}
    if scenario == "expired":
        claims.update(iat=now - 7200, exp=now - 3600)
    elif scenario == "other-aud":
        claims["aud"] = OTHER_AUDIENCE
    elif scenario != "valid":
        return jsonify({"error": "unknown scenario"}), 400
    return jsonify({"token": jwt.encode(claims, _secret_for(endpoint), algorithm="HS256")})


@app.get("/endpoints")
def list_endpoints():
    return jsonify({"endpoints": [f"/api/{n}" for n in ENDPOINTS],
                    "_ground_truth": ENDPOINTS})


# ---------------------------------------------------------------- protected APIs

@app.get("/api/secure")
def secure():
    tok = _bearer()
    if not tok:
        return _unauthorized("missing token")
    try:
        return _ok(_strict_decode(tok, STRONG_SECRET))
    except jwt.PyJWTError as exc:
        return _unauthorized(str(exc))


@app.get("/api/accepts-none")
def accepts_none():
    """FLAW: trusts the token's own 'alg' header; alg=none skips verification."""
    tok = _bearer()
    if not tok:
        return _unauthorized("missing token")
    try:
        header = jwt.get_unverified_header(tok)
        if str(header.get("alg", "")).lower() == "none":
            return _ok(jwt.decode(tok, options={"verify_signature": False}))
        return _ok(_strict_decode(tok, STRONG_SECRET))
    except jwt.PyJWTError as exc:
        return _unauthorized(str(exc))


@app.get("/api/no-signature-check")
def no_signature_check():
    """FLAW: decodes without verifying the signature at all."""
    tok = _bearer()
    if not tok:
        return _unauthorized("missing token")
    try:
        header = jwt.get_unverified_header(tok)
        if str(header.get("alg", "")).lower() == "none":
            return _unauthorized("alg none not allowed")
        claims = jwt.decode(tok, options={"verify_signature": False, "verify_exp": True,
                                          "verify_aud": True, "verify_iss": True},
                            audience=AUDIENCE, issuer=ISSUER)
        return _ok(claims)
    except jwt.PyJWTError as exc:
        return _unauthorized(str(exc))


@app.get("/api/no-exp-check")
def no_exp_check():
    """FLAW: expiration time is ignored."""
    tok = _bearer()
    if not tok:
        return _unauthorized("missing token")
    try:
        return _ok(_strict_decode(tok, STRONG_SECRET, verify_exp=False, require=["aud", "iss"]))
    except jwt.PyJWTError as exc:
        return _unauthorized(str(exc))


@app.get("/api/no-aud-check")
def no_aud_check():
    """FLAW: audience is not validated, so tokens for other services are accepted."""
    tok = _bearer()
    if not tok:
        return _unauthorized("missing token")
    try:
        claims = jwt.decode(tok, STRONG_SECRET, algorithms=["HS256"], issuer=ISSUER,
                            options={"verify_aud": False, "require": ["exp", "iss"]})
        return _ok(claims)
    except jwt.PyJWTError as exc:
        return _unauthorized(str(exc))


@app.get("/api/weak-secret")
def weak_secret():
    """FLAW: validation is correct, but the HMAC secret is guessable."""
    tok = _bearer()
    if not tok:
        return _unauthorized("missing token")
    try:
        return _ok(_strict_decode(tok, WEAK_SECRET))
    except jwt.PyJWTError as exc:
        return _unauthorized(str(exc))


if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore", category=jwt.warnings.InsecureKeyLengthWarning)
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)
