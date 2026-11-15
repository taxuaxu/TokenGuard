"""Weak HMAC key detection: recompute the signature with each candidate secret."""
from __future__ import annotations

import hashlib
import hmac
from functools import lru_cache
from pathlib import Path
from typing import List, Optional, Sequence

from ..config import AnalysisConfig
from ..models import Finding, Severity, mask
from ..parser import ParsedToken

HMAC_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


@lru_cache(maxsize=8)
def load_wordlist(path: str) -> tuple:
    p = Path(path)
    if not p.exists():
        return ()
    with p.open("r", encoding="utf-8", errors="ignore") as fh:
        return tuple(line.rstrip("\r\n") for line in fh if line.rstrip("\r\n"))


def crack_hmac(t: ParsedToken, candidates: Sequence[str]) -> Optional[str]:
    digest = HMAC_ALGS.get(t.alg)
    if digest is None or not t.signature:
        return None
    msg = t.signing_input
    for secret in candidates:
        sig = hmac.new(secret.encode("utf-8"), msg, digest).digest()
        if hmac.compare_digest(sig, t.signature):
            return secret
    return None


def check_weak_hmac_key(t: ParsedToken, cfg: AnalysisConfig) -> List[Finding]:
    if t.alg not in HMAC_ALGS:
        return []
    candidates = list(cfg.extra_secrets) + list(load_wordlist(str(cfg.wordlist_path)))
    secret = crack_hmac(t, candidates)
    if secret is None:
        return []
    return [Finding(
        "WEAK_KEY", "Weak HMAC signing key recovered", "signature", Severity.CRITICAL,
        "The signing secret was found in a wordlist of common secrets. An attacker who "
        "recovers it can forge valid tokens with any claims.",
        evidence=f"secret={mask(secret)} (length {len(secret)})",
    )]


RULES = [check_weak_hmac_key]
