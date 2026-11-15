from __future__ import annotations

import re
from typing import List

from ..config import AnalysisConfig
from ..models import Finding, Severity
from ..parser import ParsedToken

KNOWN_ALGS = {
    "HS256", "HS384", "HS512",
    "RS256", "RS384", "RS512",
    "PS256", "PS384", "PS512",
    "ES256", "ES384", "ES512", "ES256K",
    "EdDSA",
}


def _is_none(alg) -> bool:
    return isinstance(alg, str) and alg.strip().lower() == "none"


def check_none_alg(t: ParsedToken, cfg: AnalysisConfig) -> List[Finding]:
    if _is_none(t.alg):
        return [Finding(
            "ALG_NONE", "Unsigned token (alg=none)", "header", Severity.CRITICAL,
            "The header declares the 'none' algorithm, so the token carries no signature. "
            "Any server that accepts it lets an attacker forge arbitrary claims.",
            evidence=f"alg={t.alg!r}",
        )]
    return []


def check_alg_missing_or_unknown(t: ParsedToken, cfg: AnalysisConfig) -> List[Finding]:
    alg = t.alg
    if alg is None:
        return [Finding(
            "ALG_MISSING", "Missing 'alg' header", "header", Severity.HIGH,
            "Without an 'alg' value the verifier may fall back to a default or skip verification.",
        )]
    if not isinstance(alg, str):
        return [Finding("ALG_UNKNOWN", "Malformed 'alg' header", "header", Severity.MEDIUM,
                        "The 'alg' value is not a string.", evidence=repr(alg))]
    if _is_none(alg):
        return []
    out = []
    if alg not in KNOWN_ALGS:
        out.append(Finding(
            "ALG_UNKNOWN", "Unknown signing algorithm", "header", Severity.MEDIUM,
            "The algorithm is not a standard JWS algorithm; libraries may handle it unpredictably.",
            evidence=f"alg={alg!r}",
        ))
    if cfg.expected_algs and alg not in cfg.expected_algs:
        out.append(Finding(
            "ALG_UNEXPECTED", "Unexpected signing algorithm", "header", Severity.HIGH,
            "The algorithm differs from the one the application expects. Algorithm confusion "
            "(e.g. RS256 -> HS256) can let attackers sign tokens with the public key.",
            evidence=f"alg={alg!r}, expected={cfg.expected_algs}",
        ))
    return out


def check_signature_present(t: ParsedToken, cfg: AnalysisConfig) -> List[Finding]:
    if isinstance(t.alg, str) and not _is_none(t.alg) and not t.signature:
        return [Finding(
            "SIGNATURE_EMPTY", "Empty signature", "signature", Severity.HIGH,
            "The header claims a signing algorithm but the signature part is empty, "
            "a common way of probing for verifiers that skip signature checks.",
        )]
    return []


# path traversal, quotes, SQL comment/boolean, pipes, null bytes
_SUSPICIOUS_KID = re.compile(r"(\.\./|\.\.\\|['\";|]| or |--|\x00)", re.IGNORECASE)


def check_key_injection_headers(t: ParsedToken, cfg: AnalysisConfig) -> List[Finding]:
    out = []
    h = t.header
    if "jwk" in h:
        out.append(Finding(
            "HEADER_JWK", "Embedded public key (jwk)", "header", Severity.HIGH,
            "The token supplies its own verification key. If the server trusts it, an attacker "
            "can sign tokens with a key they generated.",
        ))
    for name in ("jku", "x5u"):
        if name in h:
            out.append(Finding(
                "HEADER_KEY_URL", f"Remote key URL ({name})", "header", Severity.MEDIUM,
                f"The '{name}' header points the verifier to a URL for its key. Without a strict "
                "allow-list, attackers can host their own key.",
                evidence=f"{name}={h[name]!r}",
            ))
    kid = h.get("kid")
    if isinstance(kid, str) and _SUSPICIOUS_KID.search(kid):
        out.append(Finding(
            "HEADER_KID_INJECTION", "Suspicious 'kid' value", "header", Severity.MEDIUM,
            "The key ID contains path traversal or injection characters, which can abuse "
            "servers that use 'kid' in file paths or database queries.",
            evidence=f"kid={kid!r}",
        ))
    return out


RULES = [check_none_alg, check_alg_missing_or_unknown, check_signature_present,
         check_key_injection_headers]
