from __future__ import annotations

import json
import re
from typing import List

from ..config import AnalysisConfig
from ..models import Finding, Severity
from ..parser import ParsedToken, b64url_decode

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


# path traversal, quotes, SQL boolean, pipes, null bytes. A bare "--" is NOT
# flagged: it is a legal base64url separator and flagging it over-reports (a real
# SQL-comment injection also carries a quote or boolean, which is still caught).
_SUSPICIOUS_KID = re.compile(r"(\.\./|\.\.\\|['\";|]| or |\x00)", re.IGNORECASE)


def check_key_injection_headers(t: ParsedToken, cfg: AnalysisConfig) -> List[Finding]:
    out = []
    h = t.header
    if "jwk" in h:
        out.append(Finding(
            "HEADER_JWK", "Embedded public key (jwk)", "header", Severity.HIGH,
            "The token supplies its own verification key. If the server trusts it, an attacker "
            "can sign tokens with a key they generated.",
        ))
    if "x5c" in h:
        out.append(Finding(
            "HEADER_X5C", "Embedded certificate chain (x5c)", "header", Severity.HIGH,
            "The token embeds its own X.509 certificate chain. If the server verifies with the "
            "embedded chain instead of a trusted key, an attacker can supply a self-signed one.",
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


# Registered JOSE header parameter names (RFC 7515/7516/7518/7797). A 'crit'
# entry naming one of these is invalid per RFC 7515 4.1.11.
REGISTERED_HEADERS = {
    "alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty",
    "crit", "b64", "enc", "zip", "epk", "apu", "apv", "iv", "tag", "p2s", "p2c",
}


def check_crit_header(t: ParsedToken, cfg: AnalysisConfig) -> List[Finding]:
    if "crit" not in t.header:
        return []
    crit = t.header["crit"]
    reasons = []
    if not isinstance(crit, list) or not crit or not all(isinstance(x, str) for x in crit):
        reasons.append("'crit' must be a non-empty array of strings")
    else:
        registered = [x for x in crit if x in REGISTERED_HEADERS]
        absent = [x for x in crit if x not in t.header]
        if registered:
            reasons.append(f"names registered header(s) {registered}")
        if absent:
            reasons.append(f"names header(s) not present {absent}")
    if not reasons:
        return []  # a well-formed crit (custom extensions, all present) is valid
    return [Finding(
        "CRIT_HEADER", "Abused 'crit' header", "header", Severity.MEDIUM,
        "The 'crit' header lists extensions a verifier must understand, but here it is "
        "misused (" + "; ".join(reasons) + "). Verifiers that ignore 'crit' or mishandle "
        "it can be tricked into accepting a token they do not fully process.",
        evidence=f"crit={crit!r}",
    )]


def _duplicate_keys(segment_b64: str) -> List[str]:
    """Return keys that appear more than once in the raw JSON of a segment."""
    try:
        raw = b64url_decode(segment_b64)
    except Exception:  # noqa: BLE001
        return []
    dups: List[str] = []

    def hook(pairs):
        seen = set()
        for k, _ in pairs:
            if k in seen:
                dups.append(k)
            seen.add(k)
        return dict(pairs)

    try:
        json.loads(raw, object_pairs_hook=hook)
    except Exception:  # noqa: BLE001
        return []
    return dups


def check_duplicate_keys(t: ParsedToken, cfg: AnalysisConfig) -> List[Finding]:
    out = []
    for part, seg in (("header", t.header_b64), ("payload", t.payload_b64)):
        dups = sorted(set(_duplicate_keys(seg)))
        if dups:
            out.append(Finding(
                "DUPLICATE_KEYS", "Duplicate JSON keys", part, Severity.HIGH,
                "The JSON contains duplicate keys. JWT libraries resolve duplicates "
                "differently (first vs last wins), so an attacker can craft one token that "
                "one component validates while another trusts different values (parser "
                "differential / claim smuggling).",
                evidence=f"duplicated: {dups}",
            ))
    return out


RULES = [check_none_alg, check_alg_missing_or_unknown, check_signature_present,
         check_key_injection_headers, check_crit_header, check_duplicate_keys]
