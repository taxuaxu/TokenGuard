from __future__ import annotations

import datetime as _dt
import re
from typing import List

from ..config import AnalysisConfig
from ..models import Finding, Severity, mask
from ..parser import ParsedToken


def _fmt_ts(ts) -> str:
    try:
        return _dt.datetime.fromtimestamp(
            float(ts), _dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (TypeError, ValueError, OverflowError, OSError):
        return repr(ts)


def _is_number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _human(seconds: float) -> str:
    seconds = int(seconds)
    if seconds >= 86400:
        return f"{seconds / 86400:.1f} days"
    if seconds >= 3600:
        return f"{seconds / 3600:.1f} hours"
    return f"{seconds} seconds"


# A token that is long-lived *by design* (a refresh / "remember me" token) should
# not be flagged for excessive lifetime; detect the usual hints in header or payload.
_LONG_LIVED_TYPS = {"refresh", "refresh_token", "offline"}
_LONG_LIVED_SCOPES = ("offline_access", "remember_me")


def _is_long_lived_by_design(t: ParsedToken) -> bool:
    for src in (t.header, t.payload):
        typ = str(src.get("typ", "")).lower()
        if typ in _LONG_LIVED_TYPS:
            return True
    for claim in ("scope", "scp", "token_use", "token_type"):
        val = t.payload.get(claim)
        if isinstance(val, list):
            val = " ".join(str(x) for x in val)
        val = str(val).lower()
        if any(s in val for s in _LONG_LIVED_SCOPES) or val in _LONG_LIVED_TYPS:
            return True
    return False


def check_exp(t: ParsedToken, cfg: AnalysisConfig) -> List[Finding]:
    p = t.payload
    if "exp" not in p:
        return [Finding(
            "MISSING_EXP", "No expiration time (exp)", "payload", Severity.HIGH,
            "The token never expires. If it is stolen it can be replayed indefinitely.",
        )]
    exp = p["exp"]
    if not _is_number(exp):
        return [Finding("INVALID_EXP", "Malformed 'exp' claim", "payload", Severity.MEDIUM,
                        "'exp' must be a NumericDate (seconds since epoch).", evidence=repr(exp))]
    out = []
    now = cfg.current_time()
    if exp < now - cfg.leeway_seconds:   # allow a small clock-skew window
        out.append(Finding(
            "EXPIRED", "Token has expired", "payload", Severity.MEDIUM,
            "The token is past its expiration time. It must be rejected; if a server still "
            "accepts it, expiration is not being enforced.",
            evidence=f"exp={_fmt_ts(exp)}",
        ))
    if _is_number(p.get("iat")):
        start = p["iat"]
    elif _is_number(p.get("nbf")):
        start = p["nbf"]
    else:
        start = now
    lifetime = exp - start
    if lifetime > cfg.max_lifetime_seconds and not _is_long_lived_by_design(t):
        out.append(Finding(
            "LONG_LIFETIME", "Excessively long token lifetime", "payload", Severity.MEDIUM,
            f"The token is valid for {_human(lifetime)}, longer than the configured maximum of "
            f"{_human(cfg.max_lifetime_seconds)}. Long-lived tokens widen the window for replay.",
            evidence=f"exp={_fmt_ts(exp)}",
        ))
    return out


def check_aud(t: ParsedToken, cfg: AnalysisConfig) -> List[Finding]:
    if t.payload.get("aud") in (None, "", []):
        return [Finding(
            "MISSING_AUD", "No audience (aud)", "payload", Severity.MEDIUM,
            "Without an audience the token is not bound to a specific service and may be "
            "accepted by other services that trust the same issuer (token reuse).",
        )]
    return []


def check_iss(t: ParsedToken, cfg: AnalysisConfig) -> List[Finding]:
    if t.payload.get("iss") in (None, ""):
        return [Finding(
            "MISSING_ISS", "No issuer (iss)", "payload", Severity.LOW,
            "Without an issuer the verifier cannot confirm who created the token.",
        )]
    return []


def check_nbf(t: ParsedToken, cfg: AnalysisConfig) -> List[Finding]:
    nbf = t.payload.get("nbf")
    if _is_number(nbf) and nbf > cfg.current_time() + cfg.leeway_seconds:
        return [Finding("NOT_YET_VALID", "Token not yet valid (nbf)", "payload", Severity.INFO,
                        "The 'nbf' time is more than the clock-skew allowance in the future.",
                        evidence=f"nbf={_fmt_ts(nbf)}")]
    return []


SENSITIVE_KEYS = {
    # credentials / keys
    "password", "passwd", "pwd", "secret", "client_secret", "api_key", "apikey",
    "private_key", "secret_key", "access_key", "refresh_token", "session_token",
    # national / financial identifiers
    "ssn", "social_security_number", "sin", "nino", "tax_id", "taxid", "ein",
    "credit_card", "card_number", "cardnumber", "cc_number", "cvv", "cvc", "pin",
    "iban", "bank_account", "account_number", "routing_number", "sort_code",
    # personal data
    "passport", "passport_number", "drivers_license", "license_number",
    "date_of_birth", "dob", "birthdate", "mothers_maiden_name",
    "security_answer", "security_question", "phone_number", "home_address",
}

# Value patterns catch sensitive data regardless of the field name.
_VALUE_PATTERNS = [
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){3,7}(?:[ ]?[A-Z0-9]{1,3})?\b")),
]
_CARD_CANDIDATE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _luhn_ok(s: str) -> bool:
    digits = [int(c) for c in s if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total, parity = 0, len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _value_sensitive(value: str):
    """Return a label (e.g. 'SSN', 'credit-card') if a string value looks sensitive."""
    for label, pat in _VALUE_PATTERNS:
        if pat.search(value):
            return label
    for cand in _CARD_CANDIDATE.findall(value):
        if _luhn_ok(cand):
            return "credit-card"
    return None


def _find_sensitive(obj, path=""):
    """Walk nested dicts/lists; yield (key_path, value, reason) for sensitive data,
    detected both by key name and by the value's own pattern."""
    hits = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            kp = f"{path}.{k}" if path else str(k)
            if isinstance(k, str) and k.lower() in SENSITIVE_KEYS:
                hits.append((kp, v, "name"))
            elif isinstance(v, str):
                label = _value_sensitive(v)
                if label:
                    hits.append((kp, v, label))
            hits.extend(_find_sensitive(v, kp))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            hits.extend(_find_sensitive(v, f"{path}[{i}]"))
    return hits


def check_sensitive_data(t: ParsedToken, cfg: AnalysisConfig) -> List[Finding]:
    hits = _find_sensitive(t.payload)
    if hits:
        shown = ", ".join(
            f"{kp}={mask(v)}" + ("" if reason == "name" else f" ({reason})")
            for kp, v, reason in hits)
        return [Finding(
            "SENSITIVE_DATA", "Sensitive data in payload", "payload", Severity.HIGH,
            "JWT payloads are only Base64URL-encoded, not encrypted. Anyone holding the token "
            "can read these values (nested fields and value patterns included).",
            evidence=shown,
        )]
    return []


RULES = [check_exp, check_aud, check_iss, check_nbf, check_sensitive_data]
