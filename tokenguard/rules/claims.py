from __future__ import annotations

import datetime as _dt
from typing import List

from ..config import AnalysisConfig
from ..models import Finding, Severity, mask
from ..parser import ParsedToken


def _fmt_ts(ts) -> str:
    try:
        return _dt.datetime.utcfromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S UTC")
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
    if exp < now:
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
    if lifetime > cfg.max_lifetime_seconds:
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
    if _is_number(nbf) and nbf > cfg.current_time():
        return [Finding("NOT_YET_VALID", "Token not yet valid (nbf)", "payload", Severity.INFO,
                        "The 'nbf' time is in the future.", evidence=f"nbf={_fmt_ts(nbf)}")]
    return []


SENSITIVE_KEYS = {"password", "passwd", "pwd", "secret", "client_secret", "api_key",
                  "apikey", "private_key", "ssn", "credit_card", "card_number"}


def check_sensitive_data(t: ParsedToken, cfg: AnalysisConfig) -> List[Finding]:
    hits = [k for k in t.payload if k.lower() in SENSITIVE_KEYS]
    if hits:
        shown = ", ".join(f"{k}={mask(t.payload[k])}" for k in hits)
        return [Finding(
            "SENSITIVE_DATA", "Sensitive data in payload", "payload", Severity.HIGH,
            "JWT payloads are only Base64URL-encoded, not encrypted. Anyone holding the token "
            "can read these values.",
            evidence=shown,
        )]
    return []


RULES = [check_exp, check_aud, check_iss, check_nbf, check_sensitive_data]
