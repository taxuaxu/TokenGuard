"""A hand-labeled adversarial test set — the honest counterpart to the generated dataset.

Unlike dataset/generate.py, these tokens are NOT derived from TokenGuard's own rule
definitions. They are written by hand and labeled by human judgment of what a security
reviewer would actually consider a vulnerability. The set is built mostly around *hard
negatives* — tokens that look suspicious but are legitimate (clock-skew nbf values,
genuine long-lived refresh tokens, key ids that merely contain '--', claim names that
resemble sensitive keys, valid asymmetric tokens) — plus tricky positives, including a
few that the tool is expected to MISS (sensitive values stored under field names its
keyword list does not know). It therefore probes both false positives and false
negatives, so a tool is expected to score below a perfect 1.0 here, which is a more
meaningful result than the generated set.

Each record: {"token", "labels", "note", "now"[, "expected_algs"]}.
`labels` is the human ground truth (empty = should NOT be flagged).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import warnings

import jwt

warnings.filterwarnings("ignore")

ISS = "https://auth.lab.local"
AUD = "tokenguard-api"
STRONG = "k9$Vq2!xLr8#Tz4@pW7&nB1^mE6*hY3%ZaCdEf"
DAY = 86400
NOW = int(time.time())


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()


def _b64s(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).rstrip(b"=").decode()


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


def _raw(header, payload_obj, sig="ZHVtbXk") -> str:
    return f"{_b64(header)}.{_b64(payload_obj)}.{sig}"


def _manual_hs(header, payload, secret=STRONG) -> str:
    """HS256 token with full control of the raw payload (e.g. a malformed exp)."""
    si = f"{_b64(header)}.{_b64(payload)}".encode()
    sig = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), si, hashlib.sha256).digest()).rstrip(b"=").decode()
    return f"{si.decode()}.{sig}"


_RECS = []


def _add(token, labels, note, expected_algs=None):
    rec = {"token": token, "labels": labels, "note": note, "now": NOW}
    if expected_algs is not None:
        rec["expected_algs"] = expected_algs
    _RECS.append(rec)


def _build():
    _RECS.clear()
    HS = {"alg": "HS256", "typ": "JWT"}
    NONE = {"alg": "none", "typ": "JWT"}

    # =================================================================
    # HARD NEGATIVES — legitimate but suspicious (ground truth: [])
    # =================================================================

    # --- clock-skew nbf: a near-future nbf is normal with skew tolerance (tool over-flags) ---
    for skew, note in [(5, "+5s"), (30, "+30s"), (90, "+90s"), (120, "+2m")]:
        _add(_signed(claims(nbf=NOW + skew)), [], f"clock-skew nbf ({note}) — legitimate")

    # --- genuinely long-lived tokens that are legitimate (tool over-flags LONG_LIFETIME) ---
    _add(_signed(claims(exp=NOW + 7 * DAY, scope="remember_me")), [],
         "legitimate 7-day 'remember me' session")
    _add(_signed(claims(exp=NOW + 30 * DAY, scope="offline_access", typ="refresh")), [],
         "legitimate 30-day refresh token")
    _add(_signed(claims(exp=NOW + 90 * DAY, typ="refresh")), [],
         "legitimate 90-day refresh token")

    # --- key ids that merely contain '--' or other separators (tool over-flags kid) ---
    for kid in ("Ab3--Xy9_v12", "prod--eu--2026", "tenant--acme"):
        _add(_signed(claims(), headers={"kid": kid}), [],
             f"legitimate base64url kid containing '--' ({kid})")

    # --- claim names that resemble sensitive keys but are harmless (correctly NOT flagged) ---
    for extra in (
        {"password_updated_at": NOW - DAY},
        {"has_password": True},
        {"pwd_policy": "strong"},
        {"secret_rotation_days": 30},
        {"api_version": "v2"},
        {"apikey_set": True},
        {"discard_reason": "none"},
        {"card_last4": "1234"},
        {"ssn_verified": True},
        {"privatekey_fingerprint": "ab:cd:ef"},
    ):
        key = list(extra)[0]
        _add(_signed(claims(**extra)), [], f"benign claim name '{key}' (resembles a sensitive key)")

    # --- valid asymmetric tokens (structurally sound, correctly NOT flagged) ---
    for alg, nb in (("RS256", 256), ("RS384", 256), ("PS256", 256), ("ES256", 64),
                    ("ES384", 96), ("EdDSA", 64)):
        _add(_unverified(alg, claims(), sig_bytes=nb), [], f"valid {alg} token")

    # --- lifetime boundaries and short-lived tokens (correctly NOT flagged) ---
    _add(_signed(claims(exp=NOW + DAY)), [], "lifetime exactly 24h (boundary)")
    _add(_signed(claims(exp=NOW + DAY - 60)), [], "lifetime just under 24h")
    _add(_signed(claims(exp=NOW + 60)), [], "short-lived 60s access token")

    # --- audiences, issuers, kids that look odd but are fine ---
    _add(_signed(claims(aud=[AUD, "reports-api"])), [], "multi-audience list, both valid")
    _add(_signed(claims(), headers={"kid": "signing-key.v3"}), [],
         "versioned kid with a dot (no traversal)")
    _add(_signed(claims(), headers={"kid": "tenant/acme/key1"}), [],
         "path-style kid with '/' but no '../'")
    _add(_signed(claims(jti="a1", azp="web", scope="read write", amr=["pwd"])), [],
         "many standard claims, all valid")
    # --- well-formed crit with a custom extension that is present (correctly NOT flagged) ---
    _add(_signed(claims(), headers={"crit": ["x-ext"], "x-ext": True}), [],
         "well-formed crit, extension present")
    # --- strong HMAC secret, not in any wordlist ---
    _add(_signed(claims(), secret=STRONG), [], "strong HMAC secret (not guessable)")

    # =================================================================
    # HARD POSITIVES the tool DOES catch (ground truth: a real issue)
    # =================================================================
    _add(_raw(NONE, claims()), ["ALG_NONE"], "unsigned token (alg=none)")
    _add(_raw({"alg": "None", "typ": "JWT"}, claims()), ["ALG_NONE"],
         "alg=None, mixed case (bypass attempt)")
    _add(_signed(claims(iat=NOW - 1200, nbf=NOW - 1200, exp=NOW - 10)), [],
         "expired 10s ago — within clock-skew tolerance, legitimately still accepted")
    _add(_signed(claims(iat=NOW - 2 * DAY - 900, nbf=NOW - 2 * DAY - 900, exp=NOW - 2 * DAY)),
         ["EXPIRED"], "expired 2 days ago (15m original lifetime)")
    _add(_signed(claims(context={"session": {"ssn": "123-45-6789"}})), ["SENSITIVE_DATA"],
         "ssn nested two levels deep (known key)")
    _add(_signed(claims(password="hunter2")), ["SENSITIVE_DATA"], "password in payload")
    _add(_signed(claims(api_key="AK-9c1f2e")), ["SENSITIVE_DATA"], "api_key in payload")
    _add(_signed(claims(credit_card="4111111111111111")), ["SENSITIVE_DATA"],
         "credit_card in payload")
    for secret in ("changeme", "password", "admin", "letmein", "qwerty"):
        _add(_signed(claims(), secret=secret), ["WEAK_KEY"], f"weak HMAC key '{secret}'")
    _add(_signed(claims()), ["ALG_UNEXPECTED"],
         "algorithm confusion: app pins RS256, token is HS256", expected_algs=["RS256"])
    _add(_unverified("RS256", claims()), ["ALG_UNEXPECTED"],
         "app pins ES256 but receives RS256", expected_algs=["ES256"])
    _add(_signed(claims(), headers={"crit": ["alg"]}), ["CRIT_HEADER"],
         "crit names a registered header (alg)")
    _add(_signed(claims(), headers={"x5c": ["MIIBcert=="]}), ["HEADER_X5C"],
         "embedded x5c certificate chain")
    _add(_signed(claims(), headers={"jku": "https://evil.example/k.json"}), ["HEADER_KEY_URL"],
         "jku key URL to attacker host")
    _add(_signed(claims(), headers={"kid": "key1' OR '1'='1"}), ["HEADER_KID_INJECTION"],
         "kid SQL injection")
    _add(_raw(HS, claims(), sig=""), ["SIGNATURE_EMPTY"], "HS256 header, signature stripped")
    dup = ('{"iss":"' + ISS + '","aud":"' + AUD + '","sub":"a","sub":"b",'
           + f'"iat":{NOW},"nbf":{NOW},"exp":{NOW + 900}' + '}')
    _add(_b64(HS) + "." + _b64s(dup) + ".ZHVtbXk",
         ["DUPLICATE_KEYS"], "duplicate 'sub' key in payload")

    # =================================================================
    # HARD POSITIVES the tool MISSES — honest recall gaps (ground truth: an issue)
    # The keyword list for sensitive data is finite, so genuinely sensitive values
    # stored under unusual field names are not detected.
    # =================================================================
    _add(_signed(claims(social_security_number="123-45-6789")), ["SENSITIVE_DATA"],
         "SSN under 'social_security_number' (not in the keyword list)")
    _add(_signed(claims(cvv="123")), ["SENSITIVE_DATA"],
         "card CVV under 'cvv' (not in the keyword list)")
    _add(_signed(claims(iban="TR12 0006 1005 1978 6457 8413 26")), ["SENSITIVE_DATA"],
         "bank IBAN under 'iban' (not in the keyword list)")

    # =================================================================
    # ADDITIONAL CASES (expanded to 100)
    # =================================================================

    # --- more over-flagged legitimate tokens (false positives) ---
    _add(_signed(claims(nbf=NOW + 180)), ["NOT_YET_VALID"],
         "nbf +3m — beyond skew tolerance, genuinely not-yet-valid")
    _add(_signed(claims(exp=NOW + 14 * DAY, scope="remember_me")), [],
         "legitimate 14-day 'remember me' session")
    _add(_signed(claims(exp=NOW + 180 * DAY, typ="refresh")), [],
         "legitimate 180-day refresh token")
    _add(_signed(claims(), headers={"kid": "a1--b2--c3"}), [],
         "legitimate base64url kid containing '--' (a1--b2--c3)")

    # --- more benign claim-name lookalikes (correctly NOT flagged) ---
    for extra, key in [
        ({"credit_card_on_file": True}, "credit_card_on_file"),
        ({"ssn_last4": "6789"}, "ssn_last4"),
        ({"pin_set": True}, "pin_set"),
        ({"secret_question_set": True}, "secret_question_set"),
    ]:
        _add(_signed(claims(**extra)), [], f"benign claim name '{key}'")

    # --- more legitimate structural tokens (correctly NOT flagged) ---
    _add(_signed(claims(), headers={"x5t": "aB3dEf"}), [],
         "x5t certificate thumbprint header (reference, not embedded)")
    _add(_signed(claims(), headers={"typ": "at+jwt"}), [], "typ 'at+jwt' (RFC 9068 access token)")
    _add(_unverified("ES512", claims(), sig_bytes=132), [], "valid ES512 token")
    _add(_signed(claims(sub="550e8400-e29b-41d4-a716-446655440000")), [], "UUID subject")
    _add(_signed(claims(roles=["user", "editor"], groups=["g1", "g2"])), [],
         "role / group arrays, valid")
    _add(_signed(claims(ui={"theme": {"mode": "dark"}})), [], "deeply nested, non-sensitive data")

    # --- more positives the tool DOES catch ---
    _add(_raw({"alg": "HS1", "typ": "JWT"}, claims()), ["ALG_UNKNOWN"], "unknown algorithm 'HS1'")
    _add(_raw({"alg": 123, "typ": "JWT"}, claims()), ["ALG_UNKNOWN"], "malformed (non-string) alg")
    _add(_raw({"typ": "JWT"}, claims()), ["ALG_MISSING"], "missing 'alg' header")
    _add(_signed(claims(), headers={"jwk": {"kty": "oct", "k": "YXR0"}}), ["HEADER_JWK"],
         "embedded jwk (oct)")
    _add(_signed(claims(), headers={"x5u": "https://evil.example/c.pem"}), ["HEADER_KEY_URL"],
         "x5u remote certificate URL")
    _add(_signed(claims(), headers={"kid": "../../../../etc/passwd"}), ["HEADER_KID_INJECTION"],
         "kid unix path traversal")
    _add(_signed(claims(), headers={"kid": "a|whoami"}), ["HEADER_KID_INJECTION"],
         "kid command-injection pipe")
    _add(_signed(claims(passwd="hunter2")), ["SENSITIVE_DATA"], "passwd in payload")
    _add(_signed(claims(client_secret="cs-abc")), ["SENSITIVE_DATA"], "client_secret in payload")
    _add(_signed(claims(private_key="-----BEGIN PRIVATE KEY-----")), ["SENSITIVE_DATA"],
         "private_key in payload")
    _add(_signed(claims(card_number="4111111111111111")), ["SENSITIVE_DATA"],
         "card_number in payload")
    _add(_signed(claims(data={"a": {"b": {"password": "x"}}})), ["SENSITIVE_DATA"],
         "password nested three levels deep")
    _add(_manual_hs(HS, claims(exp="soon")), ["INVALID_EXP"], "exp is a text string")
    _add(_manual_hs(HS, claims(exp=True)), ["INVALID_EXP"], "exp is a boolean")
    # Context matters: a long-lived *access* token (no refresh semantics) is a real issue.
    _add(_signed(claims(exp=NOW + 365 * DAY)), ["LONG_LIFETIME"], "access token valid for 1 year")
    # A far-future nbf is not clock skew but a genuinely not-yet-valid token.
    _add(_signed(claims(nbf=NOW + 365 * DAY)), ["NOT_YET_VALID"], "nbf one year in the future")
    for secret in ("welcome", "dragon", "monkey"):
        _add(_signed(claims(), secret=secret), ["WEAK_KEY"], f"weak HMAC key '{secret}'")
    _add(_b64s('{"typ":"JWT","typ":"JWT","alg":"HS256"}') + "." + _b64(claims()) + ".ZHVtbXk",
         ["DUPLICATE_KEYS"], "duplicate 'typ' key in header")

    # --- more real issues the tool MISSES (honest recall gaps) ---
    _add(_signed(claims(passport_number="X1234567")), ["SENSITIVE_DATA"],
         "passport number under 'passport_number' (not in the keyword list)")
    _add(_signed(claims(tax_id="12-3456789")), ["SENSITIVE_DATA"],
         "tax id under 'tax_id' (not in the keyword list)")
    _add(_signed(claims(date_of_birth="1990-05-01")), ["SENSITIVE_DATA"],
         "date of birth under 'date_of_birth' (not in the keyword list)")
    _add(_signed(claims(security_answer="Fluffy")), ["SENSITIVE_DATA"],
         "security answer under 'security_answer' (not in the keyword list)")

    # --- residual hard cases: limits that remain even after the improvements ---
    # Value-pattern detection can over-match a coincidentally Luhn-valid number.
    _add(_signed(claims(order_id="4532015112830366")), [],
         "16-digit Luhn-valid order id (not a card) — value heuristic over-matches")
    # Sensitive data under a generic key with a free-text value is still missed.
    _add(_signed(claims(answer="Fluffy")), ["SENSITIVE_DATA"],
         "security answer under generic 'answer' key, non-pattern value (missed)")
    _add(_signed(claims(note="temp password is hunter2")), ["SENSITIVE_DATA"],
         "secret inside a free-text 'note' claim (missed)")

    return list(_RECS)


def records():
    return _build()


def main():
    recs = records()
    pos = sum(1 for r in recs if r["labels"])
    print(f"{len(recs)} hand-labeled hard cases ({pos} insecure, {len(recs) - pos} "
          f"legitimate-but-suspicious)")


if __name__ == "__main__":
    main()
