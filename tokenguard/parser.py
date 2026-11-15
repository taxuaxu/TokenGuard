"""Manual JWT parsing. The signature is NOT verified here on purpose, so that
insecure tokens (e.g. alg=none) can still be inspected."""
from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass


class TokenParseError(ValueError):
    pass


def b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + padding)
    except (binascii.Error, ValueError) as exc:
        raise TokenParseError(f"invalid Base64URL segment: {exc}") from exc


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@dataclass
class ParsedToken:
    raw: str
    header: dict
    payload: dict
    signature: bytes
    header_b64: str
    payload_b64: str
    signature_b64: str

    @property
    def signing_input(self) -> bytes:
        return f"{self.header_b64}.{self.payload_b64}".encode("ascii")

    @property
    def alg(self):
        return self.header.get("alg")


def _decode_json(segment: str, name: str) -> dict:
    try:
        obj = json.loads(b64url_decode(segment))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TokenParseError(f"{name} is not valid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise TokenParseError(f"{name} must be a JSON object")
    return obj


def parse_token(token: str) -> ParsedToken:
    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenParseError(f"expected 3 dot-separated parts, got {len(parts)}")
    h, p, s = parts
    return ParsedToken(
        raw=token,
        header=_decode_json(h, "header"),
        payload=_decode_json(p, "payload"),
        signature=b64url_decode(s) if s else b"",
        header_b64=h,
        payload_b64=p,
        signature_b64=s,
    )
