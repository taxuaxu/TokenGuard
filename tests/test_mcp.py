"""MCP case study tested end-to-end against the lab server (in-process)."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp_server.server import create_app  # noqa: E402
from tokenguard.mcp_probe import run_mcp_probe, vulnerabilities  # noqa: E402

BASE = "http://127.0.0.1:7000"


class FlaskProbeClient:
    """Adapts the probe's absolute-URL interface to an in-process Flask app."""

    def __init__(self, app, base=BASE):
        self.c = app.test_client()
        self.base = base.rstrip("/")

    def _path(self, url):
        assert url.startswith(self.base), f"off-base URL in probe: {url}"
        return url[len(self.base):] or "/"

    def get(self, url, token=None):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        r = self.c.get(self._path(url), headers=headers)
        return r.status_code, dict(r.headers), (r.get_json(silent=True) or {})

    def post(self, url, json=None, token=None):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        r = self.c.post(self._path(url), json=json, headers=headers)
        return r.status_code, dict(r.headers), (r.get_json(silent=True) or {})


def _probe(enforce):
    app = create_app(enforce_audience=enforce, issuer_base=BASE)
    return run_mcp_probe(BASE, client=FlaskProbeClient(app))


def _by_check(results):
    return {r.check: r for r in results}


# ---------------- secure configuration ----------------

def test_secure_server_passes_every_check():
    results = _probe(enforce=True)
    assert vulnerabilities(results) == []
    for r in results:
        assert r.passed, f"{r.check}: {r.detail}"


def test_secure_challenges_unauthenticated():
    r = _by_check(_probe(enforce=True))["UNAUTH_CHALLENGE"]
    assert r.passed and "resource_metadata" in r.detail


def test_secure_rejects_foreign_audience():
    r = _by_check(_probe(enforce=True))["AUDIENCE_BINDING"]
    assert r.passed and r.vulnerability is None


def test_secure_accepts_valid_token():
    r = _by_check(_probe(enforce=True))["VALID_TOKEN_ACCEPTED"]
    assert r.passed and "tokenguard-lab-mcp" in r.detail


# ---------------- misconfigured configuration ----------------

def test_misconfigured_server_flags_audience():
    results = _probe(enforce=False)
    assert "AUDIENCE_NOT_ENFORCED" in vulnerabilities(results)
    r = _by_check(results)["AUDIENCE_BINDING"]
    assert not r.passed and r.vulnerability == "AUDIENCE_NOT_ENFORCED"


def test_misconfigured_still_challenges_and_accepts_valid():
    """The flaw is only the audience check; other controls still hold."""
    results = _by_check(_probe(enforce=False))
    assert results["UNAUTH_CHALLENGE"].passed
    assert results["VALID_TOKEN_ACCEPTED"].passed
    assert results["EXPIRED_REJECTED"].passed


# ---------------- token pass-through (RFC 9728 / confused deputy) ----------------

def test_secure_does_not_pass_token_through():
    r = _by_check(_probe(enforce=True))["TOKEN_PASSTHROUGH"]
    assert r.passed and r.vulnerability is None


def test_passthrough_server_is_flagged():
    app = create_app(enforce_audience=True, issuer_base=BASE, forward_client_token=True)
    results = run_mcp_probe(BASE, client=FlaskProbeClient(app))
    r = _by_check(results)["TOKEN_PASSTHROUGH"]
    assert not r.passed and r.vulnerability == "TOKEN_PASSED_THROUGH"
    assert "TOKEN_PASSED_THROUGH" in vulnerabilities(results)


def test_expired_rejected_always_present():
    checks = {r.check for r in _probe(enforce=True)}
    assert "EXPIRED_REJECTED" in checks and "TOKEN_PASSTHROUGH" in checks
