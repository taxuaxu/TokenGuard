"""Active mode tested end-to-end against the vulnerable Flask app (in-process)."""
import importlib.util
from pathlib import Path

import pytest

from tokenguard.active.runner import run_active_tests, summarize

APP_PATH = Path(__file__).resolve().parent.parent / "vuln_server" / "app.py"


@pytest.fixture(scope="module")
def vuln():
    spec = importlib.util.spec_from_file_location("vuln_app", APP_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FlaskClient:
    def __init__(self, app):
        self.c = app.test_client()

    def get(self, path, token=None, params=None):
        headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
        r = self.c.get(path, headers=headers, query_string=params)
        return r.status_code, (r.get_json(silent=True) or {})


def test_active_mode_finds_every_intended_flaw(vuln):
    summary = summarize(run_active_tests(client=FlaskClient(vuln.app)))
    for name, flaw in vuln.ENDPOINTS.items():
        expected = [] if flaw is None else [flaw]
        assert summary[f"/api/{name}"] == expected, name


def test_baseline_accepted_and_no_token_rejected(vuln):
    results = run_active_tests(client=FlaskClient(vuln.app))
    baseline = [r for r in results if r.attack == "BASELINE_VALID"]
    no_token = [r for r in results if r.attack == "NO_TOKEN"]
    assert baseline and all(r.accepted for r in baseline)
    assert no_token and all(r.status == 401 and not r.accepted for r in no_token)


def test_secure_endpoint_rejects_all_attacks(vuln):
    results = run_active_tests(client=FlaskClient(vuln.app))
    for r in results:
        if r.endpoint == "/api/secure" and not r.expected_accept and r.status is not None:
            assert not r.accepted, r.attack


def test_remote_host_is_refused():
    from tokenguard.active.runner import HttpClient
    with pytest.raises(ValueError):
        HttpClient("http://example.com")
