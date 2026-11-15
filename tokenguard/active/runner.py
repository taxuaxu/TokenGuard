"""Active testing: send crafted tokens to a LOCAL lab server and record which
ones are accepted. Every attack token should be rejected by a secure server."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ..config import AnalysisConfig
from . import attacks

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}

# attack id -> server flaw it demonstrates
ATTACK_TO_FLAW = {
    "ALG_NONE": "ALG_NONE",
    "TAMPERED_SIGNATURE": "NO_SIGNATURE_CHECK",
    "EXPIRED_TOKEN": "NO_EXP_CHECK",
    "WRONG_AUDIENCE": "NO_AUD_CHECK",
    "WEAK_KEY_FORGERY": "WEAK_KEY",
}


@dataclass
class ActiveResult:
    endpoint: str
    attack: str
    status: Optional[int]
    accepted: bool
    expected_accept: bool
    note: str = ""

    @property
    def vulnerable(self) -> bool:
        return self.accepted and not self.expected_accept

    @property
    def flaw(self) -> Optional[str]:
        return ATTACK_TO_FLAW.get(self.attack) if self.vulnerable else None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["vulnerable"] = self.vulnerable
        return d


class HttpClient:
    """Minimal client: get(path, token=None, params=None) -> (status, json)."""

    def __init__(self, base_url: str, timeout: float = 5.0, allow_remote: bool = False):
        host = urlparse(base_url).hostname
        if not allow_remote and host not in LOCAL_HOSTS:
            raise ValueError(f"Refusing to test non-local host {host!r}: active mode is for "
                             "locally hosted lab servers only.")
        import requests
        self._requests = requests
        self.base = base_url.rstrip("/")
        self.timeout = timeout

    def get(self, path: str, token: Optional[str] = None, params=None) -> Tuple[int, dict]:
        headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
        r = self._requests.get(self.base + path, headers=headers, params=params,
                               timeout=self.timeout)
        try:
            body = r.json()
        except ValueError:
            body = {}
        return r.status_code, body


def _send(client, endpoint: str, attack: str, token: Optional[str], expected_accept: bool,
          note: str = "") -> ActiveResult:
    status, _ = client.get(endpoint, token=token)
    return ActiveResult(endpoint, attack, status, 200 <= status < 300, expected_accept, note)


def test_endpoint(client, endpoint: str, config: Optional[AnalysisConfig] = None,
                  secret: Optional[str] = None) -> List[ActiveResult]:
    name = endpoint.rsplit("/", 1)[-1]

    def issue(scenario):
        return client.get("/login", params={"endpoint": name, "scenario": scenario})[1].get("token")

    baseline = issue("valid")
    results: List[ActiveResult] = []

    results.append(_send(client, endpoint, "NO_TOKEN", None, False))

    if not baseline:
        results.append(ActiveResult(
            endpoint, "BASELINE_VALID", None, False, True,
            "could not obtain a baseline token from the server; attacks skipped"))
        return results

    base = _send(client, endpoint, "BASELINE_VALID", baseline, True)
    if not base.accepted:
        base.note = "valid token rejected; remaining results inconclusive"
    results.append(base)

    results.append(_send(client, endpoint, "ALG_NONE", attacks.none_alg_token(baseline), False))
    results.append(_send(client, endpoint, "TAMPERED_SIGNATURE",
                         attacks.tampered_signature_token(baseline), False))
    results.append(_send(client, endpoint, "EXPIRED_TOKEN", issue("expired"), False))
    results.append(_send(client, endpoint, "WRONG_AUDIENCE", issue("other-aud"), False))

    recovered = secret or attacks.recover_secret(baseline, config)
    if recovered:
        forged = attacks.weak_key_forgery_token(baseline, recovered)
        results.append(_send(client, endpoint, "WEAK_KEY_FORGERY", forged, False,
                             note="secret supplied" if secret else "secret recovered from wordlist"))
    else:
        results.append(ActiveResult(endpoint, "WEAK_KEY_FORGERY", None, False, False,
                                    note="skipped: secret not in wordlist"))
    return results


def discover_endpoints(client) -> List[str]:
    _, body = client.get("/endpoints")
    return list(body.get("endpoints", []))


def run_active_tests(target: str = "http://127.0.0.1:5000", secret: Optional[str] = None,
                     client=None, config: Optional[AnalysisConfig] = None) -> List[ActiveResult]:
    client = client or HttpClient(target)
    out: List[ActiveResult] = []
    for ep in discover_endpoints(client):
        out.extend(test_endpoint(client, ep, config=config, secret=secret))
    return out


def summarize(results: List[ActiveResult]) -> Dict[str, List[str]]:
    """endpoint -> list of detected flaws"""
    summary: Dict[str, List[str]] = {}
    for r in results:
        summary.setdefault(r.endpoint, [])
        if r.flaw:
            summary[r.endpoint].append(r.flaw)
    return summary


def format_results(results: List[ActiveResult]) -> str:
    lines = [f"{'ENDPOINT':<26}{'ATTACK':<22}{'STATUS':<8}{'RESULT':<12}NOTE"]
    for r in results:
        if r.status is None:
            verdict = "SKIPPED"
        elif r.expected_accept:
            verdict = "ok" if r.accepted else "REJECTED?"
        else:
            verdict = "VULNERABLE" if r.accepted else "rejected"
        lines.append(f"{r.endpoint:<26}{r.attack:<22}{str(r.status or '-'):<8}{verdict:<12}{r.note}")
    lines.append("")
    for ep, flaws in summarize(results).items():
        lines.append(f"{ep:<26}=> {', '.join(flaws) if flaws else 'no flaws detected'}")
    return "\n".join(lines)
