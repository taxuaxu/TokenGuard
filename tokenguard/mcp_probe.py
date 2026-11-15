"""MCP case study: probe a locally hosted, OAuth 2.1-protected MCP server.

Following the MCP authorization spec (OAuth 2.1 + RFC 9728), the probe checks the
rules the proposal highlights:

  1. An unauthenticated request is correctly challenged (401 + WWW-Authenticate
     pointing at the protected-resource metadata).
  2. The protected-resource metadata advertises an authorization server (discovery).
  3. A token whose audience is bound to ANOTHER resource is rejected (audience
     binding / no confused-deputy).
  4. A token correctly bound to this resource is accepted.
  5. An expired token is rejected.
  6. The server does not pass the client's token through to upstream services
     (a downstream call must use a token minted for the upstream, not the
     client's token bound to this resource).

Only localhost targets are allowed.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import List, Optional, Tuple
from urllib.parse import urlparse

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
OTHER_RESOURCE = "http://127.0.0.1:9999/other-service"


@dataclass
class MCPProbeResult:
    check: str
    passed: bool
    detail: str = ""
    vulnerability: Optional[str] = None   # set when a security control is missing

    def to_dict(self) -> dict:
        return asdict(self)


# ------------------------------------------------------------------ clients

class RequestsClient:
    """Real HTTP client restricted to localhost."""

    def __init__(self, timeout: float = 5.0, allow_remote: bool = False):
        import requests
        self._requests = requests
        self.timeout = timeout
        self.allow_remote = allow_remote

    def _check(self, url: str):
        if not self.allow_remote and urlparse(url).hostname not in LOCAL_HOSTS:
            raise ValueError(f"Refusing non-local URL {url!r}: MCP probe is for local labs only.")

    def get(self, url: str, token: Optional[str] = None) -> Tuple[int, dict, dict]:
        self._check(url)
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        r = self._requests.get(url, headers=headers, timeout=self.timeout)
        return r.status_code, dict(r.headers), _json(r)

    def post(self, url: str, json=None, token: Optional[str] = None) -> Tuple[int, dict, dict]:
        self._check(url)
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        r = self._requests.post(url, json=json, headers=headers, timeout=self.timeout)
        return r.status_code, dict(r.headers), _json(r)


def _json(resp):
    try:
        return resp.json()
    except ValueError:
        return {}


# ------------------------------------------------------------------ probe

_RESOURCE_META_RE = re.compile(r'resource_metadata="([^"]+)"')


def _accepted(status: int, body: dict) -> bool:
    return 200 <= status < 300 and "result" in body


def run_mcp_probe(target: str = "http://127.0.0.1:7000", client=None) -> List[MCPProbeResult]:
    client = client or RequestsClient()
    base = target.rstrip("/")
    mcp_url = f"{base}/mcp"
    results: List[MCPProbeResult] = []

    # 1. Unauthenticated request must be challenged.
    status, headers, _ = client.post(mcp_url, json={"jsonrpc": "2.0", "id": 1,
                                                    "method": "initialize"})
    www = headers.get("WWW-Authenticate", "") or headers.get("www-authenticate", "")
    challenged = status == 401 and www.lower().startswith("bearer")
    m = _RESOURCE_META_RE.search(www)
    results.append(MCPProbeResult(
        "UNAUTH_CHALLENGE", challenged,
        f"status={status}, WWW-Authenticate={www!r}",
        vulnerability=None if challenged else "NO_AUTH_CHALLENGE",
    ))

    # 2. Protected-resource metadata advertises an authorization server.
    prm_url = m.group(1) if m else f"{base}/.well-known/oauth-protected-resource"
    status, _, prm = client.get(prm_url)
    auth_servers = prm.get("authorization_servers") or []
    results.append(MCPProbeResult(
        "RESOURCE_METADATA", bool(auth_servers) and status == 200,
        f"status={status}, authorization_servers={auth_servers}",
    ))

    # Discover the token endpoint from the authorization-server metadata
    # (RFC 8414). Fall back to a conventional path only if discovery fails.
    token_endpoint = None
    discovered = False
    if auth_servers:
        as_url = auth_servers[0].rstrip("/")
        status, _, asm = client.get(f"{as_url}/.well-known/oauth-authorization-server")
        token_endpoint = asm.get("token_endpoint")
        discovered = bool(token_endpoint)
    results.append(MCPProbeResult(
        "AS_DISCOVERY", discovered,
        f"token_endpoint={'discovered: ' + token_endpoint if discovered else 'not discovered (using fallback)'}",
    ))
    if not token_endpoint:
        token_endpoint = f"{base}/as/token"

    def mint(resource: str, scenario: str = "valid") -> Optional[str]:
        st, _, body = client.post(token_endpoint,
                                  json={"resource": resource, "scenario": scenario})
        return body.get("access_token") if 200 <= st < 300 else None

    resource_uri = prm.get("resource", mcp_url)

    def call_initialize(token):
        return client.post(mcp_url, token=token,
                           json={"jsonrpc": "2.0", "id": 2, "method": "initialize"})

    # 3. A token bound to ANOTHER resource must be rejected.
    foreign = mint(OTHER_RESOURCE)
    if foreign:
        status, _, body = call_initialize(foreign)
        accepted = _accepted(status, body)
        results.append(MCPProbeResult(
            "AUDIENCE_BINDING", not accepted,
            f"token aud={OTHER_RESOURCE!r} -> status={status}, "
            f"{'ACCEPTED (wrong)' if accepted else 'rejected'}",
            vulnerability="AUDIENCE_NOT_ENFORCED" if accepted else None,
        ))
    else:
        results.append(MCPProbeResult("AUDIENCE_BINDING", False,
                                      "could not mint foreign-audience token"))

    # 4. A token correctly bound to this resource must be accepted.
    good = mint(resource_uri)
    if good:
        status, _, body = call_initialize(good)
        accepted = _accepted(status, body)
        server_name = body.get("result", {}).get("serverInfo", {}).get("name", "?")
        results.append(MCPProbeResult(
            "VALID_TOKEN_ACCEPTED", accepted,
            f"status={status}, serverInfo.name={server_name!r}",
        ))
    else:
        results.append(MCPProbeResult("VALID_TOKEN_ACCEPTED", False,
                                      "could not mint resource-bound token"))

    # 5. An expired token must be rejected.
    expired = mint(resource_uri, scenario="expired")
    if expired:
        status, _, body = call_initialize(expired)
        accepted = _accepted(status, body)
        results.append(MCPProbeResult(
            "EXPIRED_REJECTED", not accepted,
            f"expired token -> status={status}, "
            f"{'ACCEPTED (wrong)' if accepted else 'rejected'}",
            vulnerability="EXPIRY_NOT_ENFORCED" if accepted else None,
        ))
    else:
        results.append(MCPProbeResult("EXPIRED_REJECTED", False,
                                      "could not mint expired token"))

    # 6. The server must not pass the client's token through to upstream services
    #    (RFC 9728 / confused-deputy): a downstream call must use a token minted
    #    for the upstream, not the client's token bound to this resource.
    status, _, body = call_initialize_method(client, mcp_url, good, "upstream/call") \
        if good else (None, None, {})
    res = body.get("result") if isinstance(body, dict) else None
    if res and "forwarded_aud" in res:
        passed_through = res.get("forwarded_aud") == resource_uri
        results.append(MCPProbeResult(
            "TOKEN_PASSTHROUGH", not passed_through,
            f"upstream received aud={res.get('forwarded_aud')!r} "
            f"(upstream resource={res.get('upstream_resource')!r})",
            vulnerability="TOKEN_PASSED_THROUGH" if passed_through else None,
        ))
    else:
        results.append(MCPProbeResult("TOKEN_PASSTHROUGH", True,
                                      "server does not expose an upstream call (n/a)"))

    return results


def call_initialize_method(client, mcp_url, token, method):
    return client.post(mcp_url, token=token,
                       json={"jsonrpc": "2.0", "id": 3, "method": method})


def vulnerabilities(results: List[MCPProbeResult]) -> List[str]:
    return [r.vulnerability for r in results if r.vulnerability]


def format_results(results: List[MCPProbeResult]) -> str:
    lines = [f"{'CHECK':<22}{'RESULT':<10}DETAIL"]
    for r in results:
        verdict = "PASS" if r.passed else ("VULN" if r.vulnerability else "FAIL")
        lines.append(f"{r.check:<22}{verdict:<10}{r.detail}")
    vulns = vulnerabilities(results)
    lines.append("")
    lines.append(f"Vulnerabilities: {', '.join(vulns) if vulns else 'none detected'}")
    return "\n".join(lines)
