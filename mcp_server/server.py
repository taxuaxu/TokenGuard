"""A local, OAuth 2.1-protected MCP (Model Context Protocol) server for the case study.

!!! FOR LOCAL LAB USE ONLY. The embedded authorization server issues tokens freely. !!!

It plays three roles that are conceptually separate in the MCP authorization spec:

  * Authorization Server (AS)  -> /as/token, /.well-known/oauth-authorization-server
  * Protected Resource (RS)    -> /.well-known/oauth-protected-resource  (RFC 9728)
  * MCP server (JSON-RPC)      -> /mcp  (initialize, tools/list), Bearer-protected

Two configurations:
  * secure        : validates that a token's audience is bound to THIS resource.
  * misconfigured : skips audience validation, so a token minted for another
                    resource is wrongly accepted (token pass-through / confused deputy).

Run:
    python mcp_server/server.py                 # secure,        127.0.0.1:7000
    python mcp_server/server.py --insecure      # misconfigured, 127.0.0.1:7001
"""
from __future__ import annotations

import time

import jwt
from flask import Flask, jsonify, request

STRONG_SECRET = "mcp$Lab!Shared9Secret#Between_AS_and_RS-2026-xyz"  # 48 chars (lab only)
TOKEN_TTL = 900


def create_app(enforce_audience: bool = True, issuer_base: str = "http://127.0.0.1:7000"):
    app = Flask(__name__)
    issuer_base = issuer_base.rstrip("/")
    # The AS issuer identifier is the base URL (no path), so its metadata lives at
    # {issuer_base}/.well-known/oauth-authorization-server per RFC 8414 and OAuth
    # discovery resolves it correctly. The token endpoint itself is still under /as.
    as_issuer = issuer_base
    token_endpoint = f"{issuer_base}/as/token"
    resource_uri = f"{issuer_base}/mcp"          # this server's canonical resource id
    prm_url = f"{issuer_base}/.well-known/oauth-protected-resource"

    app.config.update(enforce_audience=enforce_audience, issuer_base=issuer_base,
                      as_issuer=as_issuer, resource_uri=resource_uri)

    # ---------------- Authorization Server (lab issuer) ----------------

    @app.get("/.well-known/oauth-authorization-server")
    def as_metadata():
        return jsonify({
            "issuer": as_issuer,
            "token_endpoint": token_endpoint,
            "token_endpoint_auth_methods_supported": ["none"],
            "grant_types_supported": ["client_credentials"],
            "response_types_supported": ["token"],
        })

    @app.post("/as/token")
    def issue_token():
        """Lab issuer. Mints a token whose 'aud' is the requested resource.
        params: resource (audience), sub, scenario=valid|expired"""
        data = request.get_json(silent=True) or request.form or request.args
        resource = data.get("resource", resource_uri)
        sub = data.get("sub", "mcp-client")
        scenario = data.get("scenario", "valid")
        now = int(time.time())
        claims = {"iss": as_issuer, "aud": resource, "sub": sub,
                  "iat": now, "exp": now + TOKEN_TTL, "scope": "mcp:use"}
        if scenario == "expired":
            claims.update(iat=now - 7200, exp=now - 3600)
        token = jwt.encode(claims, STRONG_SECRET, algorithm="HS256")
        return jsonify({"access_token": token, "token_type": "Bearer",
                        "expires_in": TOKEN_TTL})

    # ---------------- Protected Resource Metadata (RFC 9728) ----------------

    @app.get("/.well-known/oauth-protected-resource")
    def protected_resource_metadata():
        return jsonify({
            "resource": resource_uri,
            "authorization_servers": [as_issuer],
            "bearer_methods_supported": ["header"],
            "scopes_supported": ["mcp:use"],
        })

    # ---------------- MCP endpoint (Bearer-protected JSON-RPC) ----------------

    def _challenge(reason: str):
        resp = jsonify({"error": "invalid_token", "error_description": reason})
        resp.status_code = 401
        resp.headers["WWW-Authenticate"] = (
            f'Bearer resource_metadata="{prm_url}", error="invalid_token", '
            f'error_description="{reason}"'
        )
        return resp

    def _authenticate():
        """Return (claims, None) on success or (None, error_response)."""
        auth = request.headers.get("Authorization", "")
        if not auth.lower().startswith("bearer "):
            return None, _challenge("missing bearer token")
        token = auth[7:].strip()
        try:
            if app.config["enforce_audience"]:
                claims = jwt.decode(token, STRONG_SECRET, algorithms=["HS256"],
                                    issuer=as_issuer, audience=resource_uri,
                                    options={"require": ["exp", "iss", "aud"]})
            else:
                # MISCONFIGURATION: audience is not checked.
                claims = jwt.decode(token, STRONG_SECRET, algorithms=["HS256"],
                                    issuer=as_issuer,
                                    options={"require": ["exp", "iss"], "verify_aud": False})
            return claims, None
        except jwt.PyJWTError as exc:
            return None, _challenge(str(exc))

    @app.post("/mcp")
    def mcp():
        claims, err = _authenticate()
        if err is not None:
            return err
        body = request.get_json(silent=True) or {}
        method = body.get("method")
        req_id = body.get("id")

        if method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "tokenguard-lab-mcp", "version": "0.1.0"},
            }
        elif method == "tools/list":
            result = {"tools": [{
                "name": "echo",
                "description": "Echoes its input (lab tool).",
                "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
            }]}
        elif method == "tools/call":
            params = body.get("params", {})
            text = params.get("arguments", {}).get("text", "")
            result = {"content": [{"type": "text", "text": f"echo: {text}"}]}
        else:
            return jsonify({"jsonrpc": "2.0", "id": req_id,
                            "error": {"code": -32601, "message": f"method not found: {method}"}})

        return jsonify({"jsonrpc": "2.0", "id": req_id, "result": result,
                        "_authenticated_sub": claims.get("sub")})

    @app.get("/mcp")
    def mcp_get():
        # Unauthenticated discovery probe lands here too; always challenge without a token.
        claims, err = _authenticate()
        if err is not None:
            return err
        return jsonify({"status": "ready", "resource": resource_uri})

    return app


def main():
    import argparse
    import warnings

    warnings.filterwarnings("ignore")
    ap = argparse.ArgumentParser(description="Local OAuth 2.1 MCP lab server")
    ap.add_argument("--insecure", action="store_true",
                    help="run the misconfigured variant (no audience validation)")
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    enforce = not args.insecure
    port = args.port if args.port is not None else (7000 if enforce else 7001)
    issuer_base = f"http://{args.host}:{port}"
    app = create_app(enforce_audience=enforce, issuer_base=issuer_base)
    mode = "SECURE (audience enforced)" if enforce else "MISCONFIGURED (no audience check)"
    print(f"[mcp-lab] {mode} on {issuer_base}")
    app.run(host=args.host, port=port, debug=False)


if __name__ == "__main__":
    main()
