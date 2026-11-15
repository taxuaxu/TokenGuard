# TokenGuard — A JWT Security Analysis Tool

TokenGuard analyzes JSON Web Tokens for common security problems and actively tests how a
**locally hosted** server validates tokens. Course project (Fall 2026) — Tuğberk Aksu.

> ⚠️ For local, educational use only. It analyzes tokens and tests lab servers you run
> yourself. It does not interact with live systems, real accounts, or production credentials.

## What it does

**Static analysis** — decodes a token without trusting its signature, then runs rule groups:

| Group | Checks |
|-------|--------|
| `algorithm` | `alg=none`, missing/unknown/unexpected algorithm, empty signature, `jwk`/`jku`/`x5u`/`kid` injection headers |
| `claims` | missing `exp`/`aud`/`iss`, expired, excessive lifetime, future `nbf`, sensitive data in payload |
| `weak_key` | recovers guessable HMAC secrets (HS256/384/512) from a wordlist |

Each finding has a severity (INFO→CRITICAL), an explanation, and masked evidence.

**Active testing** — sends crafted tokens (`alg=none`, tampered signature, expired, wrong
audience, weak-key forgery) to a deliberately misconfigured local server and records which
attacks are accepted. The target host must be `127.0.0.1`/`localhost`.

**MCP case study** — probes a local, OAuth 2.1-protected MCP (Model Context Protocol)
server following the MCP authorization spec (OAuth 2.1 + RFC 9728): the 401 challenge,
protected-resource metadata discovery, **audience binding** (a token minted for another
resource must be rejected — the confused-deputy rule), and expiry. Ships a secure variant
and a misconfigured one that skips audience validation.

**Evaluation** — a labeled dataset and three detection configurations (basic / basic+weak /
all) scored with precision, recall, F1, and false-positive counts.

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows  (source .venv/bin/activate on Linux/macOS)
pip install -r requirements.txt
```

## Usage

```bash
# Static analysis
python -m tokenguard analyze "<jwt>"
python -m tokenguard analyze "<jwt>" --groups algorithm claims --json

# Active testing (run the lab server in another terminal first)
python vuln_server/app.py
python -m tokenguard active --target http://127.0.0.1:5000

# MCP case study (run a lab MCP server in another terminal first)
python mcp_server/server.py                 # secure,        :7000
python mcp_server/server.py --insecure      # misconfigured, :7001
python -m tokenguard mcp --target http://127.0.0.1:7000

# Evaluation
python dataset/generate.py
python evaluation/evaluate.py

# Web UI
streamlit run app.py

# Tests
pytest
```

## Layout

```
tokenguard/        package: parser, models, config, rules/, active/, mcp_probe, cli
vuln_server/app.py deliberately misconfigured Flask server + tiny token issuer
mcp_server/server.py local OAuth 2.1 MCP server (secure + misconfigured variants)
dataset/generate.py labeled secure/insecure tokens (PyJWT)
evaluation/evaluate.py precision / recall / F1 / FP across 3 configs
app.py             Streamlit UI (static + active tabs)
wordlists/         common-secrets wordlist for weak-key detection
tests/             pytest suite (static rules + active mode)
```

## Status

Static analysis, active testing against the local lab server, the OAuth 2.1 MCP case
study, the labeled dataset, and evaluation are implemented with a passing test suite
(`pytest`). The `jwt_tool` baseline comparison is the remaining milestone.
