# TokenGuard — A JWT Security Analysis Tool

TokenGuard analyzes JSON Web Tokens for common security problems and actively tests how a
**locally hosted** server validates tokens. Course project (Fall 2026) — Tuğberk Aksu.

> ⚠️ For local, educational use only. It analyzes tokens and tests lab servers you run
> yourself. It does not interact with live systems, real accounts, or production credentials.

## What it does

**Static analysis** — decodes a token without trusting its signature, then runs rule groups:

| Group | Checks |
|-------|--------|
| `algorithm` | `alg=none`, missing/unknown/unexpected algorithm, empty signature, `jwk`/`x5c`/`jku`/`x5u`/`kid` injection headers, abused `crit` header (RFC 7515), duplicate JSON keys (parser confusion) |
| `claims` | missing `exp`/`aud`/`iss`, expired, excessive lifetime, future `nbf`, sensitive data in payload (nested fields included) |
| `weak_key` | recovers guessable HMAC secrets (HS256/384/512) from a wordlist |

Each finding has a severity (INFO→CRITICAL), an explanation, masked evidence, and
remediation advice. A report combines an overall risk verdict, a human-readable claim
timeline (`iat`/`nbf`/`exp` with relative time), and the findings into Markdown.

**Active testing** — sends crafted tokens (`alg=none`, tampered signature, expired, wrong
audience, weak-key forgery) to a deliberately misconfigured local server and records which
attacks are accepted. The target host must be `127.0.0.1`/`localhost`.

**MCP case study** — probes a local, OAuth 2.1-protected MCP (Model Context Protocol)
server following the MCP authorization spec (OAuth 2.1 + RFC 9728): the 401 challenge,
protected-resource metadata discovery, **audience binding** (a token minted for another
resource must be rejected — the confused-deputy rule), expiry, and **token pass-through**
(a downstream call must use a token minted for the upstream, not the client's token). Ships
a secure variant and misconfigured ones that skip audience validation or pass the client's
token through.

**Evaluation** — a labeled dataset of 180 tokens (152 insecure, 28 secure and boundary
negatives). Coverage is derived from TokenGuard's own definitions, so the dataset exercises
every known algorithm, every sensitive-claim key, and a balanced sample of the weak-key
wordlist (the full wordlist via `--full-wordlist`, 223 tokens), alongside the full set of
algorithm, header-injection, and claim defects (HMAC and asymmetric, algorithm confusion,
header soup) and systematic multi-issue combinations. It is scored under two detection
configurations (`basic` without weak-key detection, `all` with it) on precision, recall, F1,
and false-positive counts, with a per-class breakdown (support and precision/recall per rule)
and an optional head-to-head benchmark against the external `jwt_tool` on their shared checks.
The test suite revalidates every token against its labels, so a mislabeled record or a
drifting rule fails a test instead of silently skewing the metrics.

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
python -m tokenguard analyze "<jwt>" --report      # Markdown report (risk, timeline, fixes)

# Active testing (run the lab server in another terminal first)
python vuln_server/app.py
python -m tokenguard active --target http://127.0.0.1:5000

# MCP case study (run a lab MCP server in another terminal first)
python mcp_server/server.py                 # secure,        :7000
python mcp_server/server.py --insecure      # misconfigured (no aud + pass-through), :7001
python mcp_server/server.py --passthrough   # token pass-through only, :7001
python -m tokenguard mcp --target http://127.0.0.1:7000

# Evaluation
python dataset/generate.py                      # balanced weak-key sample
python dataset/generate.py --full-wordlist      # exhaustive weak-key coverage
python evaluation/evaluate.py
python evaluation/evaluate.py --active-target http://127.0.0.1:5000   # + active-mode accuracy

# Evaluation with the jwt_tool baseline (clone ticarpi/jwt_tool first)
#   pip install termcolor pycryptodomex requests ratelimit   # jwt_tool's deps
python evaluation/evaluate.py --jwt-tool /path/to/jwt_tool.py   # or set JWT_TOOL

# Web UI (control panel: start/stop servers, run tests, charts, matrix)
streamlit run app.py

# Tests
pytest
```

## Layout

```
tokenguard/        package: parser, models, config, rules/, active/, mcp_probe, report, cli
vuln_server/app.py deliberately misconfigured Flask server + tiny token issuer
mcp_server/server.py local OAuth 2.1 MCP server (secure + misconfigured variants)
dataset/generate.py labeled secure/insecure tokens (PyJWT)
evaluation/evaluate.py precision / recall / F1 / FP across 3 configs
evaluation/baselines.py jwt_tool adapter (runs it, maps output to our labels)
app.py             Streamlit control panel (server control, static, active matrix, MCP, evaluation)
wordlists/         common-secrets wordlist for weak-key detection
tests/             pytest suite (static rules, active mode, dataset integrity)
```

## Results

On the 180-token labeled dataset, `basic` checks reach recall 0.82 (they miss the weak-key
labels); adding weak-key detection brings `all` to precision/recall/F1 = 1.0 with no false
positives. Because this dataset is derived from TokenGuard's own rule definitions, that
perfect score reflects coverage and internal consistency rather than generalization. On the
checks shared with `jwt_tool` (`alg=none`, expired, weak key), TokenGuard matches the
baseline (1.0 vs. 0.98, one jwt_tool false positive) while also covering claim-level issues
(`aud`/`iss`/lifetime/sensitive data) that jwt_tool does not flag.

For a more honest measure, a separate **hand-labeled hard set** of 100 adversarial cases,
written independently of the rules, first exposed concrete gaps (precision 0.75, recall
0.85). Addressing them — clock-skew tolerance for `exp`/`nbf`, context-aware lifetime
(refresh tokens are not flagged), a tighter `kid` pattern, and value-pattern plus an
expanded keyword list for sensitive data — raised the independent score to **precision 0.98
and recall 0.96**. Two documented limitations remain: the value heuristic can over-match a
coincidentally valid card number, and a secret under a generic free-text claim is still
missed. This iteration, on data independent of the rules, is the better reflection of
real-world behavior than the perfect score on the self-derived set.

## Status

All proposal milestones are implemented with a passing test suite (`pytest`): static
analysis, active testing against the local lab server, the OAuth 2.1 MCP case study, the
labeled dataset, evaluation, and the `jwt_tool` baseline comparison.
