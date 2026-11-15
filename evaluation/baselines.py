"""Baseline adapter: run the external `jwt_tool` and map its output to our labels.

jwt_tool (https://github.com/ticarpi/jwt_tool) is a well-known JWT testing tool. It is
not on PyPI as an importable package, so this adapter shells out to the script. Point it
at the file with `--jwt-tool PATH`, the `JWT_TOOL` environment variable, or by placing
`jwt_tool.py` on PATH.

Overlap with TokenGuard's rules (what a fair head-to-head can score):
  * ALG_NONE  <- header line `alg = "none"`
  * EXPIRED   <- decode output `TOKEN IS EXPIRED!`
  * WEAK_KEY  <- `-C -d <wordlist>` output `... is the CORRECT key!`

jwt_tool does not flag missing aud/iss/exp, long lifetimes, or sensitive payload data,
so those labels are outside the shared-checks comparison.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable, Optional, Set

from tokenguard.config import DEFAULT_WORDLIST
from tokenguard.parser import TokenParseError, parse_token

OVERLAP_LABELS = {"ALG_NONE", "EXPIRED", "WEAK_KEY"}
HMAC_ALGS = {"HS256", "HS384", "HS512"}

_ANSI = re.compile(r"\x1B\[[0-9;?]*[a-zA-Z]")
_NONE_ALG = re.compile(r'alg\s*=\s*["\']?none["\']?', re.IGNORECASE)


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text or "")


def parse_jwt_tool_output(decode_out: str, crack_out: str = "") -> Set[str]:
    """Map jwt_tool's textual output to overlap labels (pure, so it is unit-testable)."""
    labels: Set[str] = set()
    decode_out = strip_ansi(decode_out)
    crack_out = strip_ansi(crack_out)
    if _NONE_ALG.search(decode_out):
        labels.add("ALG_NONE")
    if "TOKEN IS EXPIRED" in decode_out.upper():
        labels.add("EXPIRED")
    if "IS THE CORRECT KEY" in crack_out.upper():
        labels.add("WEAK_KEY")
    return labels


# runner: (token, crack) -> combined stdout+stderr text
Runner = Callable[[str, bool], str]


def _token_alg(token: str) -> Optional[str]:
    try:
        return parse_token(token).alg
    except TokenParseError:
        return None


def jwt_tool_labels(token: str, runner: Runner) -> Set[str]:
    decode_out = runner(token, False)
    crack_out = ""
    alg = _token_alg(token)
    if isinstance(alg, str) and alg.upper() in HMAC_ALGS:
        crack_out = runner(token, True)
    return parse_jwt_tool_output(decode_out, crack_out)


class JwtTool:
    """Locates and runs the real jwt_tool script."""

    def __init__(self, path: Optional[str], python_exe: str = None,
                 wordlist: Path = DEFAULT_WORDLIST, timeout: float = 60.0):
        self.path = path
        self.python_exe = python_exe or sys.executable
        self.wordlist = str(wordlist)
        self.timeout = timeout

    @property
    def available(self) -> bool:
        return bool(self.path) and Path(self.path).exists()

    @classmethod
    def locate(cls, explicit: Optional[str] = None, **kw) -> "JwtTool":
        path = explicit or os.environ.get("JWT_TOOL") or shutil.which("jwt_tool.py")
        return cls(path, **kw)

    def _run(self, token: str, crack: bool) -> str:
        args = [self.python_exe, self.path, token]
        if crack:
            args += ["-C", "-d", self.wordlist]
        env = dict(os.environ, PYTHONWARNINGS="ignore")
        try:
            proc = subprocess.run(args, capture_output=True, text=True, errors="ignore",
                                  timeout=self.timeout, env=env)
        except subprocess.TimeoutExpired:
            return ""
        return (proc.stdout or "") + (proc.stderr or "")

    def labels(self, token: str) -> Set[str]:
        if not self.available:
            raise RuntimeError("jwt_tool not found; pass --jwt-tool PATH or set JWT_TOOL")
        return jwt_tool_labels(token, self._run)
