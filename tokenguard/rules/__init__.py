"""Detection rules. Each rule is a function (token, config) -> list[Finding],
registered in a named group so configurations can be compared in evaluation."""
from __future__ import annotations

from typing import Callable, Dict, Iterable, List, Optional

from ..config import AnalysisConfig
from ..models import Finding
from ..parser import ParsedToken, parse_token
from . import algorithm, claims, weak_key

Rule = Callable[[ParsedToken, AnalysisConfig], List[Finding]]

RULE_GROUPS: Dict[str, List[Rule]] = {
    "algorithm": algorithm.RULES,
    "claims": claims.RULES,
    "weak_key": weak_key.RULES,
}

ALL_GROUPS = tuple(RULE_GROUPS)


def analyze(token, groups: Optional[Iterable[str]] = None,
            config: Optional[AnalysisConfig] = None) -> List[Finding]:
    """Run the selected rule groups against a token (string or ParsedToken)."""
    config = config or AnalysisConfig()
    parsed = token if isinstance(token, ParsedToken) else parse_token(token)
    findings: List[Finding] = []
    for group in (groups or ALL_GROUPS):
        for rule in RULE_GROUPS[group]:
            findings.extend(rule(parsed, config))
    findings.sort(key=lambda f: f.severity, reverse=True)
    return findings
