from __future__ import annotations

from dataclasses import dataclass, asdict
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name


@dataclass
class Finding:
    rule_id: str          # e.g. "ALG_NONE"
    title: str
    part: str             # "header" | "payload" | "signature"
    severity: Severity
    explanation: str
    evidence: str = ""    # already masked when sensitive

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = str(self.severity)
        return d


def mask(value, visible: int = 2) -> str:
    """Mask a sensitive value, revealing only the last `visible` characters and
    only when the value is long enough that most of it stays hidden. Short values
    (<= 6 chars), such as common recovered secrets, are masked completely so that
    guessable keys are not partially leaked in the output."""
    if value is None:
        return ""
    value = str(value)
    if len(value) <= 6:
        return "*" * len(value)
    return "*" * (len(value) - visible) + value[-visible:]
