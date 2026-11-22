from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

DEFAULT_WORDLIST = Path(__file__).resolve().parent.parent / "wordlists" / "common_secrets.txt"


@dataclass
class AnalysisConfig:
    now: Optional[float] = None                 # unix time; None = current time
    leeway_seconds: int = 120                   # clock-skew tolerance for exp/nbf
    max_lifetime_seconds: int = 24 * 3600       # longer than this -> LONG_LIFETIME
    expected_algs: Optional[List[str]] = None   # if set, anything else -> ALG_UNEXPECTED
    wordlist_path: Path = DEFAULT_WORDLIST
    extra_secrets: List[str] = field(default_factory=list)

    def current_time(self) -> float:
        return time.time() if self.now is None else self.now
