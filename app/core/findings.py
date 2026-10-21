"""
Plain data types shared by the detection pipeline.

Deliberately free of any web-framework / pydantic dependency so the core
engine can be used and unit-tested on its own.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Decision(str, Enum):
    """Possible policy decisions."""

    ALLOW = "allow"
    TRANSFORM = "transform"
    BLOCK = "block"


# What to do with the text a finding points at.
ACTION_REDACT = "redact"          # replace the matched span
ACTION_QUARANTINE = "quarantine"  # drop the whole context document


@dataclass(frozen=True)
class Finding:
    """One detector hit."""

    rule_id: str        # e.g. "override_instructions", "email"
    tag: str            # "prompt_injection" | "rag_injection" | "pii"
    severity: int       # points contributed to the risk score
    start: int          # span in the *canonical* text (see utils/text.py)
    end: int
    evidence: str       # human readable; never echoes PII values
    source: str         # "prompt" or the context document id
    action: str         # ACTION_REDACT | ACTION_QUARANTINE
    replacement: str    # text that replaces the span when redacting
