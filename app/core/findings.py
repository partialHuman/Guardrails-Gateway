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


@dataclass(frozen=True, slots=True)
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


class ScanBudget:
    """
    Request-wide allowance of *regular* findings, shared by every detector.

    This is the single, consistent way detectors report that their budget
    ran out. A detector calls :meth:`reserve` immediately BEFORE it creates
    each finding:

    * ``True``  - one finding was reserved; the detector may create it.
    * ``False`` - no allowance is left. :attr:`exhausted` is now latched
      ``True`` and the detector must stop at once and return what it has.
      Because detectors iterate lazily, abandoning the loop also abandons
      the underlying regex iteration: no further matches are even produced.

    ``exhausted`` therefore means "a further finding was discovered that
    could not be recorded", i.e. the scan is INCOMPLETE. Exactly ``limit``
    findings with nothing left over is a complete scan and does not set it.

    A caller that passes a budget MUST check ``exhausted`` afterwards: an
    empty or short result from an exhausted scan is not a "clean" result.

    The synthetic ``scan_limit_exceeded`` finding is created outside the
    budget (it is never reserved), so reporting exhaustion cannot itself
    consume or re-trigger the limit.

    The object is mutable and intended for one request on one thread.
    """

    __slots__ = ("_limit", "_used", "_exhausted")

    def __init__(self, limit: int) -> None:
        # Zero and negative budgets are supported and mean "no findings
        # allowed": the first match found exhausts the budget.
        self._limit = max(0, int(limit))
        self._used = 0
        self._exhausted = False

    @property
    def limit(self) -> int:
        return self._limit

    @property
    def used(self) -> int:
        return self._used

    @property
    def remaining(self) -> int:
        return self._limit - self._used

    @property
    def exhausted(self) -> bool:
        return self._exhausted

    def reserve(self) -> bool:
        """Claim one finding. Returns False (and latches) when none is left."""
        if self._exhausted:
            return False

        if self._used >= self._limit:
            self._exhausted = True
            return False

        self._used += 1
        return True

    def __repr__(self) -> str:
        return (
            f"ScanBudget(limit={self._limit}, used={self._used}, "
            f"exhausted={self._exhausted})"
        )
