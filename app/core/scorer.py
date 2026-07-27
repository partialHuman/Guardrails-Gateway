"""
Risk scoring engine for SentraGuard Lite.

Converts detector findings into:
- Overall risk score (0-100)
- Risk tags
"""

from __future__ import annotations

from app.schemas import Reason
from app.core.policy import (
    PROMPT_INJECTION_SCORE,
    RAG_INJECTION_SCORE,
    PII_SCORE,
)


def calculate_score(reasons: list[Reason]) -> tuple[int, list[str]]:
    """
    Calculate the overall risk score and collect unique risk tags.

    Scoring is applied once per unique risk category to avoid
    double-counting multiple matches of the same threat type.

    Args:
        reasons: List of detector findings.

    Returns:
        Tuple containing:
        - risk score (0-100)
        - sorted list of unique risk tags
    """

    tags = {reason.tag for reason in reasons}

    score = 0

    if "prompt_injection" in tags:
        score += PROMPT_INJECTION_SCORE

    if "rag_injection" in tags:
        score += RAG_INJECTION_SCORE

    if "pii" in tags:
        score += PII_SCORE

    score = min(score, 100)

    return score, sorted(tags)