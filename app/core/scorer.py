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

    Args:
        reasons: List of detector findings.

    Returns:
        Tuple containing:
        - risk score (0-100)
        - list of unique risk tags
    """

    score = 0
    tags: set[str] = set()

    for reason in reasons:

        tags.add(reason.tag)

        if reason.tag == "prompt_injection":
            score += PROMPT_INJECTION_SCORE

        elif reason.tag == "rag_injection":
            score += RAG_INJECTION_SCORE

        elif reason.tag == "pii":
            score += PII_SCORE

    # Cap score at 100
    score = min(score, 100)

    return score, sorted(tags)