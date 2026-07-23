"""
Detection engine for SentraGuard Lite.

Implements:
- Prompt Injection Detection
- PII Detection
- RAG Injection Detection
"""

from __future__ import annotations

import re

from app.schemas import Reason
from app.core.policy import (
    PROMPT_INJECTION_PATTERNS,
    RAG_INJECTION_PATTERNS,
)

from app.utils.regex import (
    EMAIL_REGEX,
    PHONE_REGEX,
)

# Compile regex once for better performance
EMAIL_PATTERN = re.compile(EMAIL_REGEX, re.IGNORECASE)
PHONE_PATTERN = re.compile(PHONE_REGEX)


def detect_prompt_injection(text: str) -> list[Reason]:
    """
    Detect prompt injection attempts.

    Returns:
        List of Reason objects.
    """

    reasons: list[Reason] = []

    lowered = text.lower()

    matched = set()

    for phrase in PROMPT_INJECTION_PATTERNS:

        if phrase in lowered and phrase not in matched:

            matched.add(phrase)

            reasons.append(
                Reason(
                    tag="prompt_injection",
                    evidence=f"Matched phrase: '{phrase}'"
                )
            )

    return reasons


def detect_rag_injection(text: str) -> list[Reason]:
    """
    Detect malicious instructions inside retrieved documents.
    """

    reasons: list[Reason] = []

    lowered = text.lower()

    matched = set()

    for phrase in RAG_INJECTION_PATTERNS:

        if phrase in lowered and phrase not in matched:

            matched.add(phrase)

            reasons.append(
                Reason(
                    tag="rag_injection",
                    evidence=f"Matched phrase: '{phrase}'"
                )
            )

    return reasons


def detect_pii(text: str) -> list[Reason]:
    """
    Detect personally identifiable information.
    """

    reasons: list[Reason] = []

    if EMAIL_PATTERN.search(text):

        reasons.append(

            Reason(
                tag="pii",
                evidence="Email address detected"
            )

        )

    if PHONE_PATTERN.search(text):

        reasons.append(

            Reason(
                tag="pii",
                evidence="Phone number detected"
            )

        )

    return reasons