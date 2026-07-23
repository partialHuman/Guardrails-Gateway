"""
Sanitization utilities for SentraGuard Lite.
"""

from __future__ import annotations

import re

from app.core.policy import (
    PROMPT_INJECTION_PATTERNS,
    RAG_INJECTION_PATTERNS,
)
from app.utils.regex import EMAIL_REGEX, PHONE_REGEX

# Compile regex patterns
EMAIL_PATTERN = re.compile(EMAIL_REGEX, re.IGNORECASE)
PHONE_PATTERN = re.compile(PHONE_REGEX)


def sanitize_prompt(text: str) -> str:
    """
    Sanitize a user prompt by:
    - Redacting emails
    - Redacting phone numbers
    - Removing prompt injection phrases
    """

    sanitized = text

    # Redact email addresses
    sanitized = EMAIL_PATTERN.sub(
        "[REDACTED_EMAIL]",
        sanitized
    )

    # Redact phone numbers
    sanitized = PHONE_PATTERN.sub(
        "[REDACTED_PHONE]",
        sanitized
    )

    # Remove prompt injection phrases
    for phrase in PROMPT_INJECTION_PATTERNS + RAG_INJECTION_PATTERNS:
        sanitized = re.sub(
            re.escape(phrase),
            "[REMOVED_PROMPT_INJECTION]",
            sanitized,
            flags=re.IGNORECASE,
        )

    return sanitized.strip()


def sanitize_document(text: str) -> str:
    """
    Sanitize a retrieved context document.
    """

    return sanitize_prompt(text)