"""
Sanitization utilities for SentraGuard Lite.

Redaction is span based: detectors report where a match is, the
sanitizer replaces exactly those spans in the canonical text.
"""

from __future__ import annotations

from typing import Iterable

from app.core.detectors import (
    detect_pii,
    detect_prompt_injection,
    detect_rag_injection,
)
from app.core.findings import Finding
from app.utils.text import canonicalize


def apply_findings(text: str, findings: Iterable[Finding]) -> str:
    """
    Replace the span of every given finding with its replacement text.

    Overlapping spans are merged (the earliest finding's replacement
    wins). If there is nothing to replace, the original text is returned
    untouched.
    """

    spans = [(f.start, f.end, f.replacement) for f in findings]

    if not spans:
        return text

    canonical = canonicalize(text)

    merged: list[list] = []

    for start, end, replacement in sorted(spans, key=lambda s: (s[0], -s[1])):

        if merged and start < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
            continue

        merged.append([start, end, replacement])

    pieces: list[str] = []

    position = 0

    for start, end, replacement in merged:
        pieces.append(canonical[position:start])
        pieces.append(replacement)
        position = end

    pieces.append(canonical[position:])

    return "".join(pieces).strip()


def sanitize_prompt(text: str) -> str:
    """
    Sanitize a user prompt by:
    - Redacting PII (emails, phones, cards, Aadhaar)
    - Removing prompt injection phrases
    """

    return apply_findings(
        text,
        detect_prompt_injection(text) + detect_pii(text),
    )


def sanitize_document(text: str) -> str:
    """
    Sanitize a retrieved context document by redacting PII and every
    injection phrase. (The analyzer quarantines high-severity documents
    instead of cleaning them; this is the "clean it anyway" helper.)
    """

    return apply_findings(
        text,
        detect_rag_injection(text) + detect_pii(text),
    )
