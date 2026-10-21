"""
Detection engine for SentraGuard Lite.

Implements:
- Prompt Injection Detection
- RAG (context document) Injection Detection
- PII Detection (email, phone, payment card, Aadhaar)

All detectors normalise the text first (see app/utils/text.py) so that
zero-width characters, odd whitespace, look-alike letters and leetspeak
do not hide a phrase. Findings carry spans into the *canonical* text,
which is what the sanitizer redacts.
"""

from __future__ import annotations

import base64
import binascii
import re

from app.core.findings import ACTION_REDACT, Finding
from app.core.policy import (
    ENCODED_PREFIX,
    INJECTION_RULES,
    PII_RULES,
    REPLACEMENT_PROMPT_INJECTION,
    REPLACEMENT_RAG_INJECTION,
    REPLACEMENT_ROLE_MARKER,
)
from app.utils.regex import (
    AADHAAR_REGEX,
    BASE64_REGEX,
    CARD_REGEX,
    EMAIL_DOMAIN_REGEX,
    EMAIL_LOCAL_CHARS,
    EMAIL_LOCAL_MAX,
    PHONE_IN_REGEX,
    PHONE_INTL_REGEX,
    PHONE_NANP_REGEX,
)
from app.utils.text import (
    canonicalize,
    fold_confusables,
    fold_leet,
)
from app.utils.validators import luhn_valid, verhoeff_valid

# Compile regex once for better performance
EMAIL_DOMAIN_PATTERN = re.compile(EMAIL_DOMAIN_REGEX)
CARD_PATTERN = re.compile(CARD_REGEX)
AADHAAR_PATTERN = re.compile(AADHAAR_REGEX)
PHONE_INTL_PATTERN = re.compile(PHONE_INTL_REGEX)
PHONE_IN_PATTERN = re.compile(PHONE_IN_REGEX)
PHONE_NANP_PATTERN = re.compile(PHONE_NANP_REGEX)
BASE64_PATTERN = re.compile(BASE64_REGEX)

# Safety valves so one hostile input cannot make a scan expensive.
# MAX_MATCHES_PER_RULE = 50
MAX_BASE64_CANDIDATES = 20
MAX_DECODED_CHARS = 4000

# Payment-card issuer prefixes (Visa, Mastercard, Amex, Discover, JCB, Diners).
_CARD_PREFIX = re.compile(r"^(?:4|5[1-5]|2[2-7]|3[0-9]|6011|65)")

_EVIDENCE_MAX = 80


# ==========================================================
# Helpers
# ==========================================================

def _clip(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= _EVIDENCE_MAX else text[:_EVIDENCE_MAX] + "…"


def _replacement_for(rule_id: str, scope: str) -> str:
    if rule_id == "role_marker":
        return REPLACEMENT_ROLE_MARKER
    if scope == "prompt":
        return REPLACEMENT_PROMPT_INJECTION
    return REPLACEMENT_RAG_INJECTION


def _decode_base64(token: str) -> str | None:
    """Return decoded text if the token is plausibly base64-encoded text."""

    candidate = token.replace("-", "+").replace("_", "/")
    candidate += "=" * (-len(candidate) % 4)

    try:
        raw = base64.b64decode(candidate, validate=True)
        decoded = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None

    if not decoded:
        return None

    printable = sum(ch.isprintable() or ch in "\n\t" for ch in decoded)

    if printable / len(decoded) < 0.9:
        return None

    return decoded[:MAX_DECODED_CHARS]


def _injection_view(canonical: str) -> str:
    return fold_leet(fold_confusables(canonical))


# ==========================================================
# Injection detection
# ==========================================================

def _detect_injection(text: str, scope: str, source: str) -> list[Finding]:
    """
    Run every injection rule that applies to `scope`
    ("prompt" or "document") against the normalised text.
    """

    tag = "prompt_injection" if scope == "prompt" else "rag_injection"

    canonical = canonicalize(text)
    view = _injection_view(canonical)

    findings: list[Finding] = []

    for rule in INJECTION_RULES:

        if scope not in rule.scopes:
            continue

        action = ACTION_REDACT if scope == "prompt" else rule.doc_action

        replacement = _replacement_for(rule.id, scope)

        for index, match in enumerate(rule.pattern.finditer(view)):

            #if index >= MAX_MATCHES_PER_RULE:
                #break

            findings.append(
                Finding(
                    rule_id=rule.id,
                    tag=tag,
                    severity=rule.severity,
                    start=match.start(),
                    end=match.end(),
                    evidence=f"Matched phrase: '{_clip(canonical[match.start():match.end()])}'",
                    source=source,
                    action=action,
                    replacement=replacement,
                )
            )

    # Base64-encoded payloads: decode once per text and re-scan.
    findings.extend(
        _detect_encoded_injection(canonical, scope, source, tag)
    )

    return findings


def _detect_encoded_injection(
    canonical: str,
    scope: str,
    source: str,
    tag: str,
) -> list[Finding]:

    findings: list[Finding] = []

    for index, token_match in enumerate(BASE64_PATTERN.finditer(canonical)):

        if index >= MAX_BASE64_CANDIDATES:
            break

        decoded = _decode_base64(token_match.group())

        if decoded is None:
            continue

        decoded_view = _injection_view(canonicalize(decoded))

        for rule in INJECTION_RULES:

            if scope not in rule.scopes or rule.id == "role_marker":
                continue

            inner = rule.pattern.search(decoded_view)

            if not inner:
                continue

            findings.append(
                Finding(
                    rule_id=f"{ENCODED_PREFIX}{rule.id}",
                    tag=tag,
                    severity=rule.severity,
                    start=token_match.start(),
                    end=token_match.end(),
                    evidence=(
                        "Base64-encoded payload matched: "
                        f"'{_clip(decoded_view[inner.start():inner.end()])}'"
                    ),
                    source=source,
                    action=(
                        ACTION_REDACT
                        if scope == "prompt"
                        else rule.doc_action
                    ),
                    replacement=_replacement_for(rule.id, scope),
                )
            )

    return findings


def detect_prompt_injection(text: str, source: str = "prompt") -> list[Finding]:
    """
    Detect prompt injection attempts in a user prompt.
    """

    return _detect_injection(text, "prompt", source)


def detect_rag_injection(text: str, source: str = "document") -> list[Finding]:
    """
    Detect malicious instructions inside retrieved documents.
    """

    return _detect_injection(text, "document", source)


# ==========================================================
# PII detection
# ==========================================================

def _trim_international(candidate: str) -> str | None:
    """
    Keep whitespace-separated groups of an international candidate while
    the running digit count stays within E.164's 15 digits.
    """

    kept: list[str] = []
    digits = 0

    for group in candidate.split():

        group_digits = sum(ch.isdigit() for ch in group)

        if digits + group_digits > 15:
            break

        kept.append(group)
        digits += group_digits

    if digits < 8:
        return None

    return " ".join(kept).rstrip(" .-(")


def _find_emails(canonical: str) -> list[tuple[int, int]]:
    """
    Linear-time email finder: for every "@", take up to 64 allowed
    characters on the left and a domain on the right.
    """

    spans: list[tuple[int, int]] = []

    position = canonical.find("@")

    while position != -1:

        domain = EMAIL_DOMAIN_PATTERN.match(canonical, position + 1)

        if domain:

            start = position

            while (
                start > 0
                and position - start < EMAIL_LOCAL_MAX
                and canonical[start - 1] in EMAIL_LOCAL_CHARS
            ):
                start -= 1

            if start < position:
                spans.append((start, domain.end()))

        position = canonical.find("@", position + 1)

    return spans


def detect_pii(text: str, source: str = "prompt") -> list[Finding]:
    """
    Detect personally identifiable information.

    Order matters: more specific / validated detectors claim their span
    first, so "4111 1111 1111 1111" is a card, never also a phone.
    """

    canonical = canonicalize(text)

    findings: list[Finding] = []

    claimed: list[tuple[int, int]] = []

    def free(start: int, end: int) -> bool:
        return all(end <= s or start >= e for s, e in claimed)

    def add(rule_id: str, start: int, end: int, evidence: str) -> None:
        claimed.append((start, end))
        rule = PII_RULES[rule_id]
        findings.append(
            Finding(
                rule_id=rule_id,
                tag="pii",
                severity=rule.severity,
                start=start,
                end=end,
                evidence=evidence,
                source=source,
                action=ACTION_REDACT,
                replacement=rule.replacement,
            )
        )

    # Email
    for start, end in _find_emails(canonical):
        if free(start, end):
            add("email", start, end, "Email address detected")

    # Payment card (Luhn + issuer prefix)
    for m in CARD_PATTERN.finditer(canonical):
        digits = re.sub(r"\D", "", m.group())
        if (
            free(m.start(), m.end())
            and _CARD_PREFIX.match(digits)
            and luhn_valid(digits)
        ):
            add("credit_card", m.start(), m.end(), "Payment card number detected")

    # Aadhaar (Verhoeff)
    for m in AADHAAR_PATTERN.finditer(canonical):
        digits = re.sub(r"\D", "", m.group())
        if free(m.start(), m.end()) and verhoeff_valid(digits):
            add("aadhaar", m.start(), m.end(), "Aadhaar number detected")

    # Phone: international, then Indian mobile, then NANP-style
    for m in PHONE_INTL_PATTERN.finditer(canonical):
        trimmed = _trim_international(m.group())
        if trimmed is None:
            continue
        start, end = m.start(), m.start() + len(trimmed)
        if free(start, end):
            add("phone", start, end, "Phone number detected")

    for pattern in (PHONE_IN_PATTERN, PHONE_NANP_PATTERN):
        for m in pattern.finditer(canonical):
            if free(m.start(), m.end()):
                add("phone", m.start(), m.end(), "Phone number detected")

    return findings
