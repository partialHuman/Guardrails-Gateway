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

Bounded scanning
----------------
Every public detector accepts an optional keyword-only ``budget``
(:class:`app.core.findings.ScanBudget`). It is shared by all detectors for
one request. A detector calls ``budget.reserve()`` BEFORE it creates each
finding; when that returns False the detector returns immediately, so the
match-collection loop and the lazy regex iterator behind it really stop
(nothing is collected and then sliced).

Reporting exhaustion: the detector returns the findings it recorded so far
and ``budget.exhausted`` is True. That result is an INCOMPLETE scan, not a
clean one: callers MUST check ``budget.exhausted`` and must not forward or
redact-and-trust the scanned text. A detector handed an already-exhausted
budget does no work and returns ``[]``. Without a budget the detectors are
unbounded, exactly as before.

The budget bounds finding objects and per-match work. It does NOT bound
regex CPU time: text that produces no matches is still scanned to its end.
"""

from __future__ import annotations

import base64
import binascii
import re

from app.core.findings import ACTION_QUARANTINE, ACTION_REDACT, Finding, ScanBudget
from app.core.policy import (
    ENCODED_PREFIX,
    INJECTION_RULES,
    LIMIT_RULE_ID,
    LIMIT_SEVERITY,
    LIMIT_TAG,
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
# Matches are never capped per rule (that would leave unredacted text behind);
# the request-wide finding budget in app/core/policy.py fails closed instead.
MAX_BASE64_CANDIDATES = 20
MAX_DECODED_CHARS = 4000

# Maximum encoded token length to inspect. In Base64, 4 chars encode 3 bytes.
# ceil(4000 / 3) * 4 = 5336 chars decode to 4000 bytes. Tokens longer than
# this are rejected before base64.b64decode() to bound CPU and memory.
MAX_BASE64_TOKEN_CHARS = ((MAX_DECODED_CHARS + 2) // 3) * 4

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

    if len(token) > MAX_BASE64_TOKEN_CHARS:
        return None

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


def limit_finding(source: str, quarantine: bool) -> Finding:
    """
    Zero-width finding meaning "the request-wide finding budget was hit".

    Severity 100 drives the request to BLOCK. `quarantine=True` marks the
    document it is attached to as dropped, so nothing unscanned is passed on.
    """

    return Finding(
        rule_id=LIMIT_RULE_ID,
        tag=LIMIT_TAG,
        severity=LIMIT_SEVERITY,
        start=0,
        end=0,
        evidence="Scan limit exceeded: request contains too many matches to process safely",
        source=source,
        action=ACTION_QUARANTINE if quarantine else ACTION_REDACT,
        replacement="",
    )


# ==========================================================
# Injection detection
# ==========================================================

def _detect_injection(
    text: str,
    scope: str,
    source: str,
    budget: ScanBudget | None = None,
) -> list[Finding]:
    """
    Run every injection rule that applies to `scope`
    ("prompt" or "document") against the normalised text.

    With a ``budget``, stops at once (all remaining rules and the base64
    pass included) when it is exhausted; see the module docstring.
    """

    if budget is not None and budget.exhausted:
        return []

    tag = "prompt_injection" if scope == "prompt" else "rag_injection"

    canonical = canonicalize(text)
    view = _injection_view(canonical)

    findings: list[Finding] = []

    for rule in INJECTION_RULES:

        if scope not in rule.scopes:
            continue

        action = ACTION_REDACT if scope == "prompt" else rule.doc_action

        replacement = _replacement_for(rule.id, scope)

        for match in rule.pattern.finditer(view):

            if budget is not None and not budget.reserve():
                return findings  # incomplete scan: stop all work now

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
        _detect_encoded_injection(canonical, scope, source, tag, budget)
    )

    return findings


def _detect_encoded_injection(
    canonical: str,
    scope: str,
    source: str,
    tag: str,
    budget: ScanBudget | None = None,
) -> list[Finding]:

    findings: list[Finding] = []

    if budget is not None and budget.exhausted:
        return findings

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

            if budget is not None and not budget.reserve():
                return findings  # incomplete scan: stop decoding further tokens

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


def detect_prompt_injection(
    text: str,
    source: str = "prompt",
    *,
    budget: ScanBudget | None = None,
) -> list[Finding]:
    """
    Detect prompt injection attempts in a user prompt.

    Pass ``budget`` to bound the scan; check ``budget.exhausted`` afterwards.
    """

    return _detect_injection(text, "prompt", source, budget)


def detect_rag_injection(
    text: str,
    source: str = "document",
    *,
    budget: ScanBudget | None = None,
) -> list[Finding]:
    """
    Detect malicious instructions inside retrieved documents.

    Pass ``budget`` to bound the scan; check ``budget.exhausted`` afterwards.
    """

    return _detect_injection(text, "document", source, budget)


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


def _iter_emails(canonical: str):
    """
    Lazy, linear-time email finder: for every "@", take up to 64 allowed
    characters on the left and a domain on the right.

    A generator on purpose: when the scan budget runs out the caller simply
    stops iterating and no further "@" is examined.
    """

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
                yield (start, domain.end())

        position = canonical.find("@", position + 1)


def _find_emails(canonical: str) -> list[tuple[int, int]]:
    """Eager form of :func:`_iter_emails` (kept for callers that want a list)."""

    return list(_iter_emails(canonical))


def _pii_candidates(canonical: str):
    """
    Yield (rule_id, start, end, evidence) in priority order.

    Order matters: more specific / validated detectors come first, so
    "4111 1111 1111 1111" is a card, never also a phone. The caller drops
    any candidate that overlaps an earlier one.
    """

    # Email
    for start, end in _iter_emails(canonical):
        yield "email", start, end, "Email address detected"

    # Payment card (Luhn + issuer prefix)
    for m in CARD_PATTERN.finditer(canonical):
        digits = re.sub(r"\D", "", m.group())
        if _CARD_PREFIX.match(digits) and luhn_valid(digits):
            yield "credit_card", m.start(), m.end(), "Payment card number detected"

    # Aadhaar (Verhoeff)
    for m in AADHAAR_PATTERN.finditer(canonical):
        digits = re.sub(r"\D", "", m.group())
        if verhoeff_valid(digits):
            yield "aadhaar", m.start(), m.end(), "Aadhaar number detected"

    # Phone: international, then Indian mobile, then NANP-style
    for m in PHONE_INTL_PATTERN.finditer(canonical):
        trimmed = _trim_international(m.group())
        if trimmed is None:
            continue
        yield "phone", m.start(), m.start() + len(trimmed), "Phone number detected"

    for pattern in (PHONE_IN_PATTERN, PHONE_NANP_PATTERN):
        for m in pattern.finditer(canonical):
            yield "phone", m.start(), m.end(), "Phone number detected"


def detect_pii(
    text: str,
    source: str = "prompt",
    *,
    budget: ScanBudget | None = None,
) -> list[Finding]:
    """
    Detect personally identifiable information.

    Runs in time linear in the input size: claimed spans are tracked in a
    byte mask, so an overlap check costs O(span) instead of O(findings).
    (The previous list-based check was quadratic: a 1 MiB request packed
    with e-mail addresses cost ~23 s of CPU.)

    Every match is reported (redaction must be complete). With a ``budget``
    the scan stops the moment it is exhausted (the lazy candidate generators
    are abandoned, so no further matches are produced); ``budget.exhausted``
    then means the scan is incomplete and the text must not be forwarded.
    Candidates that overlap an earlier finding are skipped WITHOUT consuming
    budget: only findings that are actually recorded are counted.
    """

    if budget is not None and budget.exhausted:
        return []

    canonical = canonicalize(text)

    claimed = bytearray(len(canonical))

    findings: list[Finding] = []

    for rule_id, start, end, evidence in _pii_candidates(canonical):

        if claimed.find(1, start, end) != -1:
            continue  # overlaps a span already claimed by an earlier detector

        if budget is not None and not budget.reserve():
            break  # incomplete scan: stop all work now

        claimed[start:end] = b"\x01" * (end - start)

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

    return findings
