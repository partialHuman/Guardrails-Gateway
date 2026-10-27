"""
Central policy configuration.

Contains:
- Detection rules (id, severity, scope, action)
- Decision thresholds
- Scoring weights
- The public policy document served by GET /policy

Severity = points a rule contributes to the risk score. Rules are grouped
by tag; see app/core/scorer.py for how they are combined.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.core.findings import ACTION_QUARANTINE, ACTION_REDACT

POLICY_VERSION = "3"

# ==========================================================
# Decision thresholds
# ==========================================================

BLOCK_THRESHOLD = 80

TRANSFORM_THRESHOLD = 40

# ==========================================================
# Scan limits (denial-of-service protection)
# ==========================================================

# Every text is scanned and redacted completely (no per-rule caps: a cap
# silently leaves matches beyond it in the "sanitized" output). Instead the
# whole REQUEST has a budget of findings. Legitimate traffic produces a
# handful; a request that exceeds the budget is hostile or too dense to
# redact reliably, so scanning stops, any document not yet scanned is
# quarantined, and the request is BLOCKED (fail closed).
#
# The budget is enforced INSIDE the detectors (see ScanBudget): they stop
# generating findings the moment it is spent. It bounds finding objects and
# the work done per match, NOT regex CPU time: scanning text that produces
# no matches costs time proportional to its length whatever the budget is
# (see the length limits in app/config.py and the README Limitations).
MAX_FINDINGS_PER_REQUEST = 20_000

LIMIT_RULE_ID = "scan_limit_exceeded"

LIMIT_TAG = "scan_limit"

LIMIT_SEVERITY = 100

# ==========================================================
# Scoring
# ==========================================================

# Within one tag the score is: highest rule severity
#   + EXTRA_RULE_BONUS for every *additional distinct* rule that fired
#     (capped at EXTRA_RULE_BONUS_CAP).
# Repeating the same phrase 100 times does not raise the score.
EXTRA_RULE_BONUS = 10

EXTRA_RULE_BONUS_CAP = 30

# ==========================================================
# Injection rules
# ==========================================================

_FLAGS = re.IGNORECASE | re.MULTILINE

# Skip phrases that are negated: "don't forget your instructions".
_NOT = r"(?<!n't )(?<!n’t )(?<!not )(?<!never )"


@dataclass(frozen=True)
class InjectionRule:
    id: str
    description: str
    pattern: re.Pattern
    severity: int
    scopes: tuple          # ("prompt", "document") or ("document",)
    doc_action: str = ACTION_QUARANTINE


INJECTION_RULES: tuple[InjectionRule, ...] = (

    InjectionRule(
        id="override_instructions",
        description="Tells the model to ignore / override earlier instructions",
        severity=50,
        scopes=("prompt", "document"),
        pattern=re.compile(
            _NOT
            + r"\b(?:ignore|disregard|forget|override|bypass|skip|discard)\b"
            r"[^.]{0,30}?"
            r"\b(?:previous|prior|above|earlier|preceding|former|system|your|all)\b"
            r"[^.]{0,20}?"
            r"\b(?:instructions?|prompts?|rules|directives|programming)\b"
            r"|"
            + _NOT
            + r"\b(?:override|overwrite|bypass)\s+"
            r"(?:(?:all|any|the|your|these|previous)\s+)*"
            r"(?:instructions?|directives|system\s+prompt)\b",
            _FLAGS,
        ),
    ),

    InjectionRule(
        id="disable_safeguards",
        description="Asks to disable guardrails / safety measures",
        severity=50,
        scopes=("prompt", "document"),
        pattern=re.compile(
            _NOT
            + r"\b(?:ignore|bypass|disable|override|circumvent|turn\s+off|deactivate)\b"
            r"[^.]{0,20}?\b(?:safeguards?|guardrails?)\b"
            r"|"
            + _NOT
            + r"\b(?:bypass|disable|circumvent|override|turn\s+off|deactivate)\b"
            r"[^.]{0,20}?\b(?:safety|content\s+polic(?:y|ies))\b",
            _FLAGS,
        ),
    ),

    InjectionRule(
        id="reveal_system_prompt",
        description="Tries to extract the system prompt",
        severity=45,
        scopes=("prompt", "document"),
        pattern=re.compile(
            r"\b(?:reveal|show|print|display|repeat|output|leak|dump|expose|disclose)\b"
            r"[^.]{0,15}?\b(?:(?:your|the|its|ur)\s+)?"
            r"(?:system|hidden|initial|original|secret)\s+"
            r"(?:prompt|instructions?|rules|message)\b"
            r"|"
            r"\bwhat(?:'s|\s+is|\s+are)\s+your\s+"
            r"(?:system|hidden|initial|secret)\s+(?:prompt|instructions?)\b",
            _FLAGS,
        ),
    ),

    InjectionRule(
        id="developer_mode",
        description="Jailbreak that switches the model into a 'developer mode'",
        severity=40,
        scopes=("prompt", "document"),
        pattern=re.compile(
            r"\b(?:you\s+are\s+(?:now\s+)?in|enter(?:ing)?|switch\s+to)\s+"
            r"(?:the\s+)?(?:developer|debug|god|jailbreak|dan)\s+mode\b"
            r"|"
            r"\bdeveloper\s+mode\s+(?:enabled|activated|on)\b",
            _FLAGS,
        ),
    ),

    InjectionRule(
        id="persona_jailbreak",
        description="DAN-style persona jailbreak",
        severity=50,
        scopes=("prompt", "document"),
        pattern=re.compile(
            r"\b(?:act\s+as|you\s+are\s+now|pretend\s+(?:to\s+be|you\s+are)|"
            r"from\s+now\s+on,?\s+you\s+are)\s+(?:a\s+|an\s+)?"
            r"(?:dan|do\s+anything\s+now|jailbroken|unrestricted|unfiltered)\b"
            r"|"
            r"\bdo\s+anything\s+now\b",
            _FLAGS,
        ),
    ),

    InjectionRule(
        id="chat_template_tokens",
        description="Chat-template control tokens smuggled into text",
        severity=50,
        scopes=("prompt", "document"),
        pattern=re.compile(
            r"<\|(?:im_start|im_end|system|user|assistant|endoftext|eot_id|"
            r"start_header_id|end_header_id)\|>"
            r"|\[/?INST\]"
            r"|<</?SYS>>",
            _FLAGS,
        ),
    ),

    # ---- context-document only -------------------------------------

    InjectionRule(
        id="role_marker",
        description="Line starting with a chat role ('System:', 'Developer:', 'Assistant:')",
        severity=25,
        scopes=("document",),
        doc_action=ACTION_REDACT,
        pattern=re.compile(
            r"^[ \t]*(?:system|developer|assistant)[ \t]*:",
            _FLAGS,
        ),
    ),

    InjectionRule(
        id="override_policy",
        description="Document tells the model to ignore its rules / guidelines / policy",
        severity=40,
        scopes=("document",),
        pattern=re.compile(
            _NOT
            + r"\b(?:override|ignore|disregard)\s+"
            r"(?:(?:all|any|the|these|your)\s+)*"
            r"(?:polic(?:y|ies)|guidelines|rules)\b",
            _FLAGS,
        ),
    ),

    InjectionRule(
        id="hidden_prompt_execution",
        description="Document asks the model to run a hidden prompt",
        severity=45,
        scopes=("document",),
        pattern=re.compile(
            r"\bexecute\b[^.]{0,15}?\b(?:hidden|secret)\s+"
            r"(?:prompt|instructions?|commands?)\b",
            _FLAGS,
        ),
    ),
)

# Replacement text used when redacting.
REPLACEMENT_PROMPT_INJECTION = "[REMOVED_PROMPT_INJECTION]"

REPLACEMENT_RAG_INJECTION = "[REMOVED_RAG_INJECTION]"

REPLACEMENT_ROLE_MARKER = "[ROLE_MARKER_REMOVED]"

# Returned as `sanitized_prompt` when the prompt could not be scanned to the
# end (finding budget exhausted). It deliberately contains NONE of the
# caller's text: a half-redacted prompt must never look like safe output.
INCOMPLETE_SCAN_PROMPT = "[BLOCKED: prompt could not be fully scanned]"

# Base64 payloads are decoded and re-scanned once.
ENCODED_PREFIX = "encoded:"

# ==========================================================
# PII rules
# ==========================================================

@dataclass(frozen=True)
class PiiRule:
    id: str
    description: str
    severity: int
    replacement: str


PII_RULES: dict[str, PiiRule] = {

    "email": PiiRule(
        "email", "Email address", 15, "[REDACTED_EMAIL]"
    ),

    "phone": PiiRule(
        "phone", "Phone number", 15, "[REDACTED_PHONE]"
    ),

    "credit_card": PiiRule(
        "credit_card", "Payment card number (Luhn-valid)", 40,
        "[REDACTED_CARD]"
    ),

    "aadhaar": PiiRule(
        "aadhaar", "Aadhaar number (Verhoeff-valid)", 30,
        "[REDACTED_AADHAAR]"
    ),
}

# ==========================================================
# Public policy endpoint
# ==========================================================

POLICY = {

    "version": POLICY_VERSION,

    "detectors": [
        "prompt_injection",
        "pii",
        "rag_injection",
    ],

    "thresholds": {
        "block_score": BLOCK_THRESHOLD,
        "transform_score": TRANSFORM_THRESHOLD,
    },

    "scoring": {
        "extra_rule_bonus": EXTRA_RULE_BONUS,
        "extra_rule_bonus_cap": EXTRA_RULE_BONUS_CAP,
    },

    "limits": {
        "max_findings_per_request": MAX_FINDINGS_PER_REQUEST,
        "on_limit_exceeded": "block",
        "limit_rule_id": LIMIT_RULE_ID,
        "incomplete_scan_prompt": INCOMPLETE_SCAN_PROMPT,
    },

    "injection_rules": [
        {
            "id": rule.id,
            "description": rule.description,
            "severity": rule.severity,
            "scopes": list(rule.scopes),
            "document_action": rule.doc_action,
        }
        for rule in INJECTION_RULES
    ],

    "pii_rules": [
        {
            "id": rule.id,
            "description": rule.description,
            "severity": rule.severity,
        }
        for rule in PII_RULES.values()
    ],
}
