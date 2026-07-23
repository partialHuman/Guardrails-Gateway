"""
Central policy configuration.

Contains:
- Detection patterns
- Risk scores
- Decision thresholds
"""

# ==========================================================
# Prompt Injection Patterns
# ==========================================================

PROMPT_INJECTION_PATTERNS = [

    "ignore previous instructions",

    "ignore all previous instructions",

    "forget previous instructions",

    "forget your instructions",

    "ignore system prompt",

    "reveal system prompt",

    "show system prompt",

    "developer mode",

    "act as dan",

    "bypass safety",

    "override instructions",

    "ignore safeguards",

    "disable guardrails",

]

# ==========================================================
# RAG Injection Patterns
# ==========================================================

RAG_INJECTION_PATTERNS = [

    "system:",

    "developer:",

    "assistant:",

    "override policy",

    "ignore guidelines",

    "execute hidden prompt",

    "ignore all rules",

]

# ==========================================================
# Risk Scores
# ==========================================================

PROMPT_INJECTION_SCORE = 50

RAG_INJECTION_SCORE = 40

PII_SCORE = 15

# ==========================================================
# Decision Thresholds
# ==========================================================

BLOCK_THRESHOLD = 80

TRANSFORM_THRESHOLD = 40

# ==========================================================
# Public Policy Endpoint
# ==========================================================

POLICY = {

    "version": "1",

    "detectors": [

        "prompt_injection",

        "pii",

        "rag_injection"

    ],

    "thresholds": {

        "block_score": BLOCK_THRESHOLD,

        "transform_score": TRANSFORM_THRESHOLD

    }

}