"""
Application configuration.

Keeping configuration in one place makes it easier
to modify and extend the project.

Limits can be overridden with environment variables.
"""

import os

API_TITLE = "SentraGuard Lite"

API_VERSION = "1.1.0"

API_DESCRIPTION = """
Offline AI Guardrails Gateway

Features
--------
• Prompt Injection Detection (with Unicode / encoding normalisation)
• PII Detection & Redaction (email, phone, payment card, Aadhaar)
• RAG Injection Detection (suspicious documents are quarantined)
• Risk Scoring
• Prompt & Context Sanitization

Runs completely offline.
"""


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


# Input limits (protect the regex engine from huge payloads).
MAX_PROMPT_CHARS = _int_env("GUARDRAILS_MAX_PROMPT_CHARS", 20_000)

MAX_CONTEXT_DOCS = _int_env("GUARDRAILS_MAX_CONTEXT_DOCS", 20)

MAX_DOC_CHARS = _int_env("GUARDRAILS_MAX_DOC_CHARS", 50_000)
