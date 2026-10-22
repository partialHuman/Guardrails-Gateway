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
\u2022 Prompt Injection Detection (with Unicode / encoding normalisation)
\u2022 PII Detection & Redaction (email, phone, payment card, Aadhaar)
\u2022 RAG Injection Detection (suspicious documents are quarantined)
\u2022 Risk Scoring
\u2022 Prompt & Context Sanitization

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

# Maximum raw HTTP request-body size in bytes.
# Requests exceeding this limit are rejected with HTTP 413 before the body is
# fully buffered, preventing unbounded memory consumption.
# The default (1 MiB) is generous for the prompt + context payload that
# schema limits already constrain to ~1 MB of field data.
MAX_REQUEST_BODY_BYTES = max(
    1,
    _int_env("GUARDRAILS_MAX_REQUEST_BODY_BYTES", 1_048_576),  # 1 MiB
)

# API rate limiting (per client, per process).
RATE_LIMIT_REQUESTS = max(
    1,
    _int_env("GUARDRAILS_RATE_LIMIT_REQUESTS", 60),
)

RATE_LIMIT_WINDOW_SECONDS = max(
    1,
    _int_env("GUARDRAILS_RATE_LIMIT_WINDOW_SECONDS", 60),
)
