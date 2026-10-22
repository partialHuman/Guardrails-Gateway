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
MAX_PROMPT_CHARS = max(1, _int_env("GUARDRAILS_MAX_PROMPT_CHARS", 20_000))

MAX_CONTEXT_DOCS = max(1, _int_env("GUARDRAILS_MAX_CONTEXT_DOCS", 20))

MAX_DOC_CHARS = max(1, _int_env("GUARDRAILS_MAX_DOC_CHARS", 50_000))

# Maximum raw HTTP request-body size in bytes.
# Requests exceeding this limit are rejected with HTTP 413 before the body is
# fully buffered, preventing unbounded memory consumption.
# The default (1 MiB) is generous for the prompt + context payload that
# schema limits already constrain to ~1 MB of field data.
MAX_REQUEST_BODY_BYTES = max(
    1,
    _int_env("GUARDRAILS_MAX_REQUEST_BODY_BYTES", 1_048_576),  # 1 MiB
)

# API rate limiting (per client).
RATE_LIMIT_REQUESTS = max(
    1,
    _int_env("GUARDRAILS_RATE_LIMIT_REQUESTS", 60),
)

RATE_LIMIT_WINDOW_SECONDS = max(
    1,
    _int_env("GUARDRAILS_RATE_LIMIT_WINDOW_SECONDS", 60),
)

# API rate limiting backend ("memory" or "redis").
RATE_LIMIT_BACKEND = os.getenv("GUARDRAILS_RATE_LIMIT_BACKEND", "memory")

# Optional Redis connection URL for distributed rate limiting.
RATE_LIMIT_REDIS_URL = os.getenv("GUARDRAILS_RATE_LIMIT_REDIS_URL", "")

# Shared backend failure mode:
# If False (default), fail open (allow requests) when Redis is unreachable.
# If True, fail closed (deny requests) when Redis is unreachable.
RATE_LIMIT_FAIL_CLOSED = os.getenv(
    "GUARDRAILS_RATE_LIMIT_FAIL_CLOSED", "false"
).lower() in ("true", "1", "yes")

# Trusted reverse-proxy addresses for X-Forwarded-For extraction.
# Comma-separated list of IP addresses (e.g. "10.0.0.1,10.0.0.2").
# When empty (default), X-Forwarded-For is NEVER trusted and the TCP
# peer address (request.client.host) is always used for rate limiting.
_raw_trusted = os.getenv("GUARDRAILS_TRUSTED_PROXIES", "")
TRUSTED_PROXIES: frozenset[str] = frozenset(
    addr.strip() for addr in _raw_trusted.split(",") if addr.strip()
)

# API authentication.
# Secret API key for authenticating incoming requests.
# In local development, leaving this empty allows unauthenticated access.
API_KEY: str = os.getenv("GUARDRAILS_API_KEY", "").strip()

# Whether authentication is mandatory (recommended in production).
# If True and API_KEY is empty, the gateway fails safe on startup and
# rejects protected requests with HTTP 500 rather than running unauthenticated.
REQUIRE_AUTH: bool = os.getenv(
    "GUARDRAILS_REQUIRE_AUTH", "false"
).lower() in ("true", "1", "yes")

# Explicit public endpoint override (comma-separated paths).
# When empty (default), /health, /docs, /redoc, and /openapi.json are public.
_raw_public_paths = os.getenv("GUARDRAILS_PUBLIC_PATHS", "")
PUBLIC_PATHS: frozenset[str] | None = (
    frozenset(
        p.strip().rstrip("/") or "/"
        for p in _raw_public_paths.split(",")
        if p.strip()
    )
    if _raw_public_paths.strip()
    else None
)
