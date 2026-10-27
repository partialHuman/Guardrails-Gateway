"""
Application configuration.

Keeping configuration in one place makes it easier
to modify and extend the project.

Limits can be overridden with environment variables.

Parsing is STRICT: an unparseable or out-of-range value raises ConfigError
at import time and the application refuses to start. Silently falling back
to a default is dangerous for security settings (for example
``GUARDRAILS_REQUIRE_AUTH=on`` used to be read as "false" and leave the
gateway unauthenticated without any warning).
"""

import ipaddress
import os

API_TITLE = "SentraGuard Lite"

API_VERSION = "1.2.0"

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


class ConfigError(ValueError):
    """An environment setting is invalid; the application must not start."""


_TRUE_VALUES = frozenset({"true", "1", "yes", "on", "y", "t"})

_FALSE_VALUES = frozenset({"false", "0", "no", "off", "n", "f"})


def _raw(name: str) -> str | None:
    """Return the stripped value, or None when unset/blank (use the default)."""

    value = os.getenv(name)

    if value is None or not value.strip():
        return None

    return value.strip()


def _bool_env(name: str, default: bool) -> bool:
    value = _raw(name)

    if value is None:
        return default

    lowered = value.lower()

    if lowered in _TRUE_VALUES:
        return True

    if lowered in _FALSE_VALUES:
        return False

    raise ConfigError(
        f"{name} must be a boolean (true/false, 1/0, yes/no, on/off), got {value!r}"
    )


def _int_env(name: str, default: int, minimum: int | None = None) -> int:
    value = _raw(name)

    if value is None:
        return default

    try:
        number = int(value)
    except ValueError:
        raise ConfigError(f"{name} must be an integer, got {value!r}") from None

    if minimum is not None and number < minimum:
        raise ConfigError(f"{name} must be >= {minimum}, got {number}")

    return number


def _float_env(name: str, default: float, minimum: float | None = None) -> float:
    value = _raw(name)

    if value is None:
        return default

    try:
        number = float(value)
    except ValueError:
        raise ConfigError(f"{name} must be a number, got {value!r}") from None

    if number != number or number in (float("inf"), float("-inf")):
        raise ConfigError(f"{name} must be a finite number, got {value!r}")

    if minimum is not None and number < minimum:
        raise ConfigError(f"{name} must be >= {minimum}, got {number}")

    return number


# Input limits (protect the regex engine from huge payloads).
MAX_PROMPT_CHARS = _int_env("GUARDRAILS_MAX_PROMPT_CHARS", 20_000, minimum=1)

MAX_CONTEXT_DOCS = _int_env("GUARDRAILS_MAX_CONTEXT_DOCS", 20, minimum=1)

MAX_DOC_CHARS = _int_env("GUARDRAILS_MAX_DOC_CHARS", 50_000, minimum=1)

# Maximum raw HTTP request-body size in bytes.
# Requests exceeding this limit are rejected with HTTP 413 before the body is
# fully buffered, preventing unbounded memory consumption.
# The default (1 MiB) is generous for the prompt + context payload that
# schema limits already constrain to ~1 MB of field data.
MAX_REQUEST_BODY_BYTES = _int_env(
    "GUARDRAILS_MAX_REQUEST_BODY_BYTES", 1_048_576, minimum=1  # 1 MiB
)

# API rate limiting (per client).
RATE_LIMIT_REQUESTS = _int_env("GUARDRAILS_RATE_LIMIT_REQUESTS", 60, minimum=1)

RATE_LIMIT_WINDOW_SECONDS = _int_env(
    "GUARDRAILS_RATE_LIMIT_WINDOW_SECONDS", 60, minimum=1
)

# Maximum distinct clients tracked by the in-memory limiter. Beyond this,
# new clients share one overflow bucket, so memory stays bounded even if an
# attacker rotates through millions of source addresses (e.g. an IPv6 /64).
RATE_LIMIT_MAX_CLIENTS = _int_env(
    "GUARDRAILS_RATE_LIMIT_MAX_CLIENTS", 50_000, minimum=100
)

# Failed-authentication limiter. Only FAILED attempts count against it, so
# junk traffic can no longer use up a legitimate client's request quota,
# while brute-forcing a key is still throttled.
AUTH_FAILURE_LIMIT_REQUESTS = _int_env(
    "GUARDRAILS_AUTH_FAILURE_LIMIT_REQUESTS", 10, minimum=1
)

AUTH_FAILURE_WINDOW_SECONDS = _int_env(
    "GUARDRAILS_AUTH_FAILURE_WINDOW_SECONDS", 60, minimum=1
)

# API rate limiting backend ("memory" or "redis").
RATE_LIMIT_BACKEND = (
    _raw("GUARDRAILS_RATE_LIMIT_BACKEND") or "memory"
).lower()

if RATE_LIMIT_BACKEND not in ("memory", "redis"):
    raise ConfigError(
        "GUARDRAILS_RATE_LIMIT_BACKEND must be 'memory' or 'redis', "
        f"got {RATE_LIMIT_BACKEND!r}"
    )

# Optional Redis connection URL for distributed rate limiting.
RATE_LIMIT_REDIS_URL = os.getenv("GUARDRAILS_RATE_LIMIT_REDIS_URL", "")

# Redis connect/read timeout. Without one, an unreachable Redis can stall
# every request for the OS TCP timeout.
RATE_LIMIT_REDIS_TIMEOUT_SECONDS = _float_env(
    "GUARDRAILS_RATE_LIMIT_REDIS_TIMEOUT_SECONDS", 0.25, minimum=0.01
)

# Shared backend failure mode:
# If False (default), fail open (allow requests) when Redis is unreachable.
# If True, fail closed (deny requests) when Redis is unreachable.
RATE_LIMIT_FAIL_CLOSED = _bool_env("GUARDRAILS_RATE_LIMIT_FAIL_CLOSED", False)

# Trusted reverse-proxy addresses for X-Forwarded-For extraction.
# Comma-separated list of IP addresses and/or CIDR networks
# (e.g. "10.0.0.1,172.18.0.0/16,fd00::/8").
# When empty (default), X-Forwarded-For is NEVER trusted and the TCP
# peer address (request.client.host) is always used for rate limiting.
_raw_trusted = os.getenv("GUARDRAILS_TRUSTED_PROXIES", "")

TRUSTED_PROXIES: frozenset[str] = frozenset(
    addr.strip() for addr in _raw_trusted.split(",") if addr.strip()
)

for _entry in TRUSTED_PROXIES:
    try:
        ipaddress.ip_network(_entry, strict=False)
    except ValueError:
        raise ConfigError(
            "GUARDRAILS_TRUSTED_PROXIES entries must be IP addresses or CIDR "
            f"networks, got {_entry!r}"
        ) from None

# API authentication.
# Secret API key for authenticating incoming requests.
# In local development, leaving this empty allows unauthenticated access.
API_KEY: str = os.getenv("GUARDRAILS_API_KEY", "").strip()

# Whether authentication is mandatory (recommended in production).
# If True and API_KEY is empty, the gateway refuses to start.
REQUIRE_AUTH: bool = _bool_env("GUARDRAILS_REQUIRE_AUTH", False)

# Whether the gateway may run with NO authentication at all.
# The code default is True so local development works with zero setup; the
# Docker image and docker-compose.yml set it to False, so a container never
# starts unauthenticated unless the operator opts in explicitly.
ALLOW_ANONYMOUS: bool = _bool_env("GUARDRAILS_ALLOW_ANONYMOUS", True)

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

if PUBLIC_PATHS is not None:
    for _path in PUBLIC_PATHS:
        if not _path.startswith("/"):
            raise ConfigError(
                f"GUARDRAILS_PUBLIC_PATHS entries must start with '/', got {_path!r}"
            )
