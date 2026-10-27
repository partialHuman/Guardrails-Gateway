"""API-key authentication for SentraGuard Lite.

Provides constant-time API-key verification, header extraction (X-API-Key
and Authorization: Bearer), route exemption checks, and fail-safe behavior
for production deployments.
"""

from __future__ import annotations

import secrets
from fastapi import Request
from fastapi.responses import JSONResponse

from app.core.logger import logger

_AUTH_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "WWW-Authenticate": "Bearer",
}

DEFAULT_PUBLIC_PREFIXES = ("/docs", "/redoc", "/openapi.json")
DEFAULT_PUBLIC_EXACT = frozenset({"/health"})


def extract_api_key(request: Request) -> str | None:
    """Extract an API key from request headers.

    Checks:
    1. X-API-Key header
    2. Authorization: Bearer <key> header

    Query parameters are intentionally NEVER checked to avoid credential
    exposure in access logs, browser history, and proxy telemetry.
    """
    api_key = request.headers.get("x-api-key")
    if api_key is not None:
        key = api_key.strip()
        if key:
            return key

    auth_header = request.headers.get("authorization")
    if auth_header is not None:
        parts = auth_header.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            key = parts[1].strip()
            if key:
                return key

    return None


def verify_api_key(provided_key: str | None, expected_key: str) -> bool:
    """Perform constant-time comparison between provided and expected keys.

    Protects against timing side-channel attacks.
    """
    if not provided_key or not expected_key:
        return False

    # Compare BYTES, not str: secrets.compare_digest(str, str) raises
    # TypeError for non-ASCII input, which turned a bad credential into an
    # HTTP 500 (and a logged traceback) instead of a clean 401.
    return secrets.compare_digest(
        provided_key.encode("utf-8", "surrogatepass"),
        expected_key.encode("utf-8", "surrogatepass"),
    )


def is_public_path(path: str, public_paths: frozenset[str] | None = None) -> bool:
    """Check whether a request path is exempt from authentication.

    By default, `/health`, `/docs`, `/redoc`, and `/openapi.json` are public.
    All other endpoints (including `/analyze`, `/policy`, and unknown routes)
    require authentication when enabled (default-deny).
    """
    normalized = path.rstrip("/") or "/"
    if public_paths is not None:
        return normalized in public_paths

    if normalized in DEFAULT_PUBLIC_EXACT:
        return True

    return any(
        normalized == prefix or normalized.startswith(f"{prefix}/")
        for prefix in DEFAULT_PUBLIC_PREFIXES
    )


def auth_unauthorized_response() -> JSONResponse:
    """Return a standard 401 Unauthorized response with defensive headers."""
    return JSONResponse(
        status_code=401,
        content={"detail": "Unauthorized"},
        headers=_AUTH_SECURITY_HEADERS,
    )


def auth_misconfigured_response() -> JSONResponse:
    """Return a 500 response when authentication is required but misconfigured.

    Fails safe: protected routes are refused rather than served unauthenticated.
    """
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error"},
        headers={
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store",
        },
    )


MIN_RECOMMENDED_KEY_CHARS = 16


def auth_is_misconfigured(
    require_auth: bool,
    api_key: str,
    allow_anonymous: bool = True,
) -> bool:
    """True when the gateway must NOT serve protected routes.

    That is the case when authentication is demanded (explicitly via
    REQUIRE_AUTH, or implicitly because anonymous access was not allowed)
    but no API key is configured.
    """
    return (require_auth or not allow_anonymous) and not api_key


def validate_auth_config(
    require_auth: bool,
    api_key: str,
    allow_anonymous: bool = True,
) -> None:
    """Validate server authentication configuration at startup.

    Raises:
        RuntimeError: If authentication is required but no key is configured,
            or if anonymous access is not allowed and no key is configured.
    """
    if require_auth and not api_key:
        raise RuntimeError(
            "GUARDRAILS_REQUIRE_AUTH is set to true, but GUARDRAILS_API_KEY is empty or not configured. "
            "The gateway will not run unauthenticated when authentication is required."
        )

    if not allow_anonymous and not api_key:
        raise RuntimeError(
            "No GUARDRAILS_API_KEY is configured and anonymous access is not allowed "
            "(GUARDRAILS_ALLOW_ANONYMOUS=false). Set GUARDRAILS_API_KEY, or set "
            "GUARDRAILS_ALLOW_ANONYMOUS=true to run without authentication (local development only)."
        )


def auth_startup_warnings(
    require_auth: bool,
    api_key: str,
    allow_anonymous: bool = True,
) -> list[str]:
    """Human-readable warnings to log once at startup (never contain the key)."""
    warnings: list[str] = []

    if not (require_auth or api_key):
        warnings.append(
            "Authentication is DISABLED: every endpoint, including /analyze and /policy, "
            "answers anonymous requests. Set GUARDRAILS_API_KEY before exposing this service."
        )
    elif api_key and len(api_key) < MIN_RECOMMENDED_KEY_CHARS:
        warnings.append(
            f"GUARDRAILS_API_KEY is shorter than {MIN_RECOMMENDED_KEY_CHARS} characters; "
            "use a long random value (e.g. python -c \"import secrets; print(secrets.token_urlsafe(32))\")."
        )

    return warnings
