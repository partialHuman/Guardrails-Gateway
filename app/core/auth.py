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
    return secrets.compare_digest(provided_key, expected_key)


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


def validate_auth_config(require_auth: bool, api_key: str) -> None:
    """Validate server authentication configuration at startup.

    Raises:
        RuntimeError: If authentication is required but no key is configured.
    """
    if require_auth and not api_key:
        raise RuntimeError(
            "GUARDRAILS_REQUIRE_AUTH is set to true, but GUARDRAILS_API_KEY is empty or not configured. "
            "The gateway will not run unauthenticated when authentication is required."
        )
