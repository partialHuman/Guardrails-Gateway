import math
import re
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware

import app.config as config
from app.config import (
    API_DESCRIPTION,
    API_TITLE,
    API_VERSION,
    AUTH_FAILURE_LIMIT_REQUESTS,
    AUTH_FAILURE_WINDOW_SECONDS,
    MAX_REQUEST_BODY_BYTES,
    RATE_LIMIT_BACKEND,
    RATE_LIMIT_FAIL_CLOSED,
    RATE_LIMIT_MAX_CLIENTS,
    RATE_LIMIT_REDIS_TIMEOUT_SECONDS,
    RATE_LIMIT_REDIS_URL,
    RATE_LIMIT_REQUESTS,
    RATE_LIMIT_WINDOW_SECONDS,
    TRUSTED_PROXIES,
)
from app.core.analyzer import analyze_request
from app.core.auth import (
    auth_is_misconfigured,
    auth_misconfigured_response,
    auth_startup_warnings,
    auth_unauthorized_response,
    extract_api_key,
    is_public_path,
    validate_auth_config,
    verify_api_key,
)
from app.core.logger import logger, sanitize_for_log
from app.core.policy import POLICY
from app.core.rate_limiter import (
    RateLimiterBackend,
    client_ip_from_request,
    create_rate_limiter,
    rate_limit_key,
)
from app.schemas import AnalyzeRequest, AnalyzeResponse


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Validate configuration on application startup."""
    validate_auth_config(
        config.REQUIRE_AUTH,
        config.API_KEY,
        config.ALLOW_ANONYMOUS,
    )

    for warning in auth_startup_warnings(
        config.REQUIRE_AUTH,
        config.API_KEY,
        config.ALLOW_ANONYMOUS,
    ):
        logger.warning(warning)

    yield


# ---------------------------------------------------------------------------
# Rate limiters
# ---------------------------------------------------------------------------

# General per-client request quota. Applied to AUTHENTICATED (or anonymous,
# when auth is disabled) traffic only, after authentication.
rate_limiter: RateLimiterBackend = create_rate_limiter(
    backend=RATE_LIMIT_BACKEND,
    max_requests=RATE_LIMIT_REQUESTS,
    window_seconds=RATE_LIMIT_WINDOW_SECONDS,
    redis_url=RATE_LIMIT_REDIS_URL,
    fail_closed=RATE_LIMIT_FAIL_CLOSED,
    redis_timeout=RATE_LIMIT_REDIS_TIMEOUT_SECONDS,
    max_clients=RATE_LIMIT_MAX_CLIENTS,
)

# Counts FAILED authentication attempts only. Junk traffic therefore cannot
# use up a legitimate client's request quota, yet guessing a key is throttled.
auth_failure_limiter: RateLimiterBackend = create_rate_limiter(
    backend=RATE_LIMIT_BACKEND,
    max_requests=AUTH_FAILURE_LIMIT_REQUESTS,
    window_seconds=AUTH_FAILURE_WINDOW_SECONDS,
    redis_url=RATE_LIMIT_REDIS_URL,
    fail_closed=RATE_LIMIT_FAIL_CLOSED,
    prefix="guardrails:auth_failure:",
    redis_timeout=RATE_LIMIT_REDIS_TIMEOUT_SECONDS,
    max_clients=RATE_LIMIT_MAX_CLIENTS,
)

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}

# Only well-formed ids are echoed back; anything else is replaced.
_REQUEST_ID_PATTERN = re.compile(r"[A-Za-z0-9._:-]{1,64}")

_HEALTH_PATH = "/health"


def _reject(status_code: int, detail: str) -> JSONResponse:
    """Return a JSONResponse with security headers pre-applied."""
    return JSONResponse(
        status_code=status_code,
        content={"detail": detail},
        headers=_SECURITY_HEADERS,
    )


def _request_id_of(request: Request) -> str:
    """The id assigned to this request (or a fresh one if none was set)."""
    return getattr(request.state, "request_id", None) or uuid.uuid4().hex


def _client_key(request: Request) -> str:
    """Rate-limit key for the caller (proxy-aware, IPv6 collapsed to /64)."""
    client = request.client

    identity = client_ip_from_request(
        request_client_host=client.host if client is not None else None,
        forwarded_for_header=request.headers.get("x-forwarded-for"),
        trusted_proxies=TRUSTED_PROXIES,
    )

    return rate_limit_key(identity)


async def _allow(limiter: RateLimiterBackend, key: str) -> tuple[bool, float]:
    """Consult a limiter without blocking the event loop.

    Network-backed limiters (Redis) are run in a worker thread; the
    in-memory limiter is cheap enough to call inline.
    """
    if getattr(limiter, "blocking", False):
        return await run_in_threadpool(limiter.allow, key)

    return limiter.allow(key)


def _too_many_requests(retry_after: float) -> JSONResponse:
    return JSONResponse(
        status_code=429,
        content={"detail": "Too Many Requests"},
        headers={"Retry-After": str(math.ceil(retry_after))},
    )


# ---------------------------------------------------------------------------
# Middleware
#
# ORDER MATTERS and is declared explicitly in MIDDLEWARE below, outermost
# first. A request travels top to bottom; a response travels back up:
#
#   1. assign_request_id         every response, including errors, gets X-Request-ID
#   2. add_security_headers      every response gets the defensive headers
#   3. enforce_authentication    401 / 429 (failed-auth limiter) / 500 (misconfigured)
#   4. enforce_rate_limit        429 per client (/health is exempt)
#   5. enforce_request_body_size 400 / 413 before the route reads the body
#
# (Decorating with @app.middleware made the LAST decorator the outermost,
# which is how rate limiting silently ended up before authentication.)
# ---------------------------------------------------------------------------


async def assign_request_id(request: Request, call_next):
    """Give every request a correlation id and return it as X-Request-ID."""
    inbound = request.headers.get("x-request-id")

    request_id = (
        inbound
        if inbound and _REQUEST_ID_PATTERN.fullmatch(inbound)
        else uuid.uuid4().hex
    )

    request.state.request_id = request_id

    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


async def add_security_headers(request: Request, call_next):
    """Add defensive HTTP headers to API responses."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


async def enforce_authentication(request: Request, call_next):
    """Enforce API-key authentication for protected endpoints.

    Public paths (health checks and documentation) are exempt.
    All other routes are protected by default (default-deny).

    Only FAILED attempts are counted (against ``auth_failure_limiter``), so
    unauthenticated junk cannot exhaust a valid client's request quota, and
    brute-forcing a key is still throttled.
    """
    path = request.url.path

    # 1. Exempt public paths (e.g. /health, /docs, /redoc, /openapi.json)
    if is_public_path(path, config.PUBLIC_PATHS):
        return await call_next(request)

    # 2. Fail-safe: if authentication is required but misconfigured, fail closed
    if auth_is_misconfigured(
        config.REQUIRE_AUTH,
        config.API_KEY,
        config.ALLOW_ANONYMOUS,
    ):
        logger.error(
            "Authentication required but no API key configured | request_id=%s | method=%s | path=%s",
            _request_id_of(request),
            request.method,
            sanitize_for_log(path),
        )
        return auth_misconfigured_response()

    # 3. If authentication is not enabled (local development), allow request
    auth_enabled = config.REQUIRE_AUTH or bool(config.API_KEY)
    if not auth_enabled:
        return await call_next(request)

    # 4. Verify credentials
    provided_key = extract_api_key(request)
    if verify_api_key(provided_key, config.API_KEY):
        return await call_next(request)

    # 5. Failed attempt: throttle repeated failures per client
    allowed, retry_after = await _allow(auth_failure_limiter, _client_key(request))

    logger.warning(
        "Authentication failed | request_id=%s | method=%s | path=%s",
        _request_id_of(request),
        request.method,
        sanitize_for_log(path),
    )

    if not allowed:
        return _too_many_requests(retry_after)

    return auth_unauthorized_response()


async def enforce_rate_limit(request: Request, call_next):
    """Limit requests per client address.

    ``/health`` is exempt: orchestrators probe it constantly and it does no
    work, so a probe must never be able to fail because of a rate limit.
    """
    if request.url.path.rstrip("/") == _HEALTH_PATH:
        return await call_next(request)

    allowed, retry_after = await _allow(rate_limiter, _client_key(request))
    if not allowed:
        return _too_many_requests(retry_after)

    return await call_next(request)


async def enforce_request_body_size(request: Request, call_next):
    """Reject requests whose body exceeds MAX_REQUEST_BODY_BYTES.

    Two independent checks are applied so that neither alone can be bypassed:

    1. Content-Length header – fast rejection before any body bytes are read.
       Malformed or negative values are also rejected.
    2. Streaming byte-count cap – enforced while reading the body regardless
       of what Content-Length declared, preventing unbounded memory use from
       chunked or lying Content-Length requests.

    After a successful bounded read the body is cached on the Request object
    (``request._body``) so that downstream middleware and route handlers can
    call ``await request.body()`` or ``await request.json()`` normally.
    """
    # --- Check 1: Content-Length header (fast path; not trusted alone) ---
    content_length_header = request.headers.get("content-length")
    if content_length_header is not None:
        try:
            declared_length = int(content_length_header)
        except ValueError:
            return _reject(400, "Malformed Content-Length header")

        if declared_length < 0:
            return _reject(400, "Malformed Content-Length header")

        if declared_length > MAX_REQUEST_BODY_BYTES:
            return _reject(413, "Request body too large")

    # --- Check 2: Streaming cap (enforced regardless of Content-Length) ---
    # Accumulate chunks up to the limit + 1 byte so we can detect overflow
    # without buffering the entire oversized body.
    body_chunks: list[bytes] = []
    total_bytes = 0

    async for chunk in request.stream():
        total_bytes += len(chunk)
        if total_bytes > MAX_REQUEST_BODY_BYTES:
            return _reject(413, "Request body too large")
        body_chunks.append(chunk)

    # Cache the validated body so downstream reads (request.body() /
    # request.json()) work normally. Starlette's stream() yields _body
    # directly when this attribute is set, so no double-read occurs.
    request._body = b"".join(body_chunks)  # type: ignore[attr-defined]

    return await call_next(request)


# Outermost first. See the comment block above.
MIDDLEWARE = [
    Middleware(BaseHTTPMiddleware, dispatch=assign_request_id),
    Middleware(BaseHTTPMiddleware, dispatch=add_security_headers),
    Middleware(BaseHTTPMiddleware, dispatch=enforce_authentication),
    Middleware(BaseHTTPMiddleware, dispatch=enforce_rate_limit),
    Middleware(BaseHTTPMiddleware, dispatch=enforce_request_body_size),
]

app = FastAPI(
    title=API_TITLE,
    version=API_VERSION,
    description=API_DESCRIPTION,
    lifespan=lifespan,
    middleware=MIDDLEWARE,
)


@app.exception_handler(Exception)
async def unexpected_exception_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    """Return a safe response for unexpected server errors."""
    request_id = _request_id_of(request)

    logger.error(
        "Unhandled exception | request_id=%s | method=%s | path=%s | exception_type=%s",
        request_id,
        request.method,
        sanitize_for_log(request.url.path),
        type(exc).__name__,
    )

    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error"},
        headers={**_SECURITY_HEADERS, "X-Request-ID": request_id},
    )


@app.get("/health")
def health():
    """Health check endpoint for container orchestrators."""
    return {"status": "ok"}


@app.get("/policy")
def get_policy():
    """Return the active guardrails policy."""
    return POLICY


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest):
    """Analyze a prompt and optional RAG context."""
    return analyze_request(request)
