import math

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.config import (
    API_DESCRIPTION,
    API_TITLE,
    API_VERSION,
    MAX_REQUEST_BODY_BYTES,
    RATE_LIMIT_BACKEND,
    RATE_LIMIT_FAIL_CLOSED,
    RATE_LIMIT_REDIS_URL,
    RATE_LIMIT_REQUESTS,
    RATE_LIMIT_WINDOW_SECONDS,
    TRUSTED_PROXIES,
)
from app.core.analyzer import analyze_request
from app.core.logger import logger
from app.core.policy import POLICY
from app.core.rate_limiter import (
    RateLimiterBackend,
    client_ip_from_request,
    create_rate_limiter,
)
from app.schemas import AnalyzeRequest, AnalyzeResponse

app = FastAPI(
    title=API_TITLE,
    version=API_VERSION,
    description=API_DESCRIPTION,
)

rate_limiter: RateLimiterBackend = create_rate_limiter(
    backend=RATE_LIMIT_BACKEND,
    max_requests=RATE_LIMIT_REQUESTS,
    window_seconds=RATE_LIMIT_WINDOW_SECONDS,
    redis_url=RATE_LIMIT_REDIS_URL,
    fail_closed=RATE_LIMIT_FAIL_CLOSED,
)

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def _reject(status_code: int, detail: str) -> JSONResponse:
    """Return a JSONResponse with security headers pre-applied."""
    return JSONResponse(
        status_code=status_code,
        content={"detail": detail},
        headers=_SECURITY_HEADERS,
    )


@app.middleware("http")
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


@app.middleware("http")
async def enforce_rate_limit(request: Request, call_next):
    """Limit requests per client IP address."""
    client = request.client
    client_id = client_ip_from_request(
        request_client_host=client.host if client is not None else None,
        forwarded_for_header=request.headers.get("x-forwarded-for"),
        trusted_proxies=TRUSTED_PROXIES,
    )

    allowed, retry_after = rate_limiter.allow(client_id)
    if not allowed:
        return JSONResponse(
            status_code=429,
            content={"detail": "Too Many Requests"},
            headers={"Retry-After": str(math.ceil(retry_after))},
        )

    return await call_next(request)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add defensive HTTP headers to API responses."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(Exception)
async def unexpected_exception_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    """Return a safe response for unexpected server errors."""
    logger.error(
        "Unhandled exception | method=%s | path=%s | exception_type=%s",
        request.method,
        request.url.path,
        type(exc).__name__,
    )

    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error"},
    )


@app.get("/policy")
def get_policy():
    """Return the active guardrails policy."""
    return POLICY


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest):
    """Analyze a prompt and optional RAG context."""
    return analyze_request(request)
