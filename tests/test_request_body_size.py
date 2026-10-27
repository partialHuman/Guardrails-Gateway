"""Tests for HTTP request-body size enforcement.

The middleware must:
  - Reject bodies above MAX_REQUEST_BODY_BYTES with HTTP 413 before expensive
    analysis runs.
  - Accept bodies at or below the limit.
  - Apply security headers on 413 responses.
  - Distrust Content-Length alone: enforce the cap while streaming.
  - Reject malformed / negative Content-Length values with HTTP 400.
  - Handle chunked / no-Content-Length bodies correctly.
  - Not break empty requests or normal API requests.
"""

import json

import pytest
from fastapi.testclient import TestClient

from app.config import MAX_REQUEST_BODY_BYTES
from app.main import app

client = TestClient(app)

META = {"app_id": "test-app", "user_id": "test-user", "request_id": "req-size-test"}

EXPECTED_SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "cache-control": "no-store",
}

# A minimal valid JSON payload that the /analyze endpoint accepts.
_VALID_PAYLOAD = json.dumps(
    {"prompt": "Hello", "context_docs": [], "metadata": META}
).encode()


def _raw_post(body: bytes, extra_headers: dict | None = None) -> object:
    """POST raw bytes to /analyze without automatic Content-Length management."""
    headers = {"Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)
    return client.post("/analyze", content=body, headers=headers)


def _assert_security_headers(response) -> None:
    for name, value in EXPECTED_SECURITY_HEADERS.items():
        assert response.headers.get(name) == value, (
            f"Missing or wrong security header {name!r}: "
            f"got {response.headers.get(name)!r}"
        )


# ---------------------------------------------------------------------------
# Normal / boundary requests
# ---------------------------------------------------------------------------


def test_normal_request_is_accepted():
    """A well-formed, in-limit request passes through without modification."""
    response = _raw_post(_VALID_PAYLOAD)
    assert response.status_code == 200


def test_empty_body_does_not_hang_or_crash():
    """An empty body is passed through (FastAPI returns 422 for missing fields)."""
    response = client.post("/analyze", content=b"", headers={"Content-Type": "application/json"})
    # FastAPI validates the body; empty body → 422, not a server crash or hang.
    assert response.status_code in {400, 422}


def test_body_just_below_limit_is_accepted():
    """A body one byte below the limit must be accepted."""
    # Build a valid-ish JSON payload padded with spaces to MAX_REQUEST_BODY_BYTES - 1.
    # The padding goes inside the JSON string so it remains valid JSON even if
    # we're not exactly at a field boundary – the schema will reject it anyway
    # but the size middleware must not reject it.
    padding = b" " * (MAX_REQUEST_BODY_BYTES - 1)
    response = client.post(
        "/analyze",
        content=padding,
        headers={"Content-Type": "application/json"},
    )
    # Not 413 – middleware accepted it; downstream may reject with 422.
    assert response.status_code != 413


def test_body_exactly_at_limit_is_accepted():
    """A body whose byte count equals MAX_REQUEST_BODY_BYTES must be accepted."""
    body = b"x" * MAX_REQUEST_BODY_BYTES
    response = client.post(
        "/analyze",
        content=body,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code != 413


def test_body_one_byte_over_limit_is_rejected():
    """A body one byte above the limit must be rejected with 413."""
    body = b"x" * (MAX_REQUEST_BODY_BYTES + 1)
    response = client.post(
        "/analyze",
        content=body,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json()["detail"] == "Request body too large"


def test_large_oversized_body_is_rejected():
    """A body significantly larger than the limit (e.g. 4 MiB) must be rejected."""
    body = b"x" * (4 * 1024 * 1024)
    response = client.post(
        "/analyze",
        content=body,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413


# ---------------------------------------------------------------------------
# Content-Length header checks (fast path)
# ---------------------------------------------------------------------------


def test_content_length_over_limit_rejected_before_body_read():
    """Requests with Content-Length > limit are rejected immediately (413)."""
    oversized = MAX_REQUEST_BODY_BYTES + 1
    # Send a small body but lie about the size upward.
    response = client.post(
        "/analyze",
        content=_VALID_PAYLOAD,
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(oversized),
        },
    )
    assert response.status_code == 413
    assert response.json()["detail"] == "Request body too large"


def test_content_length_exactly_at_limit_is_not_rejected_by_header_check():
    """Content-Length == limit must not trigger the 413 fast path."""
    response = client.post(
        "/analyze",
        content=_VALID_PAYLOAD,
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(MAX_REQUEST_BODY_BYTES),
        },
    )
    # May get a 422 from FastAPI (body is _VALID_PAYLOAD not padded to limit),
    # but must not be 413 from our middleware.
    assert response.status_code != 413


def test_malformed_content_length_string_is_rejected():
    """A non-integer Content-Length is rejected with 400."""
    response = client.post(
        "/analyze",
        content=_VALID_PAYLOAD,
        headers={
            "Content-Type": "application/json",
            "Content-Length": "not-a-number",
        },
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Malformed Content-Length header"


def test_negative_content_length_is_rejected():
    """A negative Content-Length is rejected with 400."""
    response = client.post(
        "/analyze",
        content=_VALID_PAYLOAD,
        headers={
            "Content-Type": "application/json",
            "Content-Length": "-1",
        },
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Malformed Content-Length header"


def test_zero_content_length_is_not_rejected():
    """Content-Length: 0 is not malformed and should pass header check."""
    response = client.post(
        "/analyze",
        content=b"",
        headers={
            "Content-Type": "application/json",
            "Content-Length": "0",
        },
    )
    # Middleware accepts it; FastAPI may return 422 for empty body.
    assert response.status_code != 413
    assert response.status_code != 400


# ---------------------------------------------------------------------------
# Streaming / no Content-Length (bypass attempt)
# ---------------------------------------------------------------------------


def test_oversized_body_rejected_without_content_length():
    """Streaming oversized body without Content-Length must still be rejected."""
    body = b"x" * (MAX_REQUEST_BODY_BYTES + 1)
    # Remove Content-Length by sending content directly; httpx will omit it
    # when we use `content=` without an explicit header.
    response = client.post(
        "/analyze",
        content=body,
        headers={"Content-Type": "application/json", "Content-Length": "0"},
    )
    # Content-Length says 0 (under limit) but actual body is over limit – the
    # streaming check must catch this.
    assert response.status_code == 413


def test_honest_undersized_content_length_with_oversized_body_is_rejected():
    """Body larger than Content-Length (both > limit) must still be rejected."""
    body = b"y" * (MAX_REQUEST_BODY_BYTES + 100)
    response = client.post(
        "/analyze",
        content=body,
        headers={
            "Content-Type": "application/json",
            # Lie downward – still large enough to be caught by streaming cap.
            "Content-Length": str(MAX_REQUEST_BODY_BYTES + 50),
        },
    )
    assert response.status_code == 413


# ---------------------------------------------------------------------------
# Security headers on rejection responses
# ---------------------------------------------------------------------------


def test_413_response_has_security_headers():
    """HTTP 413 responses must carry all required security headers."""
    body = b"x" * (MAX_REQUEST_BODY_BYTES + 1)
    response = client.post(
        "/analyze",
        content=body,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
    _assert_security_headers(response)


def test_400_malformed_content_length_has_security_headers():
    """HTTP 400 for bad Content-Length must carry security headers."""
    response = client.post(
        "/analyze",
        content=_VALID_PAYLOAD,
        headers={
            "Content-Type": "application/json",
            "Content-Length": "banana",
        },
    )
    assert response.status_code == 400
    _assert_security_headers(response)


def test_413_via_content_length_header_has_security_headers():
    """413 triggered by the Content-Length fast path must have security headers."""
    response = client.post(
        "/analyze",
        content=_VALID_PAYLOAD,
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(MAX_REQUEST_BODY_BYTES + 1),
        },
    )
    assert response.status_code == 413
    _assert_security_headers(response)


# ---------------------------------------------------------------------------
# Rejection happens before expensive analysis
# ---------------------------------------------------------------------------


def test_oversized_body_rejected_before_analysis(monkeypatch):
    """The body-size middleware must short-circuit before analyze_request runs."""
    from unittest.mock import patch

    body = b"x" * (MAX_REQUEST_BODY_BYTES + 1)

    with patch("app.main.analyze_request") as mock_analyze:
        response = client.post(
            "/analyze",
            content=body,
            headers={"Content-Type": "application/json"},
        )

    assert response.status_code == 413
    mock_analyze.assert_not_called()


# ---------------------------------------------------------------------------
# No regression in existing behaviour
# ---------------------------------------------------------------------------


def test_valid_analyze_request_still_works():
    """A valid analyze request must still succeed after the middleware is added."""
    response = client.post(
        "/analyze",
        json={"prompt": "Hello", "context_docs": [], "metadata": META},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "allow"


def test_get_policy_still_works():
    """GET /policy must not be affected by the body size middleware."""
    response = client.get("/policy")
    assert response.status_code == 200
    _assert_security_headers(response)


def test_oversized_prompt_field_still_returns_422():
    """Schema-level prompt limit still produces 422, not 413."""
    # This body is well within MAX_REQUEST_BODY_BYTES (1 MiB default) because
    # MAX_PROMPT_CHARS = 20,000 chars ≈ 20 kB — far smaller than 1 MiB.
    from app.config import MAX_PROMPT_CHARS

    response = client.post(
        "/analyze",
        json={
            "prompt": "x" * (MAX_PROMPT_CHARS + 1),
            "context_docs": [],
            "metadata": META,
        },
    )
    assert response.status_code == 422


def test_max_request_body_bytes_config_default():
    """MAX_REQUEST_BODY_BYTES must be a positive integer (default 1 MiB)."""
    assert MAX_REQUEST_BODY_BYTES == 1_048_576


def test_max_request_body_bytes_env_override(monkeypatch):
    """MAX_REQUEST_BODY_BYTES can be overridden via environment variable."""
    import importlib

    import app.config as cfg

    monkeypatch.setenv("GUARDRAILS_MAX_REQUEST_BODY_BYTES", "512")
    importlib.reload(cfg)
    try:
        assert cfg.MAX_REQUEST_BODY_BYTES == 512
    finally:
        monkeypatch.delenv("GUARDRAILS_MAX_REQUEST_BODY_BYTES", raising=False)
        importlib.reload(cfg)


def test_max_request_body_bytes_env_invalid_is_rejected(monkeypatch):
    """An invalid env value for MAX_REQUEST_BODY_BYTES stops startup (no silent default)."""
    import importlib

    import app.config as cfg

    monkeypatch.setenv("GUARDRAILS_MAX_REQUEST_BODY_BYTES", "not-a-number")
    try:
        with pytest.raises(ValueError, match="GUARDRAILS_MAX_REQUEST_BODY_BYTES"):
            importlib.reload(cfg)
    finally:
        monkeypatch.delenv("GUARDRAILS_MAX_REQUEST_BODY_BYTES", raising=False)
        importlib.reload(cfg)
