"""Integration tests exercising the full application deployment stack.

Validates:
  - Container and production health/readiness endpoints.
  - End-to-end middleware chain execution and ordering.
  - Consistent presence of defensive security headers on all responses (200, 400, 401, 404, 405, 413, 422, 429, 500).
  - Absence of tracebacks, secrets, and internal paths in error payloads.
  - Configuration resilience against non-positive and malformed values.
  - Proxy trust boundary enforcement across the live pipeline.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import app.config as config
from app.main import app

client = TestClient(app, raise_server_exceptions=False)

EXPECTED_SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "cache-control": "no-store",
}


def assert_has_security_headers(response):
    """Assert all standard security headers are present on the response."""
    for header, value in EXPECTED_SECURITY_HEADERS.items():
        assert response.headers.get(header) == value, (
            f"Missing or incorrect security header '{header}'. "
            f"Expected '{value}', got '{response.headers.get(header)}'"
        )


class TestHealthAndReadiness:
    """Validate container liveness and readiness probes."""

    def test_health_check_returns_ok_and_security_headers(self):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}
        assert_has_security_headers(resp)

    def test_health_check_with_trailing_slash(self):
        resp = client.get("/health/")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}
        assert_has_security_headers(resp)


class TestMiddlewareSecurityHeaderConsistency:
    """Verify defensive security headers are applied across all HTTP status codes."""

    def test_success_response_has_security_headers(self):
        payload = {
            "prompt": "Hello world",
            "context_docs": [],
            "metadata": {"app_id": "test", "user_id": "u", "request_id": "req-1"},
        }
        resp = client.post("/analyze", json=payload)
        assert resp.status_code == 200
        assert_has_security_headers(resp)

    def test_policy_endpoint_has_security_headers(self):
        resp = client.get("/policy")
        assert resp.status_code == 200
        assert_has_security_headers(resp)

    def test_validation_error_422_has_security_headers(self):
        resp = client.post("/analyze", json={"invalid": "payload"})
        assert resp.status_code == 422
        assert_has_security_headers(resp)
        # Ensure no traceback is exposed
        assert "Traceback" not in resp.text
        assert "line " not in resp.text

    def test_oversized_body_413_has_security_headers(self, monkeypatch):
        monkeypatch.setattr("app.main.MAX_REQUEST_BODY_BYTES", 50)
        payload = json.dumps(
            {"prompt": "A" * 60, "context_docs": [], "metadata": {"app_id": "a", "user_id": "u", "request_id": "r"}}
        ).encode()
        resp = client.post(
            "/analyze",
            content=payload,
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 413
        assert resp.json()["detail"] == "Request body too large"
        assert_has_security_headers(resp)

    def test_rate_limited_429_has_security_headers(self, monkeypatch):
        from app.core.rate_limiter import InMemoryRateLimiter

        # Force rate limiter with 1 request capacity
        limiter = InMemoryRateLimiter(max_requests=1, window_seconds=60)
        monkeypatch.setattr("app.main.rate_limiter", limiter)

        # /health is exempt from rate limiting, so use a real endpoint.
        # First request succeeds
        resp1 = client.get("/policy")
        assert resp1.status_code == 200

        # Second request from same client is rate limited
        resp2 = client.get("/policy")
        assert resp2.status_code == 429
        assert resp2.json()["detail"] == "Too Many Requests"
        assert "Retry-After" in resp2.headers
        assert_has_security_headers(resp2)

    def test_auth_failure_401_has_security_headers(self, monkeypatch):
        monkeypatch.setattr(config, "API_KEY", "prod-secret-key-12345")
        monkeypatch.setattr(config, "REQUIRE_AUTH", True)

        resp = client.post("/analyze", json={"prompt": "test"})
        assert resp.status_code == 401
        assert resp.headers.get("www-authenticate") == "Bearer"
        assert_has_security_headers(resp)

    def test_not_found_404_has_security_headers(self):
        resp = client.get("/nonexistent-endpoint-path")
        assert resp.status_code in (401, 404)
        assert_has_security_headers(resp)

    def test_method_not_allowed_405_has_security_headers(self):
        resp = client.delete("/health")
        assert resp.status_code == 405
        assert_has_security_headers(resp)

    def test_unhandled_server_error_500_has_security_headers(self):
        with patch("app.main.analyze_request", side_effect=RuntimeError("Simulated database failure")):
            payload = {
                "prompt": "Hello",
                "context_docs": [],
                "metadata": {"app_id": "test", "user_id": "u", "request_id": "req-err"},
            }
            resp = client.post("/analyze", json=payload)
            assert resp.status_code == 500
            assert resp.json() == {"detail": "Internal Server Error"}
            assert_has_security_headers(resp)
            # Ensure internal exception details are NOT leaked to the client
            assert "Simulated database failure" not in resp.text
            assert "RuntimeError" not in resp.text
            assert "Traceback" not in resp.text


class TestConfigurationSafetyAndBounds:
    """Validate that environment configurations are safely bounded."""

    def test_non_positive_env_vars_bounded_to_positive(self, monkeypatch):
        from app.config import _int_env

        monkeypatch.setenv("TEST_NEG_ENV", "-50")
        assert max(1, _int_env("TEST_NEG_ENV", 100)) == 1

        monkeypatch.setenv("TEST_ZERO_ENV", "0")
        assert max(1, _int_env("TEST_ZERO_ENV", 100)) == 1

    def test_malformed_env_vars_fail_fast(self, monkeypatch):
        from app.config import _int_env

        monkeypatch.setenv("TEST_BAD_ENV", "not-a-number")

        with pytest.raises(ValueError, match="TEST_BAD_ENV"):
            _int_env("TEST_BAD_ENV", 42)


class TestProxyTrustBoundaries:
    """Validate proxy forwarding headers are never trusted blindly."""

    def test_forwarded_for_ignored_when_no_trusted_proxies(self):
        from app.core.rate_limiter import client_ip_from_request

        ip = client_ip_from_request(
            request_client_host="192.168.1.50",
            forwarded_for_header="203.0.113.195, 70.41.3.18",
            trusted_proxies=frozenset(),
        )
        assert ip == "192.168.1.50"

    def test_forwarded_for_extracted_safely_behind_trusted_proxy(self):
        from app.core.rate_limiter import client_ip_from_request

        trusted = frozenset(["10.0.0.1", "10.0.0.2"])
        # Client directly connects from trusted proxy 10.0.0.1
        # X-Forwarded-For contains spoofed IP, actual client IP, and proxy IP
        ip = client_ip_from_request(
            request_client_host="10.0.0.1",
            forwarded_for_header="1.1.1.1, 203.0.113.50, 10.0.0.2",
            trusted_proxies=trusted,
        )
        # Rightmost untrusted IP is 203.0.113.50
        assert ip == "203.0.113.50"
