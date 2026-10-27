"""Comprehensive tests for API authentication.

Covers:
  - Auth disabled by default (backward compatibility for local dev and tests)
  - Valid credentials via X-API-Key and Authorization: Bearer headers
  - Rejection of missing, invalid, and malformed credentials with HTTP 401
  - Rejection of query parameter credentials (header-only enforcement)
  - Constant-time secret comparison
  - Endpoint protection boundaries: public vs protected vs default-deny
  - Security headers and WWW-Authenticate on 401 responses
  - Secret leakage prevention in responses and log output
  - Fail-safe behavior when authentication is required but misconfigured
  - Configuration parsing and lifespan validation
"""

from __future__ import annotations

import json
import logging
import sys
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import app.config as config
from app.core.auth import (
    DEFAULT_PUBLIC_EXACT,
    DEFAULT_PUBLIC_PREFIXES,
    auth_misconfigured_response,
    auth_unauthorized_response,
    extract_api_key,
    is_public_path,
    validate_auth_config,
    verify_api_key,
)
from app.main import app

client = TestClient(app)

DUMMY_SECRET = "sentraguard-test-secret-key-12345"
META = {"app_id": "test-app", "user_id": "test-user", "request_id": "req-auth-test"}
VALID_ANALYZE_BODY = {"prompt": "Hello world", "context_docs": [], "metadata": META}

EXPECTED_SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "cache-control": "no-store",
    "www-authenticate": "Bearer",
}


@pytest.fixture
def enable_auth(monkeypatch):
    """Enable authentication with a dummy secret key."""
    monkeypatch.setattr(config, "API_KEY", DUMMY_SECRET)
    monkeypatch.setattr(config, "REQUIRE_AUTH", True)


# ====================================================================
# 1. Backward compatibility (default state)
# ====================================================================


class TestAuthDisabledByDefault:
    """When unconfigured, local dev and test consumers are not broken."""

    def test_unauthenticated_requests_succeed_when_auth_disabled(self):
        assert config.API_KEY == ""
        assert config.REQUIRE_AUTH is False

        response = client.post("/analyze", json=VALID_ANALYZE_BODY)
        assert response.status_code == 200

    def test_policy_accessible_without_auth_by_default(self):
        response = client.get("/policy")
        assert response.status_code == 200

    def test_health_accessible_by_default(self):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


# ====================================================================
# 2. Header extraction and credential verification
# ====================================================================


class TestAuthenticationHeaders:
    """Tests for X-API-Key and Authorization: Bearer headers."""

    def test_valid_x_api_key_header_allows_analyze(self, enable_auth):
        response = client.post(
            "/analyze",
            json=VALID_ANALYZE_BODY,
            headers={"X-API-Key": DUMMY_SECRET},
        )
        assert response.status_code == 200
        assert response.json()["decision"] == "allow"

    def test_valid_x_api_key_header_allows_policy(self, enable_auth):
        response = client.get("/policy", headers={"X-API-Key": DUMMY_SECRET})
        assert response.status_code == 200

    def test_valid_bearer_authorization_header_allows_analyze(self, enable_auth):
        response = client.post(
            "/analyze",
            json=VALID_ANALYZE_BODY,
            headers={"Authorization": f"Bearer {DUMMY_SECRET}"},
        )
        assert response.status_code == 200

    def test_case_insensitive_bearer_scheme(self, enable_auth):
        response = client.post(
            "/analyze",
            json=VALID_ANALYZE_BODY,
            headers={"Authorization": f"bearer {DUMMY_SECRET}"},
        )
        assert response.status_code == 200

        response_upper = client.post(
            "/analyze",
            json=VALID_ANALYZE_BODY,
            headers={"Authorization": f"BEARER {DUMMY_SECRET}"},
        )
        assert response_upper.status_code == 200

    def test_missing_credentials_rejected_with_401(self, enable_auth):
        response = client.post("/analyze", json=VALID_ANALYZE_BODY)
        assert response.status_code == 401
        assert response.json() == {"detail": "Unauthorized"}

    def test_invalid_x_api_key_rejected_with_401(self, enable_auth):
        response = client.post(
            "/analyze",
            json=VALID_ANALYZE_BODY,
            headers={"X-API-Key": "wrong-secret-key"},
        )
        assert response.status_code == 401
        assert response.json() == {"detail": "Unauthorized"}

    def test_invalid_bearer_token_rejected_with_401(self, enable_auth):
        response = client.post(
            "/analyze",
            json=VALID_ANALYZE_BODY,
            headers={"Authorization": "Bearer wrong-token-value"},
        )
        assert response.status_code == 401
        assert response.json() == {"detail": "Unauthorized"}

    def test_empty_x_api_key_rejected_with_401(self, enable_auth):
        response = client.post(
            "/analyze",
            json=VALID_ANALYZE_BODY,
            headers={"X-API-Key": ""},
        )
        assert response.status_code == 401

    def test_whitespace_x_api_key_rejected_with_401(self, enable_auth):
        response = client.post(
            "/analyze",
            json=VALID_ANALYZE_BODY,
            headers={"X-API-Key": "   "},
        )
        assert response.status_code == 401

    def test_empty_bearer_token_rejected_with_401(self, enable_auth):
        response = client.post(
            "/analyze",
            json=VALID_ANALYZE_BODY,
            headers={"Authorization": "Bearer "},
        )
        assert response.status_code == 401

    @pytest.mark.parametrize(
        "auth_header",
        [
            "Basic dXNlcjpwYXNz",
            "Token some-token",
            "Digest username=abc",
            "Bearer",
            "Bearer token1 token2 extra",
            "UnknownScheme",
        ],
    )
    def test_malformed_auth_headers_rejected_with_401(self, enable_auth, auth_header):
        response = client.post(
            "/analyze",
            json=VALID_ANALYZE_BODY,
            headers={"Authorization": auth_header},
        )
        assert response.status_code == 401
        assert response.json() == {"detail": "Unauthorized"}

    def test_query_parameter_credentials_are_rejected(self, enable_auth):
        """Query parameters must never be accepted for credential delivery."""
        response = client.post(
            f"/analyze?api_key={DUMMY_SECRET}",
            json=VALID_ANALYZE_BODY,
        )
        assert response.status_code == 401
        assert response.json() == {"detail": "Unauthorized"}


# ====================================================================
# 3. Constant-time comparison
# ====================================================================


class TestConstantTimeVerification:
    """Tests for verify_api_key constant-time comparison helper."""

    def test_matching_keys_return_true(self):
        assert verify_api_key("exact-match-token", "exact-match-token") is True

    def test_mismatched_keys_return_false(self):
        assert verify_api_key("token-a", "token-b") is False

    @pytest.mark.parametrize(
        ("provided", "expected"),
        [
            (None, "expected-key"),
            ("", "expected-key"),
            ("provided-key", ""),
            (None, ""),
            ("", ""),
        ],
    )
    def test_empty_or_none_keys_return_false(self, provided, expected):
        assert verify_api_key(provided, expected) is False

    def test_uses_secrets_compare_digest_on_bytes(self):
        # Bytes, not str: compare_digest(str, str) raises TypeError for
        # non-ASCII input, which used to surface as an HTTP 500.
        with patch("secrets.compare_digest", return_value=True) as mock_digest:
            result = verify_api_key("key-a", "key-b")
            assert result is True
            mock_digest.assert_called_once_with(b"key-a", b"key-b")

    @pytest.mark.parametrize(
        "provided",
        ["é", "clé-secrète-x", "\xff\xfe", "日本語", "\ud800"],
    )
    def test_non_ascii_credentials_are_rejected_not_raised(self, provided):
        assert verify_api_key(provided, "a-perfectly-normal-key") is False

    def test_non_ascii_key_still_verifies_when_correct(self):
        assert verify_api_key("clé-secrète-9", "clé-secrète-9") is True


# ====================================================================
# 4. Endpoint protection strategy
# ====================================================================


class TestEndpointProtectionStrategy:
    """Verify public endpoints vs protected endpoints (default-deny)."""

    def test_health_check_is_public_when_auth_enabled(self, enable_auth):
        """Orchestrator health probes must succeed without credentials."""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    def test_health_check_with_trailing_slash_is_public(self, enable_auth):
        response = client.get("/health/")
        assert response.status_code == 200

    @pytest.mark.parametrize("docs_path", ["/docs", "/redoc", "/openapi.json"])
    def test_documentation_endpoints_are_public_when_auth_enabled(
        self, enable_auth, docs_path
    ):
        response = client.get(docs_path)
        assert response.status_code == 200

    def test_docs_oauth2_redirect_is_public(self, enable_auth):
        response = client.get("/docs/oauth2-redirect")
        assert response.status_code == 200

    def test_policy_endpoint_requires_auth_when_enabled(self, enable_auth):
        """Rules, thresholds, and severities must be protected from unauthenticated snooping."""
        unauthed = client.get("/policy")
        assert unauthed.status_code == 401

        authed = client.get("/policy", headers={"X-API-Key": DUMMY_SECRET})
        assert authed.status_code == 200

    def test_analyze_endpoint_requires_auth_when_enabled(self, enable_auth):
        unauthed = client.post("/analyze", json=VALID_ANALYZE_BODY)
        assert unauthed.status_code == 401

        authed = client.post(
            "/analyze",
            json=VALID_ANALYZE_BODY,
            headers={"X-API-Key": DUMMY_SECRET},
        )
        assert authed.status_code == 200

    def test_unknown_routes_rejected_with_401_without_credentials(self, enable_auth):
        """Default-deny prevents unauthenticated route enumeration."""
        response = client.get("/non-existent-endpoint-reconnaissance")
        assert response.status_code == 401
        assert response.json() == {"detail": "Unauthorized"}

    def test_unknown_routes_return_404_with_valid_credentials(self, enable_auth):
        """Authenticated callers get normal 404 for missing routes."""
        response = client.get(
            "/non-existent-endpoint-reconnaissance",
            headers={"X-API-Key": DUMMY_SECRET},
        )
        assert response.status_code == 404
        assert response.json() == {"detail": "Not Found"}


# ====================================================================
# 5. Security headers on authentication failures
# ====================================================================


class TestSecurityHeadersOnAuthFailure:
    """Verify security headers are applied to 401 responses."""

    def test_security_headers_present_on_401(self, enable_auth):
        response = client.post("/analyze", json=VALID_ANALYZE_BODY)
        assert response.status_code == 401

        for header_name, expected_val in EXPECTED_SECURITY_HEADERS.items():
            assert response.headers.get(header_name) == expected_val, (
                f"Missing or mismatched header {header_name}: got {response.headers.get(header_name)}"
            )

    def test_security_headers_present_on_invalid_key_401(self, enable_auth):
        response = client.post(
            "/analyze",
            json=VALID_ANALYZE_BODY,
            headers={"X-API-Key": "invalid"},
        )
        assert response.status_code == 401
        for header_name, expected_val in EXPECTED_SECURITY_HEADERS.items():
            assert response.headers.get(header_name) == expected_val


# ====================================================================
# 6. Secret leakage prevention
# ====================================================================


class TestSecretLeakagePrevention:
    """Verify raw secrets and tokens are never leaked in responses or logs."""

    def test_no_secret_in_401_response(self, enable_auth):
        attacker_attempt = "attacker-injected-token-probe"
        response = client.post(
            "/analyze",
            json=VALID_ANALYZE_BODY,
            headers={"X-API-Key": attacker_attempt},
        )
        assert response.status_code == 401
        body_text = response.text.lower()

        assert DUMMY_SECRET.lower() not in body_text
        assert attacker_attempt.lower() not in body_text
        assert "traceback" not in body_text
        assert "site-packages" not in body_text

    def test_no_secrets_in_logs_on_failed_auth(self, enable_auth, caplog):
        attacker_attempt = "attacker-raw-secret-token"
        with caplog.at_level(logging.WARNING, logger="sentraguard"):
            response = client.post(
                "/analyze",
                json=VALID_ANALYZE_BODY,
                headers={"X-API-Key": attacker_attempt},
            )
            assert response.status_code == 401

        log_output = caplog.text
        assert "Authentication failed" in log_output
        assert attacker_attempt not in log_output
        assert DUMMY_SECRET not in log_output

    def test_no_secrets_in_logs_on_bearer_auth_failure(self, enable_auth, caplog):
        attacker_bearer = "bearer-secret-token-attempt"
        with caplog.at_level(logging.WARNING, logger="sentraguard"):
            response = client.post(
                "/analyze",
                json=VALID_ANALYZE_BODY,
                headers={"Authorization": f"Bearer {attacker_bearer}"},
            )
            assert response.status_code == 401

        log_output = caplog.text
        assert attacker_bearer not in log_output
        assert DUMMY_SECRET not in log_output


# ====================================================================
# 7. Fail-safe configuration behavior
# ====================================================================


class TestFailSafeConfiguration:
    """Verify safe behavior when auth is required but key is missing/invalid."""

    def test_validate_auth_config_raises_when_required_and_key_empty(self):
        with pytest.raises(RuntimeError, match="GUARDRAILS_REQUIRE_AUTH is set to true"):
            validate_auth_config(require_auth=True, api_key="")

    def test_validate_auth_config_succeeds_when_not_required(self):
        validate_auth_config(require_auth=False, api_key="")

    def test_validate_auth_config_succeeds_when_key_present(self):
        validate_auth_config(require_auth=True, api_key=DUMMY_SECRET)

    def test_middleware_fails_closed_with_500_when_key_missing_in_production(
        self, monkeypatch, caplog
    ):
        monkeypatch.setattr(config, "REQUIRE_AUTH", True)
        monkeypatch.setattr(config, "API_KEY", "")

        with caplog.at_level(logging.ERROR, logger="sentraguard"):
            response = client.post("/analyze", json=VALID_ANALYZE_BODY)

        assert response.status_code == 500
        assert response.json() == {"detail": "Internal Server Error"}
        assert "Authentication required but no API key configured" in caplog.text

        # Verify security headers are present on misconfiguration response
        assert response.headers.get("x-content-type-options") == "nosniff"
        assert response.headers.get("x-frame-options") == "DENY"

    def test_public_endpoints_still_work_when_auth_misconfigured(self, monkeypatch):
        """Health check still responds so orchestrators know the node is alive."""
        monkeypatch.setattr(config, "REQUIRE_AUTH", True)
        monkeypatch.setattr(config, "API_KEY", "")

        response = client.get("/health")
        assert response.status_code == 200

    def test_lifespan_aborts_startup_when_auth_misconfigured(self, monkeypatch):
        monkeypatch.setattr(config, "REQUIRE_AUTH", True)
        monkeypatch.setattr(config, "API_KEY", "")

        from app.main import lifespan

        with pytest.raises(RuntimeError, match="GUARDRAILS_REQUIRE_AUTH is set to true"):
            with TestClient(app):
                pass


# ====================================================================
# 8. Path helpers and config overrides
# ====================================================================


class TestPathHelpersAndConfig:
    """Tests for public path resolution and config environment variables."""

    def test_is_public_path_with_custom_paths(self):
        custom = frozenset({"/custom-public", "/health"})
        assert is_public_path("/custom-public", custom) is True
        assert is_public_path("/health", custom) is True
        assert is_public_path("/docs", custom) is False
        assert is_public_path("/analyze", custom) is False

    def test_is_public_path_default_exact(self):
        assert is_public_path("/health") is True
        assert is_public_path("/health/") is True
        assert is_public_path("/") is False

    def test_is_public_path_default_prefixes(self):
        assert is_public_path("/docs") is True
        assert is_public_path("/docs/oauth2-redirect") is True
        assert is_public_path("/redoc") is True
        assert is_public_path("/openapi.json") is True
        assert is_public_path("/policy") is False
        assert is_public_path("/analyze") is False

    def test_config_env_vars_parsing(self, monkeypatch):
        import importlib
        import app.config as cfg

        monkeypatch.setenv("GUARDRAILS_API_KEY", "  env-key-123  ")
        monkeypatch.setenv("GUARDRAILS_REQUIRE_AUTH", "true")
        monkeypatch.setenv("GUARDRAILS_PUBLIC_PATHS", "/health, /metrics")

        importlib.reload(cfg)
        try:
            assert cfg.API_KEY == "env-key-123"
            assert cfg.REQUIRE_AUTH is True
            assert cfg.PUBLIC_PATHS == frozenset({"/health", "/metrics"})
        finally:
            monkeypatch.delenv("GUARDRAILS_API_KEY", raising=False)
            monkeypatch.delenv("GUARDRAILS_REQUIRE_AUTH", raising=False)
            monkeypatch.delenv("GUARDRAILS_PUBLIC_PATHS", raising=False)
            importlib.reload(cfg)

    def test_config_empty_public_paths(self, monkeypatch):
        import importlib
        import app.config as cfg

        monkeypatch.setenv("GUARDRAILS_PUBLIC_PATHS", "")
        importlib.reload(cfg)
        try:
            assert cfg.PUBLIC_PATHS is None
        finally:
            monkeypatch.delenv("GUARDRAILS_PUBLIC_PATHS", raising=False)
            importlib.reload(cfg)


# ====================================================================
# 9. CLI integration
# ====================================================================


class TestCliAuthentication:
    """Test CLI parameter support for API keys without requiring requests installed."""

    @pytest.fixture
    def mock_requests(self, monkeypatch):
        """Provide a mock requests module so CLI tests run in headless/minimal CI environments."""
        class MockConnectionError(Exception):
            pass

        class MockHTTPError(Exception):
            def __init__(self, *args, response=None, **kwargs):
                super().__init__(*args, **kwargs)
                self.response = response

        fake_requests = MagicMock()
        fake_exceptions = MagicMock()
        fake_exceptions.ConnectionError = MockConnectionError
        fake_exceptions.HTTPError = MockHTTPError
        fake_requests.exceptions = fake_exceptions

        monkeypatch.setitem(sys.modules, "requests", fake_requests)
        monkeypatch.setitem(sys.modules, "requests.exceptions", fake_exceptions)

        if "cli" in sys.modules:
            monkeypatch.delitem(sys.modules, "cli")

        return fake_requests

    def test_cli_sends_api_key_header(self, monkeypatch, mock_requests):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "decision": "allow",
            "risk_score": 0,
            "risk_tags": [],
            "sanitized_prompt": "test prompt",
            "sanitized_context_docs": [],
            "quarantined_doc_ids": [],
            "reasons": [],
        }
        mock_response.raise_for_status.return_value = None
        mock_requests.post.return_value = mock_response

        import cli

        monkeypatch.setattr(
            "sys.argv",
            ["cli.py", "--prompt", "Hello", "--api-key", DUMMY_SECRET],
        )
        cli.main()

        assert mock_requests.post.called
        _, kwargs = mock_requests.post.call_args
        assert "headers" in kwargs
        assert kwargs["headers"].get("X-API-Key") == DUMMY_SECRET

    def test_cli_uses_api_key_from_env(self, monkeypatch, mock_requests):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "decision": "allow",
            "risk_score": 0,
            "risk_tags": [],
            "sanitized_prompt": "test prompt",
            "sanitized_context_docs": [],
            "quarantined_doc_ids": [],
            "reasons": [],
        }
        mock_response.raise_for_status.return_value = None
        mock_requests.post.return_value = mock_response

        monkeypatch.setenv("GUARDRAILS_API_KEY", DUMMY_SECRET)
        monkeypatch.setattr(
            "sys.argv",
            ["cli.py", "--prompt", "Hello"],
        )

        import cli

        cli.main()

        assert mock_requests.post.called
        _, kwargs = mock_requests.post.call_args
        assert kwargs["headers"].get("X-API-Key") == DUMMY_SECRET

    def test_cli_handles_401_unauthorized(self, monkeypatch, mock_requests, capsys):
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_requests.post.return_value = mock_response
        mock_response.raise_for_status.side_effect = mock_requests.exceptions.HTTPError(
            "401 Client Error: Unauthorized", response=mock_response
        )

        import cli

        monkeypatch.setattr(
            "sys.argv",
            ["cli.py", "--prompt", "Hello", "--api-key", "wrong-key"],
        )
        with pytest.raises(SystemExit) as excinfo:
            cli.main()

        assert excinfo.value.code == 1
        captured = capsys.readouterr()
        assert "Authentication failed (401 Unauthorized)" in captured.out
