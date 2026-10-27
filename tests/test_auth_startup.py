"""SG-002: the gateway does not silently run unauthenticated."""

import pytest
from fastapi.testclient import TestClient

import app.config as config
from app.core.auth import (
    auth_is_misconfigured,
    auth_startup_warnings,
    validate_auth_config,
)
from app.main import app

GOOD_KEY = "a-long-random-key-0123456789abcdef"


@pytest.mark.parametrize(
    "require, key, allow, misconfigured",
    [
        (False, "", True, False),    # local development: anonymous allowed
        (False, "", False, True),    # container default: refuse without a key
        (True, "", True, True),      # auth required, key missing
        (True, "", False, True),
        (False, GOOD_KEY, False, False),
        (True, GOOD_KEY, True, False),
    ],
)
def test_auth_is_misconfigured_truth_table(require, key, allow, misconfigured):
    assert auth_is_misconfigured(require, key, allow) is misconfigured


def test_validate_refuses_missing_key_when_anonymous_not_allowed():
    with pytest.raises(RuntimeError, match="GUARDRAILS_ALLOW_ANONYMOUS"):
        validate_auth_config(False, "", False)


def test_validate_allows_anonymous_only_when_explicitly_permitted():
    validate_auth_config(False, "", True)


def test_validate_still_refuses_require_auth_without_key():
    with pytest.raises(RuntimeError, match="GUARDRAILS_REQUIRE_AUTH"):
        validate_auth_config(True, "", True)


def test_warning_when_authentication_is_disabled():
    warnings = auth_startup_warnings(False, "", True)

    assert len(warnings) == 1
    assert "DISABLED" in warnings[0]


def test_warning_for_short_key_never_contains_the_key():
    key = "short-key"

    warnings = auth_startup_warnings(False, key, True)

    assert len(warnings) == 1
    assert "shorter than" in warnings[0]
    assert key not in warnings[0]


def test_no_warnings_for_a_strong_key():
    assert auth_startup_warnings(True, GOOD_KEY, False) == []


def test_application_refuses_to_start_unauthenticated_when_not_allowed(monkeypatch):
    monkeypatch.setattr(config, "API_KEY", "")
    monkeypatch.setattr(config, "REQUIRE_AUTH", False)
    monkeypatch.setattr(config, "ALLOW_ANONYMOUS", False)

    with pytest.raises(RuntimeError, match="anonymous access is not allowed"):
        with TestClient(app):
            pass


def test_startup_logs_a_loud_warning_in_anonymous_mode(monkeypatch, caplog):
    monkeypatch.setattr(config, "API_KEY", "")
    monkeypatch.setattr(config, "REQUIRE_AUTH", False)
    monkeypatch.setattr(config, "ALLOW_ANONYMOUS", True)

    with caplog.at_level("WARNING", logger="sentraguard"):
        with TestClient(app):
            pass

    assert "Authentication is DISABLED" in caplog.text


def test_requests_fail_closed_if_startup_validation_was_skipped(monkeypatch):
    # TestClient without ``with`` never runs the lifespan, so the middleware
    # must independently refuse to serve protected routes.
    monkeypatch.setattr(config, "API_KEY", "")
    monkeypatch.setattr(config, "REQUIRE_AUTH", False)
    monkeypatch.setattr(config, "ALLOW_ANONYMOUS", False)
    client = TestClient(app)

    response = client.get("/policy")

    assert response.status_code == 500
    assert response.json() == {"detail": "Internal Server Error"}

    # Public health probes keep working.
    assert client.get("/health").status_code == 200
