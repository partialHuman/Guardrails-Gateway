"""SG-004: failed-auth throttling, /health exemption, and auth-before-quota ordering."""

import pytest
from fastapi.testclient import TestClient

import app.config as config
from app import main
from app.core.rate_limiter import InMemoryRateLimiter
from app.main import app

KEY = "tiered-limits-test-key-0123456789"

ANALYZE = {
    "prompt": "hello",
    "context_docs": [],
    "metadata": {"app_id": "t", "user_id": "u", "request_id": "r-1"},
}


@pytest.fixture
def secured(monkeypatch):
    """Auth on; small, known quotas: 3 requests / 2 failed attempts."""
    monkeypatch.setattr(config, "API_KEY", KEY)
    monkeypatch.setattr(config, "REQUIRE_AUTH", True)
    monkeypatch.setattr(main, "rate_limiter", InMemoryRateLimiter(3, 60))
    monkeypatch.setattr(main, "auth_failure_limiter", InMemoryRateLimiter(2, 60))
    return TestClient(app)


def _auth(key=KEY):
    return {"X-API-Key": key}


def test_junk_requests_do_not_consume_a_valid_clients_quota(secured):
    # Two bad attempts are answered 401, the third is throttled...
    statuses = [secured.post("/analyze", json=ANALYZE).status_code for _ in range(3)]
    assert statuses == [401, 401, 429]

    # ...but the SAME client can still use its own valid key: the junk never
    # touched the general request quota (it used to, which locked out
    # legitimate users behind a shared address).
    assert secured.post("/analyze", json=ANALYZE, headers=_auth()).status_code == 200


def test_valid_requests_are_still_limited_by_the_general_quota(secured):
    statuses = [
        secured.post("/analyze", json=ANALYZE, headers=_auth()).status_code
        for _ in range(4)
    ]

    assert statuses == [200, 200, 200, 429]


def test_valid_credentials_are_never_subject_to_the_failure_limiter(secured):
    for _ in range(2):
        assert secured.post("/analyze", json=ANALYZE).status_code == 401

    # Failure budget is exhausted, yet a valid key passes straight through.
    for _ in range(2):
        assert secured.post("/analyze", json=ANALYZE, headers=_auth()).status_code == 200


def test_failure_throttle_returns_retry_after(secured):
    for _ in range(2):
        secured.post("/analyze", json=ANALYZE)

    response = secured.post("/analyze", json=ANALYZE)

    assert response.status_code == 429
    assert int(response.headers["Retry-After"]) >= 1
    assert response.json() == {"detail": "Too Many Requests"}


def test_failure_quota_is_per_client(secured):
    for _ in range(3):
        secured.post("/analyze", json=ANALYZE)

    other = TestClient(app, client=("203.0.113.77", 40000))

    assert other.post("/analyze", json=ANALYZE).status_code == 401


def test_health_is_exempt_from_rate_limiting(monkeypatch):
    monkeypatch.setattr(main, "rate_limiter", InMemoryRateLimiter(1, 60))
    client = TestClient(app)

    assert [client.get("/health").status_code for _ in range(10)] == [200] * 10
    assert client.get("/health/").status_code in (200, 307)

    # ...while any other endpoint is still limited.
    assert client.get("/policy").status_code == 200
    assert client.get("/policy").status_code == 429


def test_health_probe_succeeds_even_when_the_client_is_throttled(monkeypatch):
    monkeypatch.setattr(main, "rate_limiter", InMemoryRateLimiter(1, 60))
    client = TestClient(app)

    client.get("/policy")
    assert client.get("/policy").status_code == 429
    assert client.get("/health").status_code == 200


def test_unauthenticated_request_never_reaches_the_general_limiter(monkeypatch):
    """Behavioural proof of middleware order: authentication runs first."""
    monkeypatch.setattr(config, "API_KEY", KEY)
    monkeypatch.setattr(config, "REQUIRE_AUTH", True)

    class Spy:
        blocking = False
        calls = 0

        def allow(self, client_id):
            Spy.calls += 1
            return True, 0.0

    monkeypatch.setattr(main, "rate_limiter", Spy())
    client = TestClient(app)

    assert client.post("/analyze", json=ANALYZE).status_code == 401
    assert Spy.calls == 0

    assert client.post("/analyze", json=ANALYZE, headers=_auth()).status_code == 200
    assert Spy.calls == 1


@pytest.mark.parametrize("blocking, expect_threadpool", [(True, True), (False, False)])
def test_blocking_limiters_are_run_off_the_event_loop(
    monkeypatch, blocking, expect_threadpool
):
    offloaded = []

    async def spy(function, *args):
        offloaded.append(function)
        return function(*args)

    class Limiter:
        def allow(self, client_id):
            return True, 0.0

    limiter = Limiter()
    limiter.blocking = blocking

    monkeypatch.setattr(main, "rate_limiter", limiter)
    monkeypatch.setattr(main, "run_in_threadpool", spy)

    assert TestClient(app).get("/policy").status_code == 200
    assert bool(offloaded) is expect_threadpool


def test_anonymous_mode_still_applies_the_general_limiter(monkeypatch):
    monkeypatch.setattr(config, "API_KEY", "")
    monkeypatch.setattr(config, "REQUIRE_AUTH", False)
    monkeypatch.setattr(main, "rate_limiter", InMemoryRateLimiter(2, 60))
    client = TestClient(app)

    assert [client.get("/policy").status_code for _ in range(3)] == [200, 200, 429]
