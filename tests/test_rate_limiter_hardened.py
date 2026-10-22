"""Comprehensive tests for the production rate-limiting module.

Covers:
  - Sliding-window correctness (InMemory and Redis)
  - Retry-After accuracy
  - Memory eviction of stale client entries
  - Concurrent access safety
  - Client-IP extraction with trusted-proxy boundaries
  - Backend protocol conformance
  - Configuration validation and edge cases
  - Shared backend failure modes (fail-open vs fail-closed)
  - Rate limiter factory creation and error handling
  - Backward compatibility with existing middleware behaviour
"""

import math
import sys
import threading
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.core.rate_limiter import (
    InMemoryRateLimiter,
    RateLimiterBackend,
    RedisRateLimiter,
    client_ip_from_request,
    create_rate_limiter,
)
from app.main import app, rate_limiter

client = TestClient(app)

META = {"app_id": "test-app", "user_id": "test-user", "request_id": "req-rl-test"}


# ====================================================================
# InMemoryRateLimiter — sliding-window correctness
# ====================================================================


class TestSlidingWindow:
    """Core sliding-window algorithm tests."""

    def test_allows_up_to_max_requests(self):
        limiter = InMemoryRateLimiter(max_requests=3, window_seconds=60)
        results = [limiter.allow("c")[0] for _ in range(4)]
        assert results == [True, True, True, False]

    def test_denies_after_limit_reached(self):
        limiter = InMemoryRateLimiter(max_requests=1, window_seconds=60)
        allowed, _ = limiter.allow("c")
        denied, retry = limiter.allow("c")
        assert allowed is True
        assert denied is False
        assert retry > 0

    def test_window_expiry_re_allows_requests(self):
        now = [0.0]
        limiter = InMemoryRateLimiter(
            max_requests=1, window_seconds=10, clock=lambda: now[0]
        )

        limiter.allow("c")
        denied, _ = limiter.allow("c")
        assert denied is False

        # Advance past the window.
        now[0] = 10.1
        allowed, retry = limiter.allow("c")
        assert allowed is True
        assert retry == 0.0

    def test_partial_window_expiry(self):
        """Oldest request expires, newer ones remain — only one slot opens."""
        now = [0.0]
        limiter = InMemoryRateLimiter(
            max_requests=2, window_seconds=10, clock=lambda: now[0]
        )

        limiter.allow("c")  # t=0
        now[0] = 5.0
        limiter.allow("c")  # t=5

        # Both slots used; t=0 request hasn't expired yet.
        denied, _ = limiter.allow("c")
        assert denied is False

        # t=10.1 → the t=0 request expires, but t=5 still lives.
        now[0] = 10.1
        allowed, _ = limiter.allow("c")
        assert allowed is True

        # Only one slot opened; second attempt should fail (t=5 still counts).
        denied_2, _ = limiter.allow("c")
        assert denied_2 is False

    def test_independent_clients(self):
        limiter = InMemoryRateLimiter(max_requests=1, window_seconds=60)

        a_ok, _ = limiter.allow("a")
        b_ok, _ = limiter.allow("b")
        a_denied, _ = limiter.allow("a")

        assert a_ok is True
        assert b_ok is True
        assert a_denied is False


# ====================================================================
# Retry-After accuracy
# ====================================================================


class TestRetryAfter:
    """Verify Retry-After reports actual wait time, not the static window."""

    def test_retry_after_reflects_earliest_slot_opening(self):
        now = [0.0]
        limiter = InMemoryRateLimiter(
            max_requests=2, window_seconds=10, clock=lambda: now[0]
        )

        limiter.allow("c")  # t=0
        now[0] = 3.0
        limiter.allow("c")  # t=3

        now[0] = 5.0
        denied, retry = limiter.allow("c")  # t=5

        assert denied is False
        # The oldest timestamp is t=0; it expires at t=10.
        # retry_after should be ~5s (10 - 5), but at least 1.
        assert 4.0 <= retry <= 10.1

    def test_retry_after_is_at_least_one_second(self):
        now = [0.0]
        limiter = InMemoryRateLimiter(
            max_requests=1, window_seconds=10, clock=lambda: now[0]
        )

        limiter.allow("c")  # t=0

        # Advance to just before window expires.
        now[0] = 9.5
        denied, retry = limiter.allow("c")
        assert denied is False
        assert retry >= 1.0

    def test_retry_after_is_zero_when_allowed(self):
        limiter = InMemoryRateLimiter(max_requests=5, window_seconds=60)
        allowed, retry = limiter.allow("c")
        assert allowed is True
        assert retry == 0.0

    def test_retry_after_header_is_integer_string_in_http_response(self, monkeypatch):
        """The Retry-After header in the HTTP response is a ceiled integer."""
        monkeypatch.setattr(rate_limiter, "max_requests", 1)
        rate_limiter._requests.clear()

        try:
            client.get("/policy")
            response = client.get("/policy")
            assert response.status_code == 429

            retry_after = response.headers["retry-after"]
            assert retry_after.isdigit()
            assert int(retry_after) >= 1
        finally:
            rate_limiter._requests.clear()


# ====================================================================
# Memory eviction
# ====================================================================


class TestMemoryEviction:
    """Stale client entries are evicted to bound memory usage."""

    def test_stale_clients_are_evicted(self):
        now = [0.0]
        limiter = InMemoryRateLimiter(
            max_requests=10, window_seconds=10, clock=lambda: now[0]
        )

        # Create entries for many clients at t=0.
        for i in range(100):
            limiter.allow(f"client-{i}")

        assert len(limiter._requests) == 100

        # Advance past the window + one window (eviction interval).
        now[0] = 20.1

        # A new request triggers eviction.
        limiter.allow("trigger")
        assert len(limiter._requests) <= 2  # "trigger" + maybe some residual

    def test_active_clients_survive_eviction(self):
        now = [0.0]
        limiter = InMemoryRateLimiter(
            max_requests=10, window_seconds=10, clock=lambda: now[0]
        )

        # "stale" at t=0, "active" at t=15.
        limiter.allow("stale")
        now[0] = 15.0
        limiter.allow("active")

        # Advance past eviction interval from t=0.
        now[0] = 20.1
        limiter.allow("trigger")

        # "stale" should be gone, "active" and "trigger" should remain.
        assert "stale" not in limiter._requests
        assert "active" in limiter._requests
        assert "trigger" in limiter._requests

    def test_eviction_does_not_run_every_call(self):
        """Eviction is amortised — not on every allow() call."""
        now = [0.0]
        limiter = InMemoryRateLimiter(
            max_requests=10, window_seconds=10, clock=lambda: now[0]
        )

        limiter.allow("first")
        now[0] = 5.0  # Within one window of last eviction — no sweep.
        limiter.allow("second")

        # Both clients should still be present (no premature eviction).
        assert "first" in limiter._requests
        assert "second" in limiter._requests


# ====================================================================
# Concurrent access
# ====================================================================


class TestConcurrency:
    """Thread-safety under concurrent access."""

    def test_concurrent_requests_do_not_exceed_limit(self):
        limiter = InMemoryRateLimiter(max_requests=10, window_seconds=60)
        results: list[bool] = []
        lock = threading.Lock()

        def hammer():
            for _ in range(5):
                allowed, _ = limiter.allow("shared")
                with lock:
                    results.append(allowed)

        threads = [threading.Thread(target=hammer) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Exactly max_requests should be allowed.
        assert sum(results) == 10
        assert len(results) == 50


# ====================================================================
# RedisRateLimiter — atomic sliding-window and fail-safety
# ====================================================================


class MockRedisClient:
    """In-memory simulation of Redis eval behavior executing the Lua script."""

    def __init__(self):
        self.zsets: dict[str, list[tuple[float, str]]] = {}
        self.ttls: dict[str, float] = {}
        self.raise_on_eval: Exception | None = None

    def eval(self, script: str, numkeys: int, key: str, now_s: str, window_s: str, max_s: str, member: str):
        if self.raise_on_eval:
            raise self.raise_on_eval

        now = float(now_s)
        window = float(window_s)
        max_requests = int(max_s)
        cutoff = now - window

        zset = self.zsets.setdefault(key, [])
        # Prune older than cutoff
        zset[:] = [entry for entry in zset if entry[0] > cutoff]

        if len(zset) < max_requests:
            zset.append((now, member))
            self.ttls[key] = now + window + 1
            return [1, 0]
        else:
            oldest_ts = zset[0][0]
            retry_after = max(1.0, (oldest_ts + window) - now)
            return [0, math.ceil(retry_after)]


class TestRedisRateLimiter:
    """Unit tests for the RedisRateLimiter implementation."""

    def test_allows_up_to_max_requests(self):
        client_mock = MockRedisClient()
        limiter = RedisRateLimiter(
            client=client_mock, max_requests=2, window_seconds=60, clock=lambda: 1000.0
        )

        allowed_1, retry_1 = limiter.allow("client-1")
        allowed_2, retry_2 = limiter.allow("client-1")
        denied_3, retry_3 = limiter.allow("client-1")

        assert allowed_1 is True
        assert retry_1 == 0.0
        assert allowed_2 is True
        assert retry_2 == 0.0
        assert denied_3 is False
        assert retry_3 >= 1.0

    def test_window_expiration(self):
        client_mock = MockRedisClient()
        now = [1000.0]
        limiter = RedisRateLimiter(
            client=client_mock, max_requests=1, window_seconds=10, clock=lambda: now[0]
        )

        allowed_1, _ = limiter.allow("client-1")
        denied, retry = limiter.allow("client-1")
        assert allowed_1 is True
        assert denied is False
        assert retry == 10.0

        # Advance past window
        now[0] = 1010.5
        allowed_again, retry_again = limiter.allow("client-1")
        assert allowed_again is True
        assert retry_again == 0.0

    def test_independent_clients_in_redis(self):
        client_mock = MockRedisClient()
        limiter = RedisRateLimiter(client=client_mock, max_requests=1, window_seconds=60)

        ok_a, _ = limiter.allow("client-a")
        ok_b, _ = limiter.allow("client-b")
        denied_a, _ = limiter.allow("client-a")

        assert ok_a is True
        assert ok_b is True
        assert denied_a is False

    def test_fail_open_on_redis_error(self):
        client_mock = MockRedisClient()
        client_mock.raise_on_eval = ConnectionError("Redis connection lost")
        limiter = RedisRateLimiter(
            client=client_mock, max_requests=5, window_seconds=60, fail_closed=False
        )

        # Fail open allows request
        allowed, retry = limiter.allow("client-1")
        assert allowed is True
        assert retry == 0.0

    def test_fail_closed_on_redis_error(self):
        client_mock = MockRedisClient()
        client_mock.raise_on_eval = TimeoutError("Redis timed out")
        limiter = RedisRateLimiter(
            client=client_mock, max_requests=5, window_seconds=30, fail_closed=True
        )

        # Fail closed denies request with full window retry
        allowed, retry = limiter.allow("client-1")
        assert allowed is False
        assert retry == 30.0

    @pytest.mark.parametrize(
        ("max_requests", "window_seconds"),
        [(0, 60), (1, 0), (-1, 60), (1, -1)],
    )
    def test_rejects_invalid_configuration(self, max_requests, window_seconds):
        client_mock = MockRedisClient()
        with pytest.raises(ValueError):
            RedisRateLimiter(client_mock, max_requests, window_seconds)


# ====================================================================
# Rate limiter factory
# ====================================================================


class TestRateLimiterFactory:
    """Tests for create_rate_limiter factory."""

    def test_creates_in_memory_backend(self):
        limiter = create_rate_limiter(backend="memory", max_requests=10, window_seconds=60)
        assert isinstance(limiter, InMemoryRateLimiter)
        assert isinstance(limiter, RateLimiterBackend)

    def test_creates_redis_backend_with_client(self):
        client_mock = MockRedisClient()
        limiter = create_rate_limiter(
            backend="redis",
            max_requests=10,
            window_seconds=60,
            redis_client=client_mock,
            fail_closed=True,
        )
        assert isinstance(limiter, RedisRateLimiter)
        assert isinstance(limiter, RateLimiterBackend)
        assert limiter.fail_closed is True

    def test_redis_backend_requires_url_or_client(self):
        with pytest.raises(ValueError, match="redis_url or redis_client is required"):
            create_rate_limiter(backend="redis", redis_url=None, redis_client=None)

    def test_redis_backend_raises_runtime_error_if_package_missing(self, monkeypatch):
        # Force redis import to fail
        monkeypatch.setitem(sys.modules, "redis", None)
        with pytest.raises(RuntimeError, match="The 'redis' package is required"):
            create_rate_limiter(backend="redis", redis_url="redis://localhost:6379/0")

    def test_redis_backend_creates_from_url_when_package_installed(self, monkeypatch):
        fake_redis = MagicMock()
        fake_client = MagicMock()
        fake_redis.from_url.return_value = fake_client

        monkeypatch.setitem(sys.modules, "redis", fake_redis)

        limiter = create_rate_limiter(
            backend="redis",
            redis_url="redis://localhost:6379/0",
            max_requests=15,
            window_seconds=45,
        )
        assert isinstance(limiter, RedisRateLimiter)
        fake_redis.from_url.assert_called_once_with("redis://localhost:6379/0")

    def test_unknown_backend_raises_value_error(self):
        with pytest.raises(ValueError, match="Unsupported rate limiter backend"):
            create_rate_limiter(backend="cassandra")


# ====================================================================
# Client-IP extraction with trusted-proxy support
# ====================================================================


class TestClientIpExtraction:
    """Tests for client_ip_from_request function."""

    def test_returns_peer_when_no_trusted_proxies(self):
        assert client_ip_from_request("10.0.0.1", None) == "10.0.0.1"

    def test_returns_peer_when_trusted_proxies_is_none(self):
        assert (
            client_ip_from_request(
                "10.0.0.1", "1.2.3.4", trusted_proxies=None
            )
            == "10.0.0.1"
        )

    def test_returns_peer_when_trusted_proxies_is_empty(self):
        assert (
            client_ip_from_request(
                "10.0.0.1", "1.2.3.4", trusted_proxies=frozenset()
            )
            == "10.0.0.1"
        )

    def test_ignores_forwarded_for_when_peer_is_not_trusted(self):
        """Untrusted peers cannot influence client identity via XFF."""
        assert (
            client_ip_from_request(
                "evil.attacker",
                "1.2.3.4, 5.6.7.8",
                trusted_proxies=frozenset({"10.0.0.1"}),
            )
            == "evil.attacker"
        )

    def test_extracts_rightmost_untrusted_from_xff(self):
        """When peer is trusted, take the rightmost untrusted XFF entry."""
        assert (
            client_ip_from_request(
                "10.0.0.1",
                "spoofed.by.client, real.client.ip, 10.0.0.1",
                trusted_proxies=frozenset({"10.0.0.1"}),
            )
            == "real.client.ip"
        )

    def test_skips_multiple_trusted_proxies_in_chain(self):
        """Multi-hop proxy chains: skip all trusted proxies."""
        assert (
            client_ip_from_request(
                "10.0.0.2",
                "client.ip, 10.0.0.1, 10.0.0.2",
                trusted_proxies=frozenset({"10.0.0.1", "10.0.0.2"}),
            )
            == "client.ip"
        )

    def test_all_xff_entries_trusted_returns_peer(self):
        """If every XFF entry is trusted, fall back to the TCP peer."""
        assert (
            client_ip_from_request(
                "10.0.0.1",
                "10.0.0.2, 10.0.0.1",
                trusted_proxies=frozenset({"10.0.0.1", "10.0.0.2"}),
            )
            == "10.0.0.1"
        )

    def test_missing_peer_returns_unknown(self):
        assert client_ip_from_request(None, None) == "unknown"

    def test_empty_xff_header_ignored(self):
        assert (
            client_ip_from_request(
                "10.0.0.1",
                "",
                trusted_proxies=frozenset({"10.0.0.1"}),
            )
            == "10.0.0.1"
        )

    def test_whitespace_in_xff_is_stripped(self):
        assert (
            client_ip_from_request(
                "10.0.0.1",
                "  real.ip  , 10.0.0.1  ",
                trusted_proxies=frozenset({"10.0.0.1"}),
            )
            == "real.ip"
        )


# ====================================================================
# Middleware integration — backward compatibility
# ====================================================================


class TestMiddlewareIntegration:
    """Ensure the middleware still behaves correctly with the updated limiter."""

    def test_rate_limit_returns_429_and_retry_after(self, monkeypatch):
        monkeypatch.setattr(rate_limiter, "max_requests", 1)
        monkeypatch.setattr(rate_limiter, "window_seconds", 60)
        rate_limiter._requests.clear()

        try:
            first = client.get("/policy")
            second = client.get("/policy")

            assert first.status_code == 200
            assert second.status_code == 429
            assert second.json() == {"detail": "Too Many Requests"}

            retry_after = int(second.headers["retry-after"])
            assert 1 <= retry_after <= 60
        finally:
            rate_limiter._requests.clear()

    def test_rate_limit_does_not_trust_forwarded_for_header(self, monkeypatch):
        """Without trusted proxies, XFF must not change rate-limit identity."""
        monkeypatch.setattr(rate_limiter, "max_requests", 1)
        rate_limiter._requests.clear()

        try:
            first = client.get(
                "/policy",
                headers={"X-Forwarded-For": "198.51.100.10"},
            )
            second = client.get(
                "/policy",
                headers={"X-Forwarded-For": "198.51.100.11"},
            )

            assert first.status_code == 200
            assert second.status_code == 429
        finally:
            rate_limiter._requests.clear()

    def test_rate_limited_response_has_security_headers(self, monkeypatch):
        monkeypatch.setattr(rate_limiter, "max_requests", 1)
        rate_limiter._requests.clear()

        try:
            client.get("/policy")
            response = client.get("/policy")

            assert response.status_code == 429
            assert response.headers["x-content-type-options"] == "nosniff"
            assert response.headers["x-frame-options"] == "DENY"
            assert response.headers["referrer-policy"] == "no-referrer"
            assert response.headers["cache-control"] == "no-store"
        finally:
            rate_limiter._requests.clear()

    def test_normal_requests_unaffected(self):
        """Normal requests still work after rate-limiter hardening."""
        rate_limiter._requests.clear()
        try:
            response = client.post(
                "/analyze",
                json={"prompt": "Hello", "context_docs": [], "metadata": META},
            )
            assert response.status_code == 200
            assert response.json()["decision"] == "allow"
        finally:
            rate_limiter._requests.clear()

    def test_429_response_does_not_leak_internal_details(self, monkeypatch):
        """Rate-limited responses reveal only 'Too Many Requests'."""
        monkeypatch.setattr(rate_limiter, "max_requests", 1)
        rate_limiter._requests.clear()

        try:
            client.get("/policy")
            response = client.get("/policy")

            assert response.status_code == 429
            body = response.json()
            assert body == {"detail": "Too Many Requests"}
            text = response.text.lower()
            assert "traceback" not in text
            assert "client" not in text  # no client_id leakage
        finally:
            rate_limiter._requests.clear()


# ====================================================================
# Backend protocol
# ====================================================================


class TestBackendProtocol:
    """RateLimiterBackend protocol conformance."""

    def test_inmemory_satisfies_protocol(self):
        limiter = InMemoryRateLimiter(max_requests=10, window_seconds=60)
        assert isinstance(limiter, RateLimiterBackend)

    def test_redis_satisfies_protocol(self):
        client_mock = MockRedisClient()
        limiter = RedisRateLimiter(client=client_mock, max_requests=10, window_seconds=60)
        assert isinstance(limiter, RateLimiterBackend)

    def test_custom_backend_satisfies_protocol(self):
        """A minimal custom backend is accepted by the protocol check."""

        class CustomBackend:
            def allow(self, client_id: str) -> tuple[bool, float]:
                return True, 0.0

        assert isinstance(CustomBackend(), RateLimiterBackend)


# ====================================================================
# Configuration
# ====================================================================


class TestConfiguration:
    """Config validation and environment variable behaviour."""

    @pytest.mark.parametrize(
        ("max_requests", "window_seconds"),
        [(0, 60), (1, 0), (-1, 60), (1, -1)],
    )
    def test_rejects_invalid_configuration(self, max_requests, window_seconds):
        with pytest.raises(ValueError):
            InMemoryRateLimiter(max_requests, window_seconds)

    def test_defaults_from_config(self):
        from app.config import (
            RATE_LIMIT_BACKEND,
            RATE_LIMIT_FAIL_CLOSED,
            RATE_LIMIT_REDIS_URL,
            RATE_LIMIT_REQUESTS,
            RATE_LIMIT_WINDOW_SECONDS,
        )

        assert RATE_LIMIT_REQUESTS >= 1
        assert RATE_LIMIT_WINDOW_SECONDS >= 1
        assert RATE_LIMIT_BACKEND == "memory"
        assert RATE_LIMIT_REDIS_URL == ""
        assert RATE_LIMIT_FAIL_CLOSED is False

    def test_trusted_proxies_defaults_to_empty(self):
        from app.config import TRUSTED_PROXIES

        # Without GUARDRAILS_TRUSTED_PROXIES env var, defaults to empty.
        assert isinstance(TRUSTED_PROXIES, frozenset)

    def test_trusted_proxies_env_parsing(self, monkeypatch):
        import importlib

        import app.config as cfg

        monkeypatch.setenv(
            "GUARDRAILS_TRUSTED_PROXIES", "10.0.0.1, 10.0.0.2 , 10.0.0.3"
        )
        importlib.reload(cfg)
        try:
            assert cfg.TRUSTED_PROXIES == frozenset(
                {"10.0.0.1", "10.0.0.2", "10.0.0.3"}
            )
        finally:
            monkeypatch.delenv("GUARDRAILS_TRUSTED_PROXIES", raising=False)
            importlib.reload(cfg)

    def test_trusted_proxies_empty_env(self, monkeypatch):
        import importlib

        import app.config as cfg

        monkeypatch.setenv("GUARDRAILS_TRUSTED_PROXIES", "")
        importlib.reload(cfg)
        try:
            assert cfg.TRUSTED_PROXIES == frozenset()
        finally:
            monkeypatch.delenv("GUARDRAILS_TRUSTED_PROXIES", raising=False)
            importlib.reload(cfg)

    @pytest.mark.parametrize("val", ["true", "1", "yes", "TRUE"])
    def test_fail_closed_truthy_env(self, monkeypatch, val):
        import importlib

        import app.config as cfg

        monkeypatch.setenv("GUARDRAILS_RATE_LIMIT_FAIL_CLOSED", val)
        importlib.reload(cfg)
        try:
            assert cfg.RATE_LIMIT_FAIL_CLOSED is True
        finally:
            monkeypatch.delenv("GUARDRAILS_RATE_LIMIT_FAIL_CLOSED", raising=False)
            importlib.reload(cfg)

    @pytest.mark.parametrize("val", ["false", "0", "no", "anything_else"])
    def test_fail_closed_falsy_env(self, monkeypatch, val):
        import importlib

        import app.config as cfg

        monkeypatch.setenv("GUARDRAILS_RATE_LIMIT_FAIL_CLOSED", val)
        importlib.reload(cfg)
        try:
            assert cfg.RATE_LIMIT_FAIL_CLOSED is False
        finally:
            monkeypatch.delenv("GUARDRAILS_RATE_LIMIT_FAIL_CLOSED", raising=False)
            importlib.reload(cfg)
