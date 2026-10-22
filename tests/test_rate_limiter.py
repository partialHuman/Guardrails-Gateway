import pytest

from app.core.rate_limiter import InMemoryRateLimiter


def test_allows_requests_until_limit():
    limiter = InMemoryRateLimiter(max_requests=2, window_seconds=60)

    assert limiter.allow("client-a") is True
    assert limiter.allow("client-a") is True
    assert limiter.allow("client-a") is False


def test_clients_have_independent_limits():
    limiter = InMemoryRateLimiter(max_requests=1, window_seconds=60)

    assert limiter.allow("client-a") is True
    assert limiter.allow("client-b") is True
    assert limiter.allow("client-a") is False


def test_request_is_allowed_after_window_expires():
    now = [100.0]
    limiter = InMemoryRateLimiter(
        max_requests=1,
        window_seconds=10,
        clock=lambda: now[0],
    )

    assert limiter.allow("client-a") is True
    assert limiter.allow("client-a") is False

    now[0] = 110.0

    assert limiter.allow("client-a") is True


@pytest.mark.parametrize(
    ("max_requests", "window_seconds"),
    [(0, 60), (1, 0), (-1, 60), (1, -1)],
)
def test_rejects_invalid_configuration(max_requests, window_seconds):
    with pytest.raises(ValueError):
        InMemoryRateLimiter(max_requests, window_seconds)