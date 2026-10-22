import pytest

from app.core.rate_limiter import InMemoryRateLimiter


def test_allows_requests_until_limit():
    limiter = InMemoryRateLimiter(max_requests=2, window_seconds=60)

    allowed_1, retry_1 = limiter.allow("client-a")
    allowed_2, retry_2 = limiter.allow("client-a")
    allowed_3, retry_3 = limiter.allow("client-a")

    assert allowed_1 is True
    assert retry_1 == 0.0
    assert allowed_2 is True
    assert retry_2 == 0.0
    assert allowed_3 is False
    assert retry_3 > 0


def test_clients_have_independent_limits():
    limiter = InMemoryRateLimiter(max_requests=1, window_seconds=60)

    allowed_a, _ = limiter.allow("client-a")
    allowed_b, _ = limiter.allow("client-b")
    denied_a, _ = limiter.allow("client-a")

    assert allowed_a is True
    assert allowed_b is True
    assert denied_a is False


def test_request_is_allowed_after_window_expires():
    now = [100.0]
    limiter = InMemoryRateLimiter(
        max_requests=1,
        window_seconds=10,
        clock=lambda: now[0],
    )

    allowed_1, _ = limiter.allow("client-a")
    denied, _ = limiter.allow("client-a")

    assert allowed_1 is True
    assert denied is False

    now[0] = 110.1
    allowed_again, retry = limiter.allow("client-a")

    assert allowed_again is True
    assert retry == 0.0


@pytest.mark.parametrize(
    ("max_requests", "window_seconds"),
    [(0, 60), (1, 0), (-1, 60), (1, -1)],
)
def test_rejects_invalid_configuration(max_requests, window_seconds):
    with pytest.raises(ValueError):
        InMemoryRateLimiter(max_requests, window_seconds)
