"""Shared test configuration.

The application owns module-global rate limiters (``app.main.rate_limiter``
and ``app.main.auth_failure_limiter``). Every ``TestClient`` request comes
from the same client identity, so without a reset the limiters' counters
leak from one test into the next and results depend on test ORDER (running
a different subset used to fail with spurious 429s).

State is cleared before and after every test; tests that need specific
limits still patch ``max_requests`` etc. themselves (monkeypatch undoes it).
"""

import pytest


def _reset(limiter) -> None:
    requests = getattr(limiter, "_requests", None)

    if requests is not None:
        requests.clear()


@pytest.fixture(autouse=True)
def _isolated_rate_limiters():
    from app import main

    for limiter in (main.rate_limiter, main.auth_failure_limiter):
        _reset(limiter)

    yield

    for limiter in (main.rate_limiter, main.auth_failure_limiter):
        _reset(limiter)
