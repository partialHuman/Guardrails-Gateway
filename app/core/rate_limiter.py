"""Rate-limiting backends for single-process and production deployments.

.. important::

    The :class:`InMemoryRateLimiter` enforces limits **per OS process**.
    Multi-worker deployments (e.g. ``uvicorn --workers 4``) or multi-replica
    orchestrations (Kubernetes, ECS, …) will each maintain an independent
    counter, so the *effective* cluster-wide limit is ``max_requests × N``.

    For coordinated rate limiting across workers or replicas, use
    :class:`RedisRateLimiter` with a shared Redis instance.
"""

from __future__ import annotations

import math
import time
import uuid
from collections import defaultdict, deque
from threading import Lock
from time import monotonic
from typing import Any, Callable, Protocol, runtime_checkable

from app.core.logger import logger

# ──────────────────────────────────────────────────────────────────
# Backend protocol
# ──────────────────────────────────────────────────────────────────


@runtime_checkable
class RateLimiterBackend(Protocol):
    """Interface that any rate-limiter backend must satisfy.

    ``allow`` returns a tuple of *(permitted, retry_after_seconds)*.
    *retry_after_seconds* is the number of seconds the client should wait
    before retrying when *permitted* is ``False``.  When *permitted* is
    ``True`` the value must be ``0.0``.
    """

    def allow(self, client_id: str) -> tuple[bool, float]: ...


# ──────────────────────────────────────────────────────────────────
# In-memory implementation (default, process-local)
# ──────────────────────────────────────────────────────────────────


class InMemoryRateLimiter:
    """Sliding-window rate limiter backed by process-local memory.

    .. warning::

        This backend is **not shared** across OS processes or replicas.
        It is appropriate for single-process development servers and as
        a per-process safety net in production.  See the module docstring
        for guidance on multi-worker deployments.

    Memory safety
    -------------
    Stale client entries (those whose newest timestamp is older than
    *window_seconds*) are evicted periodically during ``allow()`` calls.
    The eviction sweep runs at most once every *window_seconds* to avoid
    adding per-request overhead.

    Retry-After
    -----------
    When a request is denied, ``retry_after`` reports the number of
    seconds until the **oldest** request in the client's window expires,
    making room for a new one.
    """

    def __init__(
        self,
        max_requests: int,
        window_seconds: int,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        if max_requests < 1:
            raise ValueError("max_requests must be at least 1")
        if window_seconds < 1:
            raise ValueError("window_seconds must be at least 1")

        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._clock = clock
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()
        self._last_eviction: float = clock()

    # -- public API --------------------------------------------------

    def allow(self, client_id: str) -> tuple[bool, float]:
        """Check whether *client_id* may proceed.

        Returns ``(True, 0.0)`` when the request is allowed, or
        ``(False, retry_after)`` when the client has exceeded
        *max_requests* in the current window.
        """
        now = self._clock()
        cutoff = now - self.window_seconds

        with self._lock:
            # Periodic eviction of stale entries.
            self._maybe_evict(now)

            timestamps = self._requests[client_id]

            # Remove expired timestamps for *this* client.
            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()

            if len(timestamps) >= self.max_requests:
                # The oldest surviving timestamp determines when a slot
                # opens.  ``retry_after`` is always > 0 because we just
                # pruned entries older than *cutoff*.
                retry_after = (timestamps[0] + self.window_seconds) - now
                return False, max(retry_after, 1.0)

            timestamps.append(now)
            return True, 0.0

    # -- memory management -------------------------------------------

    def _maybe_evict(self, now: float) -> None:
        """Remove client entries that have gone completely stale.

        Called inside the lock.  Only runs a full sweep once per window
        to amortise the O(clients) scan cost.
        """
        if now - self._last_eviction < self.window_seconds:
            return

        cutoff = now - self.window_seconds
        stale_keys = [
            key
            for key, ts in self._requests.items()
            if not ts or ts[-1] <= cutoff
        ]
        for key in stale_keys:
            del self._requests[key]

        self._last_eviction = now


# ──────────────────────────────────────────────────────────────────
# Redis implementation (shared, multi-worker / multi-replica)
# ──────────────────────────────────────────────────────────────────

_REDIS_SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local max_requests = tonumber(ARGV[3])
local member = ARGV[4]
local cutoff = now - window

-- 1. Remove expired timestamps outside the rolling window
redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)

-- 2. Count requests currently in the window
local count = redis.call('ZCARD', key)

if count < max_requests then
    -- Allowed: record this request and ensure key TTL
    redis.call('ZADD', key, now, member)
    redis.call('EXPIRE', key, math.ceil(window) + 1)
    return {1, 0}
else
    -- Denied: find oldest request to calculate exact retry_after
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local retry_after = window
    if oldest and #oldest >= 2 then
        local oldest_ts = tonumber(oldest[2])
        retry_after = math.max(1, (oldest_ts + window) - now)
    end
    return {0, math.ceil(retry_after)}
end
"""


class RedisRateLimiter:
    """Sliding-window rate limiter backed by Redis for multi-worker deployments.

    .. note::

        Uses an atomic Lua script executing on the Redis server to prevent
        race conditions between concurrent workers. Keys automatically
        expire after `window_seconds + 1` of inactivity, bounding Redis memory.

    Fail safety
    -----------
    When Redis is unreachable or returns an error:
    - If `fail_closed` is False (default / fail-open), the request is
      allowed (returns `(True, 0.0)`).
    - If `fail_closed` is True, the request is denied (returns
      `(False, float(window_seconds))`).
    In both cases, the failure is logged and the limiter NEVER silently falls
    back to per-process in-memory counters, ensuring behavior remains explicit.
    """

    def __init__(
        self,
        client: Any,
        max_requests: int,
        window_seconds: int,
        prefix: str = "guardrails:rate_limit:",
        fail_closed: bool = False,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if max_requests < 1:
            raise ValueError("max_requests must be at least 1")
        if window_seconds < 1:
            raise ValueError("window_seconds must be at least 1")

        self.client = client
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.prefix = prefix
        self.fail_closed = fail_closed
        self._clock = clock

    def allow(self, client_id: str) -> tuple[bool, float]:
        """Check whether *client_id* may proceed via Redis."""
        now = self._clock()
        key = f"{self.prefix}{client_id}"
        member = f"{now}:{uuid.uuid4().hex}"

        try:
            result = self.client.eval(
                _REDIS_SLIDING_WINDOW_LUA,
                1,
                key,
                str(now),
                str(self.window_seconds),
                str(self.max_requests),
                member,
            )
            allowed = bool(result[0] == 1)
            retry_after = float(result[1]) if not allowed else 0.0
            return allowed, retry_after
        except Exception as exc:
            logger.error(
                "Rate limiter backend error | client_id=%s | error=%s",
                client_id,
                type(exc).__name__,
            )
            if self.fail_closed:
                return False, float(self.window_seconds)
            return True, 0.0


# ──────────────────────────────────────────────────────────────────
# Rate limiter factory
# ──────────────────────────────────────────────────────────────────


def create_rate_limiter(
    backend: str = "memory",
    max_requests: int = 60,
    window_seconds: int = 60,
    redis_url: str | None = None,
    redis_client: Any = None,
    fail_closed: bool = False,
    clock: Callable[[], float] | None = None,
) -> RateLimiterBackend:
    """Create a configured rate limiter backend instance."""
    normalized_backend = backend.lower().strip()
    if normalized_backend == "memory":
        return InMemoryRateLimiter(
            max_requests=max_requests,
            window_seconds=window_seconds,
            clock=clock or monotonic,
        )
    elif normalized_backend == "redis":
        if redis_client is None:
            if not redis_url:
                raise ValueError(
                    "redis_url or redis_client is required when backend is 'redis'"
                )
            try:
                import redis
            except ImportError as exc:
                raise RuntimeError(
                    "The 'redis' package is required when using the Redis rate limiter backend. "
                    "Install it with: pip install redis"
                ) from exc
            redis_client = redis.from_url(redis_url)

        return RedisRateLimiter(
            client=redis_client,
            max_requests=max_requests,
            window_seconds=window_seconds,
            fail_closed=fail_closed,
            clock=clock or time.time,
        )
    else:
        raise ValueError(
            f"Unsupported rate limiter backend: {backend!r}. Must be 'memory' or 'redis'."
        )


# ──────────────────────────────────────────────────────────────────
# Client-IP extraction with trusted-proxy support
# ──────────────────────────────────────────────────────────────────


def client_ip_from_request(
    request_client_host: str | None,
    forwarded_for_header: str | None,
    *,
    trusted_proxies: frozenset[str] | None = None,
) -> str:
    """Derive a rate-limiting identity from the request.

    Parameters
    ----------
    request_client_host:
        ``request.client.host`` from Starlette — the TCP peer address.
    forwarded_for_header:
        The raw ``X-Forwarded-For`` header value, or ``None``.
    trusted_proxies:
        A frozen set of IP addresses whose ``X-Forwarded-For`` values
        may be trusted.  When the TCP peer is in this set, the
        **rightmost untrusted** entry from ``X-Forwarded-For`` is used.
        If ``None`` or empty, ``X-Forwarded-For`` is **never** trusted
        and the TCP peer address is always used.

    Returns
    -------
    str
        A non-empty client identifier suitable for rate-limiting.

    Security notes
    --------------
    * The function never trusts ``X-Forwarded-For`` unless the caller
      explicitly provides a *trusted_proxies* set **and** the TCP peer
      belongs to it.
    * The *rightmost-untrusted* strategy is resistant to client-injected
      header values because it walks the chain from the end (closest to
      the server), skipping only addresses the operator has vouched for.
    * If extraction fails for any reason, the fallback ``"unknown"``
      ensures the limiter still works (all unidentifiable clients share
      one bucket, which is conservative).
    """
    peer = request_client_host or "unknown"

    if not trusted_proxies or not forwarded_for_header:
        return peer

    if peer not in trusted_proxies:
        return peer

    # Walk the X-Forwarded-For chain from the right, skipping trusted
    # proxies, and return the first untrusted address.
    parts = [p.strip() for p in forwarded_for_header.split(",") if p.strip()]
    for addr in reversed(parts):
        if addr not in trusted_proxies:
            return addr

    # Every address in the chain is trusted — use the TCP peer.
    return peer
