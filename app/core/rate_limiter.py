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

import ipaddress
import math
import time
import uuid
from collections import defaultdict, deque
from functools import lru_cache
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


# Shared bucket used once the in-memory table is full (see max_clients).
OVERFLOW_CLIENT_ID = "__overflow__"

DEFAULT_MAX_CLIENTS = 50_000


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

    The table is also bounded: at most *max_clients* distinct clients are
    tracked (about 870 bytes each). When it is full, stale entries are
    swept immediately and, if there is still no room, new clients share a
    single overflow bucket. Memory therefore stays bounded even if an
    attacker rotates through millions of source addresses, at the cost of
    those overflow clients sharing one quota.

    Retry-After
    -----------
    When a request is denied, ``retry_after`` reports the number of
    seconds until the **oldest** request in the client's window expires,
    making room for a new one.
    """

    #: In-memory work is fast and non-blocking; no need for a worker thread.
    blocking = False

    def __init__(
        self,
        max_requests: int,
        window_seconds: int,
        clock: Callable[[], float] = monotonic,
        max_clients: int = DEFAULT_MAX_CLIENTS,
    ) -> None:
        if max_requests < 1:
            raise ValueError("max_requests must be at least 1")
        if window_seconds < 1:
            raise ValueError("window_seconds must be at least 1")
        if max_clients < 1:
            raise ValueError("max_clients must be at least 1")

        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.max_clients = max_clients
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

            # Bound memory: a table that is full of live clients must not
            # grow further, whatever the attacker's address diversity.
            if (
                client_id not in self._requests
                and len(self._requests) >= self.max_clients
            ):
                self._evict_stale(now)

                if len(self._requests) >= self.max_clients:
                    client_id = OVERFLOW_CLIENT_ID

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

        self._evict_stale(now)

    def _evict_stale(self, now: float) -> None:
        """Drop every client whose newest request has left the window."""
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

    #: redis-py's sync client does network I/O; callers on an event loop
    #: must run ``allow`` in a worker thread (see app.main).
    blocking = True

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
    prefix: str | None = None,
    redis_timeout: float | None = None,
    max_clients: int = DEFAULT_MAX_CLIENTS,
) -> RateLimiterBackend:
    """Create a configured rate limiter backend instance.

    ``prefix`` namespaces Redis keys (so several limiters can share one
    Redis); ``redis_timeout`` sets the connect and read timeout in seconds
    (redis-py otherwise waits indefinitely); ``max_clients`` bounds the
    in-memory table.
    """
    normalized_backend = backend.lower().strip()
    if normalized_backend == "memory":
        return InMemoryRateLimiter(
            max_requests=max_requests,
            window_seconds=window_seconds,
            clock=clock or monotonic,
            max_clients=max_clients,
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
            if redis_timeout is None:
                redis_client = redis.from_url(redis_url)
            else:
                redis_client = redis.from_url(
                    redis_url,
                    socket_timeout=redis_timeout,
                    socket_connect_timeout=redis_timeout,
                )

        extra = {"prefix": prefix} if prefix else {}

        return RedisRateLimiter(
            client=redis_client,
            max_requests=max_requests,
            window_seconds=window_seconds,
            fail_closed=fail_closed,
            clock=clock or time.time,
            **extra,
        )
    else:
        raise ValueError(
            f"Unsupported rate limiter backend: {backend!r}. Must be 'memory' or 'redis'."
        )


# ──────────────────────────────────────────────────────────────────
# Client-IP extraction with trusted-proxy support
# ──────────────────────────────────────────────────────────────────


@lru_cache(maxsize=32)
def _trusted_networks(
    trusted_proxies: frozenset[str],
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """Parse trusted-proxy entries (IP addresses or CIDR networks)."""
    networks = []

    for entry in trusted_proxies:
        try:
            networks.append(ipaddress.ip_network(entry.strip(), strict=False))
        except ValueError:
            # Config validation rejects bad entries at startup; direct
            # callers simply never match an unparseable one.
            continue

    return tuple(networks)


def _parse_ip(
    value: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse an address as it appears in a header or socket.

    Accepts ``1.2.3.4``, ``1.2.3.4:5678``, ``2001:db8::1`` and
    ``[2001:db8::1]:443``; IPv4-mapped IPv6 addresses are folded to IPv4.
    Returns ``None`` for anything else.
    """
    text = value.strip()

    if text.startswith("["):
        closing = text.find("]")
        if closing == -1:
            return None
        text = text[1:closing]
    elif text.count(":") == 1 and "." in text:
        text = text.rsplit(":", 1)[0]

    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None

    mapped = getattr(address, "ipv4_mapped", None)

    return mapped if mapped is not None else address


def _is_trusted(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...],
) -> bool:
    return any(
        address.version == network.version and address in network
        for network in networks
    )


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
        A frozen set of IP addresses and/or CIDR networks (for example
        ``{"10.0.0.1", "172.18.0.0/16"}``) whose ``X-Forwarded-For``
        values may be trusted.  When the TCP peer is inside this set, the
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
    * A trusted proxy always appends a well-formed address. If the entry
      being examined is NOT a valid IP address, the header is malformed or
      forged and is ignored entirely (the TCP peer is used), so a hostile
      string can never become a rate-limit identity.
    * If extraction fails for any reason, the fallback ``"unknown"``
      ensures the limiter still works (all unidentifiable clients share
      one bucket, which is conservative).
    """
    peer = request_client_host or "unknown"

    if not trusted_proxies or not forwarded_for_header:
        return peer

    networks = _trusted_networks(frozenset(trusted_proxies))

    peer_ip = _parse_ip(peer)

    if peer_ip is None or not _is_trusted(peer_ip, networks):
        return peer

    # Walk the X-Forwarded-For chain from the right, skipping trusted
    # proxies, and return the first untrusted address.
    parts = [p.strip() for p in forwarded_for_header.split(",") if p.strip()]

    for raw in reversed(parts):
        address = _parse_ip(raw)

        if address is None:
            return peer

        if not _is_trusted(address, networks):
            return str(address)

    # Every address in the chain is trusted — use the TCP peer.
    return peer


IPV6_PREFIX_LENGTH = 64


def rate_limit_key(identity: str) -> str:
    """Map a client identity to the key the limiter counts against.

    IPv4 addresses are used as-is. IPv6 addresses are collapsed to their
    /64 network, because one subscriber typically controls a whole /64
    (2**64 addresses) and could otherwise rotate source addresses to get a
    fresh quota on every request. Non-IP identities (for example
    ``"unknown"``) are returned unchanged, truncated to a sane length.
    """
    address = _parse_ip(identity)

    if address is None:
        return identity[:128]

    if address.version == 6:
        network = ipaddress.ip_network(
            f"{address}/{IPV6_PREFIX_LENGTH}", strict=False
        )
        return str(network)

    return str(address)
