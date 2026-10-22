"""In-memory sliding-window rate limiter for single-process deployments."""

from collections import defaultdict, deque
from threading import Lock
from time import monotonic
from typing import Callable


class InMemoryRateLimiter:
    """Limit requests per client within a rolling time window."""

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

    def allow(self, client_id: str) -> bool:
        """Return whether a request is allowed for this client."""
        now = self._clock()
        cutoff = now - self.window_seconds

        with self._lock:
            timestamps = self._requests[client_id]

            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()

            if len(timestamps) >= self.max_requests:
                return False

            timestamps.append(now)
            return True