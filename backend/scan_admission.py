import asyncio
import math
import time
from collections import deque
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from threading import Lock


class ScanRateLimitExceeded(Exception):
    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("scan request rate limit exceeded")
        self.retry_after_seconds = retry_after_seconds


class ScanCapacityExceeded(Exception):
    """Raised when a scan cannot obtain capacity within the queue timeout."""


class ScanAdmissionController:
    """Apply per-process rate and concurrency limits to scan requests."""

    def __init__(
        self,
        *,
        max_concurrent_scans: int,
        scan_queue_timeout_seconds: float,
        rate_limit_requests: int,
        rate_limit_window_seconds: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_concurrent_scans < 1:
            raise ValueError("max_concurrent_scans must be positive")
        if (
            not math.isfinite(scan_queue_timeout_seconds)
            or scan_queue_timeout_seconds <= 0
        ):
            raise ValueError(
                "scan_queue_timeout_seconds must be positive and finite"
            )
        if rate_limit_requests < 1:
            raise ValueError("rate_limit_requests must be positive")
        if rate_limit_window_seconds < 1:
            raise ValueError("rate_limit_window_seconds must be positive")

        self._semaphore = asyncio.Semaphore(max_concurrent_scans)
        self._scan_queue_timeout_seconds = scan_queue_timeout_seconds
        self._rate_limit_requests = rate_limit_requests
        self._rate_limit_window_seconds = rate_limit_window_seconds
        self._clock = clock
        self._request_times: deque[float] = deque()
        self._rate_lock = Lock()

    def record_request(self) -> None:
        with self._rate_lock:
            now = self._clock()
            cutoff = now - self._rate_limit_window_seconds
            while self._request_times and self._request_times[0] <= cutoff:
                self._request_times.popleft()

            if len(self._request_times) >= self._rate_limit_requests:
                retry_after = math.ceil(
                    self._request_times[0]
                    + self._rate_limit_window_seconds
                    - now
                )
                raise ScanRateLimitExceeded(max(1, retry_after))

            self._request_times.append(now)

    @asynccontextmanager
    async def scan_slot(self) -> AsyncIterator[None]:
        acquired = False
        try:
            try:
                async with asyncio.timeout(
                    self._scan_queue_timeout_seconds
                ):
                    await self._semaphore.acquire()
                    acquired = True
            except TimeoutError:
                raise ScanCapacityExceeded from None

            yield
        finally:
            if acquired:
                self._semaphore.release()
