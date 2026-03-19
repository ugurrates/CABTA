"""
Author: Ugur Ates
Rate Limiter & Circuit Breaker for external API calls.

Features:
- Token-bucket rate limiter (per-API configurable)
- Circuit breaker: N consecutive failures -> open for M seconds
- Thread-safe implementation
"""

import logging
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Circuit Breaker
# ---------------------------------------------------------------------------

class CircuitState(Enum):
    CLOSED = 'closed'        # Normal operation
    OPEN = 'open'            # Failing, reject calls
    HALF_OPEN = 'half_open'  # Trying a single call to see if service recovered


@dataclass
class CircuitBreaker:
    """Per-service circuit breaker.

    After *failure_threshold* consecutive failures the circuit **opens**
    and stays open for *recovery_timeout* seconds.  Then it moves to
    **half-open** state and allows a single probe request.

    Usage::

        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=60)
        if cb.allow_request():
            try:
                result = call_api()
                cb.record_success()
            except Exception:
                cb.record_failure()
        else:
            # circuit is open, skip call
            ...
    """

    failure_threshold: int = 5
    recovery_timeout: int = 60  # seconds
    state: CircuitState = field(default=CircuitState.CLOSED)
    failure_count: int = field(default=0)
    last_failure_time: float = field(default=0.0)
    success_count: int = field(default=0)
    total_failures: int = field(default=0)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def allow_request(self) -> bool:
        """Return True if a request is allowed."""
        with self._lock:
            if self.state == CircuitState.CLOSED:
                return True
            if self.state == CircuitState.OPEN:
                if time.time() - self.last_failure_time >= self.recovery_timeout:
                    self.state = CircuitState.HALF_OPEN
                    logger.info("[CIRCUIT] Half-open: allowing probe request")
                    return True
                return False
            # HALF_OPEN - allow one probe
            return True

    def record_success(self) -> None:
        """Record a successful call."""
        with self._lock:
            self.failure_count = 0
            self.success_count += 1
            if self.state == CircuitState.HALF_OPEN:
                self.state = CircuitState.CLOSED
                logger.info("[CIRCUIT] Recovered -> closed")

    def record_failure(self) -> None:
        """Record a failed call."""
        with self._lock:
            self.failure_count += 1
            self.total_failures += 1
            self.last_failure_time = time.time()
            if self.failure_count >= self.failure_threshold:
                self.state = CircuitState.OPEN
                logger.warning(
                    f"[CIRCUIT] OPEN after {self.failure_count} consecutive failures. "
                    f"Recovery in {self.recovery_timeout}s"
                )

    def reset(self) -> None:
        with self._lock:
            self.state = CircuitState.CLOSED
            self.failure_count = 0

    def get_status(self) -> Dict:
        return {
            'state': self.state.value,
            'failure_count': self.failure_count,
            'total_failures': self.total_failures,
            'success_count': self.success_count,
        }


# ---------------------------------------------------------------------------
# Token-Bucket Rate Limiter
# ---------------------------------------------------------------------------

@dataclass
class TokenBucket:
    """Token-bucket rate limiter.

    *capacity* tokens are available; they refill at *refill_rate* tokens
    per second.  ``consume()`` blocks (up to *max_wait*) until a token is
    available, or returns False immediately if *block* is False.

    Usage::

        bucket = TokenBucket(capacity=4, refill_rate=4/60)  # 4 req/min
        if bucket.consume():
            call_api()
    """

    capacity: int = 10
    refill_rate: float = 1.0  # tokens per second
    _tokens: float = field(default=0.0, init=False)
    _last_refill: float = field(default=0.0, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self):
        self._tokens = float(self.capacity)
        self._last_refill = time.time()

    def consume(self, tokens: int = 1, block: bool = False, max_wait: float = 30.0) -> bool:
        """Try to consume *tokens*.

        Args:
            tokens: Number of tokens to consume.
            block: If True, wait until tokens are available.
            max_wait: Max seconds to wait when blocking.

        Returns:
            True if tokens were consumed, False otherwise.
        """
        deadline = time.time() + max_wait if block else 0

        while True:
            with self._lock:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return True

            if not block or time.time() >= deadline:
                return False

            # Wait a bit and retry
            time.sleep(0.1)

    @property
    def available_tokens(self) -> float:
        with self._lock:
            self._refill()
            return self._tokens

    def _refill(self) -> None:
        now = time.time()
        elapsed = now - self._last_refill
        self._tokens = min(self.capacity, self._tokens + elapsed * self.refill_rate)
        self._last_refill = now


# ---------------------------------------------------------------------------
# Rate Limit Manager (one per service)
# ---------------------------------------------------------------------------

class RateLimitManager:
    """Manages rate limiters and circuit breakers for all API services.

    Usage::

        rlm = RateLimitManager()
        rlm.configure('virustotal', requests_per_minute=4, failure_threshold=3)

        if rlm.acquire('virustotal'):
            try:
                result = call_vt_api()
                rlm.record_success('virustotal')
            except Exception:
                rlm.record_failure('virustotal')
    """

    def __init__(self):
        self._buckets: Dict[str, TokenBucket] = {}
        self._breakers: Dict[str, CircuitBreaker] = {}
        self._lock = threading.Lock()

    def configure(
        self,
        service: str,
        *,
        requests_per_minute: int = 60,
        requests_per_day: Optional[int] = None,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
    ) -> None:
        """Configure rate limit and circuit breaker for a service."""
        with self._lock:
            # Rate limit: convert to tokens/sec
            if requests_per_day:
                rate = requests_per_day / 86400
                capacity = max(1, requests_per_day // 1440)  # ~per-minute capacity
            else:
                rate = requests_per_minute / 60.0
                capacity = max(1, requests_per_minute)

            self._buckets[service] = TokenBucket(
                capacity=capacity,
                refill_rate=rate,
            )
            self._breakers[service] = CircuitBreaker(
                failure_threshold=failure_threshold,
                recovery_timeout=recovery_timeout,
            )

    def acquire(self, service: str, block: bool = False) -> bool:
        """Try to acquire permission to make a request.

        Returns True if both rate limit allows and circuit breaker is closed.
        """
        breaker = self._breakers.get(service)
        if breaker and not breaker.allow_request():
            logger.debug(f"[RATE] {service}: circuit breaker OPEN, request blocked")
            return False

        bucket = self._buckets.get(service)
        if bucket and not bucket.consume(block=block):
            logger.debug(f"[RATE] {service}: rate limit exceeded")
            return False

        return True

    def record_success(self, service: str) -> None:
        breaker = self._breakers.get(service)
        if breaker:
            breaker.record_success()

    def record_failure(self, service: str) -> None:
        breaker = self._breakers.get(service)
        if breaker:
            breaker.record_failure()

    def get_status(self, service: Optional[str] = None) -> Dict:
        """Return status for one or all services."""
        if service:
            return {
                'rate_limiter': {
                    'available': self._buckets[service].available_tokens
                    if service in self._buckets else 'N/A',
                },
                'circuit_breaker': self._breakers[service].get_status()
                if service in self._breakers else {},
            }

        return {
            svc: {
                'rate_limiter': {'available': round(self._buckets[svc].available_tokens, 1)},
                'circuit_breaker': self._breakers[svc].get_status(),
            }
            for svc in self._buckets
        }
