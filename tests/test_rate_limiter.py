"""
Tests for Rate Limiter and Circuit Breaker (Faz 3.3).
"""

import time

import pytest

from src.utils.rate_limiter import (
    TokenBucket,
    CircuitBreaker,
    CircuitState,
    RateLimitManager,
)


# ========== Token Bucket ==========

class TestTokenBucket:
    def test_initial_tokens(self):
        b = TokenBucket(capacity=5, refill_rate=1.0)
        assert b.available_tokens == pytest.approx(5.0, abs=0.5)

    def test_consume_within_capacity(self):
        b = TokenBucket(capacity=5, refill_rate=1.0)
        assert b.consume() is True
        assert b.consume() is True

    def test_consume_exceeds_capacity(self):
        b = TokenBucket(capacity=2, refill_rate=0.01)  # Very slow refill
        assert b.consume() is True
        assert b.consume() is True
        assert b.consume() is False

    def test_refill(self):
        b = TokenBucket(capacity=2, refill_rate=100.0)  # Fast refill
        b.consume()
        b.consume()
        time.sleep(0.05)  # Let some tokens refill
        assert b.consume() is True

    def test_capacity_is_max(self):
        b = TokenBucket(capacity=3, refill_rate=100.0)
        time.sleep(0.1)
        # Even after long wait, tokens shouldn't exceed capacity
        assert b.available_tokens <= 3.0 + 0.1  # Small tolerance


# ========== Circuit Breaker ==========

class TestCircuitBreaker:
    def test_initial_state_closed(self):
        cb = CircuitBreaker(failure_threshold=3)
        assert cb.state == CircuitState.CLOSED
        assert cb.allow_request() is True

    def test_opens_after_threshold(self):
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=60)
        cb.record_failure()
        cb.record_failure()
        assert cb.allow_request() is True  # Not yet at threshold
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert cb.allow_request() is False

    def test_success_resets_count(self):
        cb = CircuitBreaker(failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()  # Reset
        cb.record_failure()
        assert cb.state == CircuitState.CLOSED

    def test_half_open_after_timeout(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        time.sleep(0.01)
        assert cb.allow_request() is True  # Should move to half-open
        assert cb.state == CircuitState.HALF_OPEN

    def test_half_open_success_closes(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.01)
        cb.allow_request()  # Move to half-open
        cb.record_success()
        assert cb.state == CircuitState.CLOSED

    def test_reset(self):
        cb = CircuitBreaker(failure_threshold=2)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        cb.reset()
        assert cb.state == CircuitState.CLOSED

    def test_get_status(self):
        cb = CircuitBreaker(failure_threshold=3)
        cb.record_success()
        status = cb.get_status()
        assert status['state'] == 'closed'
        assert status['success_count'] == 1


# ========== Rate Limit Manager ==========

class TestRateLimitManager:
    def test_configure_and_acquire(self):
        rlm = RateLimitManager()
        rlm.configure('vt', requests_per_minute=60)
        assert rlm.acquire('vt') is True

    def test_circuit_breaker_integration(self):
        rlm = RateLimitManager()
        rlm.configure('vt', requests_per_minute=60, failure_threshold=2, recovery_timeout=60)
        rlm.record_failure('vt')
        rlm.record_failure('vt')
        # Circuit should be open now
        assert rlm.acquire('vt') is False

    def test_unknown_service_passes(self):
        rlm = RateLimitManager()
        # No configuration for 'unknown' -> should still allow
        assert rlm.acquire('unknown') is True

    def test_get_status(self):
        rlm = RateLimitManager()
        rlm.configure('vt', requests_per_minute=4)
        status = rlm.get_status('vt')
        assert 'rate_limiter' in status
        assert 'circuit_breaker' in status

    def test_get_all_status(self):
        rlm = RateLimitManager()
        rlm.configure('vt', requests_per_minute=4)
        rlm.configure('abuse', requests_per_minute=10)
        status = rlm.get_status()
        assert 'vt' in status
        assert 'abuse' in status

    def test_daily_rate_config(self):
        rlm = RateLimitManager()
        rlm.configure('abuse', requests_per_day=1000)
        assert rlm.acquire('abuse') is True
