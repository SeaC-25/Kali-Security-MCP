"""
Tests for resilience module (kali_mcp/core/resilience.py)

Covers:
- CircuitStats: counters, rates, reset
- CircuitBreakerConfig: defaults and presets
- CircuitBreaker: state machine (sync path)
- CircuitState enum
- Custom exceptions
"""

import time
from unittest.mock import patch

import pytest

from kali_mcp.core.resilience import (
    CircuitStats,
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitState,
    CircuitOpenError,
    RateLimitExceededError,
    TOOL_CIRCUIT_CONFIGS,
)


# ===================== CircuitStats Tests =====================

class TestCircuitStats:
    def test_defaults(self):
        s = CircuitStats()
        assert s.total_calls == 0
        assert s.consecutive_failures == 0

    def test_record_success(self):
        s = CircuitStats()
        s.record_success()
        assert s.total_calls == 1
        assert s.successful_calls == 1
        assert s.consecutive_successes == 1
        assert s.consecutive_failures == 0
        assert s.last_success_time is not None

    def test_record_failure(self):
        s = CircuitStats()
        s.record_failure("timeout")
        assert s.total_calls == 1
        assert s.failed_calls == 1
        assert s.consecutive_failures == 1
        assert s.consecutive_successes == 0
        assert s.last_error == "timeout"

    def test_record_rejection(self):
        s = CircuitStats()
        s.record_rejection()
        assert s.rejected_calls == 1

    def test_success_resets_consecutive_failures(self):
        s = CircuitStats()
        s.record_failure()
        s.record_failure()
        assert s.consecutive_failures == 2
        s.record_success()
        assert s.consecutive_failures == 0
        assert s.consecutive_successes == 1

    def test_failure_resets_consecutive_successes(self):
        s = CircuitStats()
        s.record_success()
        s.record_success()
        s.record_failure()
        assert s.consecutive_successes == 0

    def test_failure_rate_no_calls(self):
        s = CircuitStats()
        assert s.failure_rate == 0.0

    def test_failure_rate_with_data(self):
        s = CircuitStats()
        s.record_success()
        s.record_failure()
        assert s.failure_rate == 0.5

    def test_success_rate_no_calls(self):
        s = CircuitStats()
        assert s.success_rate == 1.0

    def test_success_rate_with_data(self):
        s = CircuitStats()
        s.record_success()
        s.record_success()
        s.record_failure()
        assert abs(s.success_rate - 2/3) < 0.01

    def test_reset(self):
        s = CircuitStats()
        s.record_failure()
        s.record_failure()
        s.reset()
        assert s.consecutive_failures == 0
        assert s.consecutive_successes == 0
        # total_calls preserved
        assert s.total_calls == 2

    def test_full_reset(self):
        s = CircuitStats()
        s.record_failure()
        s.record_success()
        s.record_rejection()
        s.full_reset()
        assert s.total_calls == 0
        assert s.successful_calls == 0
        assert s.failed_calls == 0
        assert s.rejected_calls == 0
        assert s.last_error is None


# ===================== CircuitBreakerConfig Tests =====================

class TestCircuitBreakerConfig:
    def test_defaults(self):
        c = CircuitBreakerConfig()
        assert c.failure_threshold == 5
        assert c.success_threshold == 3
        assert c.recovery_timeout == 30.0

    def test_preset_configs(self):
        assert "network_scan" in TOOL_CIRCUIT_CONFIGS
        assert "exploit" in TOOL_CIRCUIT_CONFIGS
        assert TOOL_CIRCUIT_CONFIGS["exploit"].recovery_timeout == 120.0
        assert TOOL_CIRCUIT_CONFIGS["network_scan"].failure_threshold == 3


# ===================== CircuitState Tests =====================

class TestCircuitState:
    def test_values(self):
        assert CircuitState.CLOSED == "closed"
        assert CircuitState.OPEN == "open"
        assert CircuitState.HALF_OPEN == "half_open"


# ===================== CircuitBreaker Tests =====================

class TestCircuitBreaker:
    def test_initial_state(self):
        cb = CircuitBreaker("test")
        assert cb.state == CircuitState.CLOSED
        assert cb.is_closed is True
        assert cb.is_open is False

    def test_properties(self):
        cb = CircuitBreaker("test")
        assert cb.name == "test"
        assert isinstance(cb.stats, CircuitStats)
        assert cb.time_in_current_state >= 0

    def test_time_until_recovery_when_closed(self):
        cb = CircuitBreaker("test")
        assert cb.time_until_recovery == 0

    def test_custom_config(self):
        config = CircuitBreakerConfig(failure_threshold=10, recovery_timeout=60.0)
        cb = CircuitBreaker("test", config=config)
        assert cb.config.failure_threshold == 10
        assert cb.config.recovery_timeout == 60.0


# ===================== Custom Exceptions =====================

class TestExceptions:
    def test_circuit_open_error(self):
        err = CircuitOpenError("nmap", 10.5)
        assert err.circuit_name == "nmap"
        assert err.recovery_time == 10.5
        assert "nmap" in str(err)

    def test_rate_limit_error(self):
        err = RateLimitExceededError("api", 5.0)
        assert err.limiter_name == "api"
        assert err.wait_time == 5.0
        assert "api" in str(err)
