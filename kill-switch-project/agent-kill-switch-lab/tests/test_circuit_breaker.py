"""
test_circuit_breaker.py — unit tests for the kill switch state machine.

Run: python -m pytest tests/ -v
"""
import time
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))

import pytest
from circuit_breaker import CircuitBreaker, CircuitState


def test_initial_state_is_closed():
    cb = CircuitBreaker()
    assert cb.state == CircuitState.CLOSED
    assert cb.is_operational()


def test_trips_after_failure_threshold():
    cb = CircuitBreaker(failure_threshold=3)
    cb.record_failure("db timeout")
    cb.record_failure("db timeout")
    assert cb.is_operational()  # still OK at 2
    cb.record_failure("db timeout")
    assert cb.state == CircuitState.OPEN
    assert not cb.is_operational()
    assert "failure threshold" in cb.kill_reason.lower()


def test_trips_after_violation_threshold():
    cb = CircuitBreaker(violation_threshold=2)
    cb.record_policy_violation("path traversal")
    assert cb.is_operational()
    cb.record_policy_violation("system path blocked")
    assert cb.state == CircuitState.OPEN
    assert "violation threshold" in cb.kill_reason.lower()


def test_force_kill_opens_immediately():
    cb = CircuitBreaker()
    cb.force_kill("ops team manual halt")
    assert cb.state == CircuitState.OPEN
    assert not cb.is_operational()
    assert "ops team manual halt" in cb.kill_reason


def test_transitions_to_half_open_after_timeout():
    cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.05)
    cb.record_failure("timeout")
    assert cb.state == CircuitState.OPEN
    time.sleep(0.1)
    assert cb.state == CircuitState.HALF_OPEN
    assert cb.is_operational()  # HALF_OPEN allows one probe


def test_success_in_half_open_closes_circuit():
    cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.05)
    cb.record_failure("timeout")
    time.sleep(0.1)
    assert cb.state == CircuitState.HALF_OPEN
    cb.record_success()
    assert cb.state == CircuitState.CLOSED
    assert cb.is_operational()


def test_counters_reset_on_close():
    cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.05)
    cb.record_failure("err")
    time.sleep(0.1)
    cb.record_success()
    # Should be back to a clean CLOSED state — trip again normally
    cb.record_failure("new err")
    assert cb.state == CircuitState.OPEN
