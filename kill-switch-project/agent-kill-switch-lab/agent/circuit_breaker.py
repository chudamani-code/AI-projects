"""
circuit_breaker.py — three-state machine that halts the agent automatically.

States:
  CLOSED   → normal operation
  OPEN     → agent is halted (kill switch tripped)
  HALF_OPEN→ testing if it's safe to resume after recovery_timeout seconds
"""
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreaker:
    # Trip to OPEN after this many consecutive tool/LLM errors
    failure_threshold: int = 3
    # Trip to OPEN after this many OPA policy violations
    violation_threshold: int = 2
    # Seconds before transitioning OPEN → HALF_OPEN to retry
    recovery_timeout: float = 30.0

    _state: CircuitState = field(default=CircuitState.CLOSED, init=False)
    _failure_count: int = field(default=0, init=False)
    _violation_count: int = field(default=0, init=False)
    _last_failure_time: Optional[float] = field(default=None, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    _kill_reason: Optional[str] = field(default=None, init=False)

    @property
    def state(self) -> CircuitState:
        with self._lock:
            if (
                self._state == CircuitState.OPEN
                and self._last_failure_time
                and time.time() - self._last_failure_time > self.recovery_timeout
            ):
                self._state = CircuitState.HALF_OPEN
            return self._state

    def record_success(self) -> None:
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.CLOSED
                self._failure_count = 0
                self._violation_count = 0

    def record_failure(self, reason: str = "error") -> None:
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()
            if self._failure_count >= self.failure_threshold:
                self._trip(f"Failure threshold ({self.failure_threshold}) reached: {reason}")

    def record_policy_violation(self, reason: str) -> None:
        with self._lock:
            self._violation_count += 1
            self._last_failure_time = time.time()
            if self._violation_count >= self.violation_threshold:
                self._trip(
                    f"Policy violation threshold ({self.violation_threshold}) reached: {reason}"
                )

    def force_kill(self, reason: str = "manual kill switch") -> None:
        """External call: ops team / signal handler / file watcher."""
        with self._lock:
            self._trip(reason)

    def _trip(self, reason: str) -> None:
        """Internal: transition to OPEN and record why."""
        self._state = CircuitState.OPEN
        self._kill_reason = reason

    def is_operational(self) -> bool:
        return self.state in (CircuitState.CLOSED, CircuitState.HALF_OPEN)

    @property
    def kill_reason(self) -> Optional[str]:
        return self._kill_reason
