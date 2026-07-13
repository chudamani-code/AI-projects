"""
agent.py — AI agent instrumented with metrics, traces, and structured logs.

Every action the agent takes emits:
  - A Prometheus metric increment (counter/histogram/gauge)
  - An OTel span (child of the active task span)
  - A structured log record (JSON, forwarded to Loki via OTel Collector)

Usage:
    agent = InstrumentedAgent("agent-reader")
    async with agent.task("Summarise files") as ctx:
        await agent.llm_call(model="claude-sonnet", tokens_in=200, tokens_out=80, latency=1.2)
        await agent.tool_call(tool_name="read_file", status="success", latency=0.05)
        await agent.policy_check(tool_name="read_file", decision="allow")
"""
import asyncio
import logging
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Optional

from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

import metrics as m
from telemetry import get_tracer

logger = logging.getLogger("agsec.agent")


@dataclass
class TaskContext:
    agent_id: str
    task_name: str
    span: trace.Span
    start_time: float = field(default_factory=time.time)
    llm_calls: int = 0
    tool_calls: int = 0
    violations: int = 0


class InstrumentedAgent:
    """
    A thin instrumentation wrapper around an AI agent.

    The class doesn't contain actual LLM/tool logic — it wraps whatever
    your agent does and ensures every action is observable.
    """

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.tracer = get_tracer()
        self._log = logging.getLogger(f"agsec.agent.{agent_id}")
        # Initialise circuit breaker gauge to CLOSED
        m.CIRCUIT_BREAKER_STATE.labels(agent_id=agent_id).set(0)

    # ── Task lifecycle ────────────────────────────────────────────────────────

    @asynccontextmanager
    async def task(self, task_name: str):
        """Context manager that wraps a complete agent task."""
        m.ACTIVE_TASKS.labels(agent_id=self.agent_id).inc()
        m.TASKS_TOTAL.labels(agent_id=self.agent_id).inc()

        with self.tracer.start_as_current_span(
            "agent_task",
            attributes={
                "agsec.agent_id": self.agent_id,
                "agsec.task_name": task_name,
            },
        ) as span:
            ctx = TaskContext(
                agent_id=self.agent_id,
                task_name=task_name,
                span=span,
            )
            self._log.info(
                "task_started",
                extra={"agent_id": self.agent_id, "task": task_name},
            )
            outcome = "completed"
            try:
                yield ctx
            except Exception as exc:
                outcome = "error"
                span.set_status(Status(StatusCode.ERROR, str(exc)))
                self._log.error(
                    "task_error",
                    extra={"agent_id": self.agent_id, "task": task_name, "error": str(exc)},
                )
                raise
            finally:
                duration = time.time() - ctx.start_time
                m.TASK_DURATION.labels(
                    agent_id=self.agent_id, outcome=outcome
                ).observe(duration)
                m.ACTIVE_TASKS.labels(agent_id=self.agent_id).dec()
                span.set_attribute("agsec.task.llm_calls", ctx.llm_calls)
                span.set_attribute("agsec.task.tool_calls", ctx.tool_calls)
                span.set_attribute("agsec.task.violations", ctx.violations)
                self._log.info(
                    "task_completed",
                    extra={
                        "agent_id": self.agent_id,
                        "task": task_name,
                        "duration_s": round(duration, 3),
                        "outcome": outcome,
                    },
                )

    # ── LLM call ──────────────────────────────────────────────────────────────

    async def llm_call(
        self,
        model: str,
        tokens_in: int,
        tokens_out: int,
        latency: float,
        stop_reason: str = "end_turn",
    ) -> None:
        """Record a completed LLM API call."""
        with self.tracer.start_as_current_span(
            "llm_call",
            attributes={
                "agsec.agent_id": self.agent_id,
                "llm.model": model,
                "llm.tokens_in": tokens_in,
                "llm.tokens_out": tokens_out,
                "llm.latency_s": latency,
                "llm.stop_reason": stop_reason,
            },
        ):
            # Simulate async work (real agents await the API here)
            await asyncio.sleep(0)

            m.LLM_CALLS.labels(
                agent_id=self.agent_id, model=model, stop_reason=stop_reason
            ).inc()
            m.LLM_TOKENS.labels(
                agent_id=self.agent_id, model=model, direction="in"
            ).inc(tokens_in)
            m.LLM_TOKENS.labels(
                agent_id=self.agent_id, model=model, direction="out"
            ).inc(tokens_out)
            m.LLM_LATENCY.labels(agent_id=self.agent_id, model=model).observe(latency)

            self._log.info(
                "llm_call",
                extra={
                    "agent_id": self.agent_id,
                    "model": model,
                    "tokens_in": tokens_in,
                    "tokens_out": tokens_out,
                    "latency_s": round(latency, 3),
                    "stop_reason": stop_reason,
                },
            )

    # ── Tool call ─────────────────────────────────────────────────────────────

    async def tool_call(
        self,
        tool_name: str,
        status: str,      # success | error | blocked
        latency: float,
        inputs: Optional[dict] = None,
    ) -> None:
        """Record a tool call attempt and its outcome."""
        with self.tracer.start_as_current_span(
            "tool_call",
            attributes={
                "agsec.agent_id": self.agent_id,
                "agsec.tool_name": tool_name,
                "agsec.tool_status": status,
                "agsec.tool_latency_s": latency,
            },
        ) as span:
            await asyncio.sleep(0)

            if status == "error":
                span.set_status(Status(StatusCode.ERROR))
            elif status == "blocked":
                span.set_attribute("agsec.blocked", True)

            m.TOOL_CALLS.labels(
                agent_id=self.agent_id, tool_name=tool_name, status=status
            ).inc()
            m.TOOL_LATENCY.labels(
                agent_id=self.agent_id, tool_name=tool_name
            ).observe(latency)

            level = logging.WARNING if status in ("error", "blocked") else logging.INFO
            self._log.log(
                level,
                "tool_call",
                extra={
                    "agent_id": self.agent_id,
                    "tool": tool_name,
                    "status": status,
                    "latency_s": round(latency, 3),
                },
            )

    # ── Policy check ──────────────────────────────────────────────────────────

    async def policy_check(
        self,
        tool_name: str,
        decision: str,    # allow | deny
        reason: str = "",
    ) -> None:
        """Record an OPA policy evaluation result."""
        with self.tracer.start_as_current_span(
            "policy_check",
            attributes={
                "agsec.agent_id": self.agent_id,
                "agsec.tool_name": tool_name,
                "agsec.policy_decision": decision,
                "agsec.policy_reason": reason,
            },
        ):
            await asyncio.sleep(0)

            m.POLICY_DECISIONS.labels(
                agent_id=self.agent_id, tool_name=tool_name, decision=decision
            ).inc()

            if decision == "deny":
                m.POLICY_VIOLATIONS.labels(
                    agent_id=self.agent_id, violation_type="policy_deny"
                ).inc()
                self._log.warning(
                    "policy_violation",
                    extra={
                        "agent_id": self.agent_id,
                        "tool": tool_name,
                        "reason": reason,
                    },
                )

    # ── Circuit breaker ───────────────────────────────────────────────────────

    def circuit_breaker_open(self, trigger: str, reason: str = "") -> None:
        """Record circuit breaker trip — agent halted."""
        m.CIRCUIT_BREAKER_STATE.labels(agent_id=self.agent_id).set(1)
        m.CIRCUIT_BREAKER_TRIPS.labels(
            agent_id=self.agent_id, trigger=trigger
        ).inc()
        self._log.critical(
            "circuit_breaker_open",
            extra={
                "agent_id": self.agent_id,
                "trigger": trigger,
                "reason": reason,
            },
        )

    def circuit_breaker_close(self) -> None:
        """Record circuit breaker recovery."""
        m.CIRCUIT_BREAKER_STATE.labels(agent_id=self.agent_id).set(0)
        self._log.info("circuit_breaker_closed", extra={"agent_id": self.agent_id})

    # ── Injection detection ───────────────────────────────────────────────────

    def injection_detected(self, action: str, score: int, findings: list[str]) -> None:
        """Record a prompt injection detection event from the guardrail gateway."""
        m.INJECTION_DETECTIONS.labels(
            agent_id=self.agent_id, action=action
        ).inc()
        level = logging.CRITICAL if action == "BLOCK" else logging.WARNING
        self._log.log(
            level,
            "injection_detected",
            extra={
                "agent_id": self.agent_id,
                "action": action,
                "score": score,
                "findings": findings,
            },
        )
