"""
metrics.py — all Prometheus metric definitions for AI agent observability.

Naming convention: agsec_{signal}_{unit}
  agsec = AI agent security
  signal = what's being measured
  unit = seconds, total, etc.

All metrics are module-level singletons — import this module once
and use the objects directly from anywhere in the agent.

Prometheus scrapes :8000/metrics every 15s (configured in prometheus.yml).
"""
import os
import threading
from prometheus_client import (
    Counter, Gauge, Histogram, Summary,
    start_http_server, REGISTRY,
)

# ── LLM call metrics ──────────────────────────────────────────────────────────

LLM_CALLS = Counter(
    "agsec_llm_calls_total",
    "Total number of LLM API calls made",
    ["agent_id", "model", "stop_reason"],
)

LLM_TOKENS = Counter(
    "agsec_llm_tokens_total",
    "Total tokens consumed (in + out)",
    ["agent_id", "model", "direction"],  # direction: in | out
)

LLM_LATENCY = Histogram(
    "agsec_llm_latency_seconds",
    "LLM API call latency",
    ["agent_id", "model"],
    buckets=[0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0],
)

LLM_ERRORS = Counter(
    "agsec_llm_errors_total",
    "Total LLM API call errors",
    ["agent_id", "model", "error_type"],
)

# ── Tool call metrics ─────────────────────────────────────────────────────────

TOOL_CALLS = Counter(
    "agsec_tool_calls_total",
    "Total tool call attempts",
    ["agent_id", "tool_name", "status"],  # status: success | error | blocked
)

TOOL_LATENCY = Histogram(
    "agsec_tool_latency_seconds",
    "Tool execution latency",
    ["agent_id", "tool_name"],
    buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0],
)

# ── Policy / security metrics ─────────────────────────────────────────────────

POLICY_DECISIONS = Counter(
    "agsec_policy_decisions_total",
    "Total OPA policy evaluation decisions",
    ["agent_id", "tool_name", "decision"],  # decision: allow | deny
)

POLICY_VIOLATIONS = Counter(
    "agsec_policy_violations_total",
    "Policy violations that contributed to circuit breaker",
    ["agent_id", "violation_type"],
)

INJECTION_DETECTIONS = Counter(
    "agsec_injection_detections_total",
    "Prompt injection attempts detected by guardrail gateway",
    ["agent_id", "action"],  # action: WARN | FLAG | BLOCK
)

# ── Circuit breaker metrics ───────────────────────────────────────────────────

CIRCUIT_BREAKER_STATE = Gauge(
    "agsec_circuit_breaker_open",
    "1 if circuit breaker is OPEN (agent halted), 0 if CLOSED",
    ["agent_id"],
)

CIRCUIT_BREAKER_TRIPS = Counter(
    "agsec_circuit_breaker_trips_total",
    "Number of times the circuit breaker has tripped",
    ["agent_id", "trigger"],  # trigger: failures | violations | manual | signal
)

# ── Task / session metrics ────────────────────────────────────────────────────

ACTIVE_TASKS = Gauge(
    "agsec_active_tasks",
    "Number of agent tasks currently in flight",
    ["agent_id"],
)

TASK_DURATION = Histogram(
    "agsec_task_duration_seconds",
    "End-to-end duration of an agent task",
    ["agent_id", "outcome"],  # outcome: completed | halted | error
    buckets=[0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0],
)

TASKS_TOTAL = Counter(
    "agsec_tasks_total",
    "Total agent tasks started",
    ["agent_id"],
)

# ── Token budget metrics ──────────────────────────────────────────────────────

TOKEN_BUDGET_REMAINING = Gauge(
    "agsec_token_budget_remaining",
    "Estimated tokens remaining in rate limit window",
    ["agent_id"],
)

# ── Metrics HTTP server ───────────────────────────────────────────────────────

_server_started = False
_lock = threading.Lock()


def start_metrics_server(port: int = 8000) -> None:
    """Start the Prometheus metrics HTTP server (idempotent)."""
    global _server_started
    with _lock:
        if not _server_started:
            start_http_server(port)
            _server_started = True
