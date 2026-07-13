"""
simulator.py — generates realistic AI agent telemetry without an API key.

Runs 3 virtual agents concurrently. After ANOMALY_DELAY seconds, each agent
begins exhibiting a different security anomaly. Watch the Grafana dashboard
respond in real time.

Agents and their anomalies:
  agent-reader     → TOKEN SPIKE       (token rate suddenly 10× normal)
  agent-processor  → POLICY VIOLATIONS (70% of tool calls get denied)
  agent-admin      → HIGH ERROR RATE   (60% tool errors → circuit breaker trip)

Run: python simulator.py
Metrics available at: http://localhost:8000/metrics
Grafana: http://localhost:3000
"""
import asyncio
import logging
import os
import random
import signal
import sys
import time

import metrics as m
from agent import InstrumentedAgent
from telemetry import init_telemetry

logger = logging.getLogger("simulator")

ANOMALY_DELAY   = int(os.getenv("ANOMALY_DELAY",   "60"))   # seconds before anomalies start
METRICS_PORT    = int(os.getenv("METRICS_PORT",    "8000"))
TASK_INTERVAL   = float(os.getenv("TASK_INTERVAL", "0.3"))  # seconds between tasks

MODELS = ["claude-sonnet-4-20250514", "claude-haiku-4-5-20251001"]
TOOLS  = ["read_file", "list_files", "write_file", "web_search", "query_rds", "invoke_lambda"]
TASKS  = [
    "Summarise files in /data directory",
    "Validate configuration and write report",
    "Process daily log batch",
    "Run anomaly detection on user activity",
    "Generate compliance report for Q3",
    "Archive old records to cold storage",
]


def _normal_llm_params() -> dict:
    return dict(
        model=random.choice(MODELS),
        tokens_in=random.randint(150, 600),
        tokens_out=random.randint(80, 250),
        latency=random.uniform(0.4, 2.2),
        stop_reason=random.choices(
            ["end_turn", "max_tokens", "tool_use"],
            weights=[0.80, 0.05, 0.15],
        )[0],
    )


def _spike_llm_params() -> dict:
    """Token spike: 8–15× normal volume."""
    return dict(
        model=random.choice(MODELS),
        tokens_in=random.randint(4_000, 12_000),
        tokens_out=random.randint(2_000, 5_000),
        latency=random.uniform(5.0, 15.0),
        stop_reason="end_turn",
    )


def _normal_tool_status() -> str:
    return random.choices(
        ["success", "error", "blocked"],
        weights=[0.87, 0.08, 0.05],
    )[0]


# ─────────────────────────────────────────────────────────────────────────────
# Agent runners
# ─────────────────────────────────────────────────────────────────────────────

async def run_agent_reader(start_time: float) -> None:
    """agent-reader: low-trust reader. Anomaly = sudden token spike."""
    agent = InstrumentedAgent("agent-reader")

    while True:
        elapsed = time.time() - start_time
        in_anomaly = elapsed > ANOMALY_DELAY
        n_llm  = random.randint(1, 3)
        n_tool = random.randint(1, 3)

        async with agent.task(random.choice(TASKS)):
            for _ in range(n_llm):
                params = _spike_llm_params() if in_anomaly else _normal_llm_params()
                await agent.llm_call(**params)

            for _ in range(n_tool):
                tool = random.choice(["read_file", "list_files"])
                status = _normal_tool_status()
                await agent.policy_check(tool, "allow" if status != "blocked" else "deny")
                await agent.tool_call(tool, status, latency=random.uniform(0.01, 0.3))

        await asyncio.sleep(TASK_INTERVAL + random.uniform(0, 0.5))


async def run_agent_processor(start_time: float) -> None:
    """agent-processor: data pipeline. Anomaly = 70% policy violations."""
    agent = InstrumentedAgent("agent-processor")

    while True:
        elapsed = time.time() - start_time
        in_anomaly = elapsed > ANOMALY_DELAY

        n_llm  = random.randint(1, 4)
        n_tool = random.randint(2, 5)

        async with agent.task(random.choice(TASKS)):
            for _ in range(n_llm):
                await agent.llm_call(**_normal_llm_params())

            for _ in range(n_tool):
                tool = random.choice(TOOLS)
                if in_anomaly:
                    # Mostly blocked by policy — agent is trying out-of-scope tools
                    status = random.choices(
                        ["success", "blocked", "error"],
                        weights=[0.20, 0.70, 0.10],
                    )[0]
                    decision = "deny" if status == "blocked" else "allow"
                else:
                    status = _normal_tool_status()
                    decision = "allow" if status != "blocked" else "deny"

                await agent.policy_check(tool, decision, reason="scope not permitted" if decision == "deny" else "")
                if status != "blocked":
                    await agent.tool_call(tool, status, latency=random.uniform(0.01, 0.5))

        await asyncio.sleep(TASK_INTERVAL + random.uniform(0, 0.3))


async def run_agent_admin(start_time: float) -> None:
    """
    agent-admin: high-trust admin. Anomaly = 60% errors → circuit breaker trips.
    Demonstrates the OPEN → HALF_OPEN → CLOSED recovery cycle.
    """
    agent = InstrumentedAgent("agent-admin")
    circuit_open = False
    circuit_open_at: float | None = None
    RECOVERY_TIMEOUT = 20.0   # seconds before half-open probe
    FAILURE_THRESHOLD = 3

    consecutive_errors = 0

    while True:
        elapsed = time.time() - start_time
        in_anomaly = elapsed > ANOMALY_DELAY

        # ── Circuit breaker: check recovery ───────────────────────────────────
        if circuit_open and circuit_open_at:
            if time.time() - circuit_open_at > RECOVERY_TIMEOUT:
                logger.info("[agent-admin] Circuit HALF_OPEN — probing...")
                circuit_open = False
                consecutive_errors = 0
                agent.circuit_breaker_close()

        if circuit_open:
            await asyncio.sleep(2.0)
            continue

        # ── Run task ──────────────────────────────────────────────────────────
        n_llm  = random.randint(1, 3)
        n_tool = random.randint(2, 6)

        try:
            async with agent.task(random.choice(TASKS)):
                for _ in range(n_llm):
                    await agent.llm_call(**_normal_llm_params())

                for _ in range(n_tool):
                    tool = random.choice(TOOLS)
                    if in_anomaly:
                        status = random.choices(
                            ["success", "error"],
                            weights=[0.35, 0.65],
                        )[0]
                    else:
                        status = _normal_tool_status()

                    await agent.policy_check(tool, "allow")
                    await agent.tool_call(tool, status, latency=random.uniform(0.05, 0.8))

                    if status == "error":
                        consecutive_errors += 1
                    else:
                        consecutive_errors = max(0, consecutive_errors - 1)

                    # Trip circuit breaker after threshold
                    if consecutive_errors >= FAILURE_THRESHOLD and not circuit_open:
                        circuit_open = True
                        circuit_open_at = time.time()
                        agent.circuit_breaker_open(
                            trigger="failures",
                            reason=f"{consecutive_errors} consecutive tool errors",
                        )
                        break

        except Exception:
            pass

        await asyncio.sleep(TASK_INTERVAL + random.uniform(0, 0.4))


async def run_injection_events(start_time: float) -> None:
    """
    Simulate sporadic injection detection events from the guardrail gateway.
    Increases in frequency after anomaly threshold.
    """
    agent_reader    = InstrumentedAgent("agent-reader")
    agent_processor = InstrumentedAgent("agent-processor")

    findings_pool = [
        "ignore_instructions", "jailbreak_keywords", "reveal_system_prompt",
        "restrictions_removed", "xml_injection", "delimiter_injection",
        "you_are_now", "authority_claim",
    ]

    while True:
        elapsed = time.time() - start_time
        in_anomaly = elapsed > ANOMALY_DELAY
        # More injection attempts during anomaly period
        interval = random.uniform(5, 15) if in_anomaly else random.uniform(20, 60)

        await asyncio.sleep(interval)

        action = random.choices(
            ["WARN", "FLAG", "BLOCK"],
            weights=[0.3, 0.4, 0.3] if in_anomaly else [0.5, 0.3, 0.2],
        )[0]
        score = {"WARN": random.randint(30, 49), "FLAG": random.randint(50, 79), "BLOCK": random.randint(80, 100)}[action]
        n_findings = random.randint(1, 3) if action == "BLOCK" else 1
        findings = random.sample(findings_pool, min(n_findings, len(findings_pool)))

        agent = random.choice([agent_reader, agent_processor])
        agent.injection_detected(action, score, findings)


# ─────────────────────────────────────────────────────────────────────────────
# Entrypoint
# ─────────────────────────────────────────────────────────────────────────────

async def main() -> None:
    # Start Prometheus metrics HTTP server
    m.start_metrics_server(port=METRICS_PORT)
    logger.info(f"Metrics server started on :{METRICS_PORT}")

    start = time.time()
    logger.info(f"Simulator started. Anomalies begin in {ANOMALY_DELAY}s.")
    logger.info("─" * 50)
    logger.info("  Grafana:    http://localhost:3000  (admin/admin)")
    logger.info("  Metrics:    http://localhost:8000/metrics")
    logger.info("  Prometheus: http://localhost:9090")
    logger.info("─" * 50)

    # Graceful shutdown
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: sys.exit(0))

    await asyncio.gather(
        run_agent_reader(start),
        run_agent_processor(start),
        run_agent_admin(start),
        run_injection_events(start),
    )


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    # Init OTel (won't fail if collector is unreachable)
    init_telemetry("simulator")
    asyncio.run(main())
