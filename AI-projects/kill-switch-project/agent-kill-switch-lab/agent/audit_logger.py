"""
audit_logger.py — append-only structured JSONL audit trail.

Every event the agent takes is logged here before it's acted on.
This gives you forensic replay, compliance evidence, and anomaly detection.

Log format: one JSON object per line (JSONL), timestamped with Unix epoch.
"""
import json
import logging
import time
from pathlib import Path
from typing import Any, Optional


class AuditLogger:
    def __init__(self, log_path: str = "logs/audit.jsonl"):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._logger = logging.getLogger("audit")

    # ── Internal ──────────────────────────────────────────────────────────────

    def _write(self, event_type: str, **kwargs: Any) -> None:
        entry = {"ts": round(time.time(), 3), "event": event_type, **kwargs}
        with self.log_path.open("a") as f:
            f.write(json.dumps(entry) + "\n")
        self._logger.info(json.dumps(entry))

    # ── Public event methods ──────────────────────────────────────────────────

    def log_agent_start(self, agent_id: str, task: str) -> None:
        self._write("agent_start", agent_id=agent_id, task=task[:200])

    def log_llm_call(
        self, agent_id: str, model: str, input_tokens: int, output_tokens: int
    ) -> None:
        self._write(
            "llm_call",
            agent_id=agent_id,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )

    def log_tool_call_requested(
        self, agent_id: str, tool_name: str, inputs: dict
    ) -> None:
        self._write(
            "tool_call_requested",
            agent_id=agent_id,
            tool=tool_name,
            inputs=inputs,
        )

    def log_policy_decision(
        self, agent_id: str, tool_name: str, allowed: bool, reason: str
    ) -> None:
        self._write(
            "policy_decision",
            agent_id=agent_id,
            tool=tool_name,
            allowed=allowed,
            reason=reason,
        )

    def log_tool_result(
        self,
        agent_id: str,
        tool_name: str,
        result: Any,
        error: Optional[str] = None,
    ) -> None:
        self._write(
            "tool_result",
            agent_id=agent_id,
            tool=tool_name,
            result=str(result)[:500] if result is not None else None,
            error=error,
        )

    def log_circuit_state(
        self, agent_id: str, state: str, reason: Optional[str] = None
    ) -> None:
        self._write(
            "circuit_state_change",
            agent_id=agent_id,
            state=state,
            reason=reason,
        )

    def log_kill_switch(
        self, agent_id: str, reason: str, triggered_by: str
    ) -> None:
        self._write(
            "kill_switch_triggered",
            agent_id=agent_id,
            reason=reason,
            triggered_by=triggered_by,
        )

    def log_agent_complete(self, agent_id: str, output: str) -> None:
        self._write("agent_complete", agent_id=agent_id, output=output[:500])
