"""
main.py — scoped AI agent with kill switch, OPA policy enforcement,
          circuit breaker, and full audit trail.

Architecture:
  User prompt
      │
      ▼
  ScopedAgent.run()
      │
      ├─► [kill switch checks] ── file watcher + OS signal handler
      │
      ├─► Anthropic API (tool definitions = only allowed-scope tools)
      │
      └─► For each tool_use block:
              │
              ├─► ToolRegistry.is_scope_allowed()   ← first gate (in-process)
              ├─► PolicyClient.is_tool_call_allowed() ← second gate (OPA sidecar)
              ├─► CircuitBreaker.record_*()          ← trip on violations/errors
              └─► ToolRegistry.execute()             ← actual execution

Run locally (no Docker):
  export ANTHROPIC_API_KEY=sk-...
  python main.py "List the files and summarize each one."

Run with Docker Compose:
  docker compose up
"""
import json
import logging
import os
import signal
import sys
from pathlib import Path

import anthropic

from audit_logger import AuditLogger
from circuit_breaker import CircuitBreaker, CircuitState
from policy_client import PolicyClient
from tool_registry import Tool, ToolRegistry

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("agent")

# ── Configuration ─────────────────────────────────────────────────────────────
AGENT_ID = os.getenv("AGENT_ID", "agent-001")
OPA_URL = os.getenv("OPA_URL", "http://localhost:8181")
MODEL = os.getenv("MODEL", "claude-sonnet-4-20250514")
# Drop this file (with any content) to kill the agent mid-run
KILL_SWITCH_FILE = Path(os.getenv("KILL_SWITCH_FILE", "/tmp/agent_kill"))


# ── Tool implementations ──────────────────────────────────────────────────────

def read_file(path: str) -> str:
    """Read a file; constrained to /data directory."""
    safe_path = Path("/data") / Path(path).name  # strip traversal attempts
    if not safe_path.exists():
        return f"File not found: {path}"
    return safe_path.read_text(encoding="utf-8", errors="replace")


def list_files(directory: str = ".") -> str:
    """List files in /data."""
    data_dir = Path("/data")
    files = [f.name for f in data_dir.iterdir() if f.is_file()]
    return json.dumps(files)


def write_file(path: str, content: str) -> str:
    """Write to /data/output only."""
    safe_path = Path("/data/output") / Path(path).name
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(content, encoding="utf-8")
    return f"Written {len(content)} bytes to {safe_path}"


def web_search(query: str) -> str:
    """Stub: replace with real implementation. Scope: network:external."""
    return f"[STUB] Search results for: {query}"


# ── Registry factory ──────────────────────────────────────────────────────────

def build_registry() -> ToolRegistry:
    """
    SECURITY DECISION POINT: the scopes listed here define the agent's
    maximum capability surface. 'network:external' is intentionally excluded —
    the LLM will never see the web_search tool definition.
    """
    registry = ToolRegistry(allowed_scopes=["read:fs", "write:fs"])

    registry.register(Tool(
        name="read_file",
        description="Read the text contents of a file from the data directory.",
        scope="read:fs",
        handler=read_file,
        input_schema={
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Filename to read"}},
            "required": ["path"],
        },
    ))

    registry.register(Tool(
        name="list_files",
        description="List all files available in the data directory.",
        scope="read:fs",
        handler=list_files,
        input_schema={
            "type": "object",
            "properties": {"directory": {"type": "string", "description": "Ignored; always lists /data"}},
        },
    ))

    registry.register(Tool(
        name="write_file",
        description="Write content to a file in the output directory.",
        scope="write:fs",
        handler=write_file,
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Output filename"},
                "content": {"type": "string", "description": "Content to write"},
            },
            "required": ["path", "content"],
        },
    ))

    # Registered but NEVER offered to the LLM — scope not in allowed_scopes
    registry.register(Tool(
        name="web_search",
        description="Search the web.",
        scope="network:external",
        handler=web_search,
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    ))

    return registry


# ── Agent ─────────────────────────────────────────────────────────────────────

class ScopedAgent:
    """
    A scoped AI agent with:
    - Explicit allow-list of tool scopes
    - OPA sidecar for per-call policy decisions
    - Circuit breaker that halts on errors or policy violations
    - File-based + signal-based kill switch
    - Append-only audit trail (JSONL)
    """

    def __init__(self) -> None:
        self.client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        self.registry = build_registry()
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=3,
            violation_threshold=2,
            recovery_timeout=30.0,
        )
        self.policy = PolicyClient(opa_url=OPA_URL)
        self.audit = AuditLogger(log_path="logs/audit.jsonl")
        self.messages: list[dict] = []

        # OS-level kill switch: SIGTERM from orchestrator/Kubernetes
        signal.signal(signal.SIGTERM, self._signal_kill)
        signal.signal(signal.SIGINT, self._signal_kill)

    # ── Kill switch mechanisms ────────────────────────────────────────────────

    def _signal_kill(self, signum: int, frame: object) -> None:
        reason = f"OS signal {signum} received"
        self.circuit_breaker.force_kill(reason=reason)
        self.audit.log_kill_switch(AGENT_ID, reason=reason, triggered_by="os_signal")
        logger.warning(f"Kill switch triggered: {reason}")
        sys.exit(1)

    def _check_file_kill_switch(self) -> None:
        """
        File-based kill switch: any operator can drop a file at KILL_SWITCH_FILE.
        The agent detects it on every loop iteration.
        This lets you halt a running agent without SSH access to the container.
        """
        if KILL_SWITCH_FILE.exists():
            try:
                reason = KILL_SWITCH_FILE.read_text().strip() or "kill switch file present"
            except OSError:
                reason = "kill switch file present"
            self.circuit_breaker.force_kill(reason=reason)
            self.audit.log_kill_switch(
                AGENT_ID, reason=reason, triggered_by="kill_switch_file"
            )

    # ── Main loop ─────────────────────────────────────────────────────────────

    def run(self, user_prompt: str) -> str:
        logger.info(f"Agent {AGENT_ID} starting — task: {user_prompt[:100]}")
        self.audit.log_agent_start(AGENT_ID, user_prompt)
        self.messages = [{"role": "user", "content": user_prompt}]

        while True:
            # ── Check kill switches before every LLM call ─────────────────────
            self._check_file_kill_switch()

            if not self.circuit_breaker.is_operational():
                reason = self.circuit_breaker.kill_reason
                self.audit.log_circuit_state(AGENT_ID, state="open", reason=reason)
                msg = f"[AGENT HALTED] Circuit breaker open: {reason}"
                logger.warning(msg)
                return msg

            # ── Call the LLM ──────────────────────────────────────────────────
            try:
                response = self.client.messages.create(
                    model=MODEL,
                    max_tokens=1024,
                    tools=self.registry.get_anthropic_tools(),
                    messages=self.messages,
                )
            except Exception as exc:
                logger.error(f"LLM call failed: {exc}")
                self.circuit_breaker.record_failure(str(exc))
                continue  # retry (circuit breaker will eventually trip)

            self.audit.log_llm_call(
                AGENT_ID,
                model=MODEL,
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens,
            )

            # ── Task complete ─────────────────────────────────────────────────
            if response.stop_reason == "end_turn":
                text = next(
                    (b.text for b in response.content if hasattr(b, "text")), ""
                )
                self.circuit_breaker.record_success()
                self.audit.log_agent_complete(AGENT_ID, text)
                return text

            # ── Process tool calls ────────────────────────────────────────────
            self.messages.append({"role": "assistant", "content": response.content})
            tool_results = []

            for block in response.content:
                if block.type != "tool_use":
                    continue

                tool_name: str = block.name
                tool_inputs: dict = block.input
                self.audit.log_tool_call_requested(AGENT_ID, tool_name, tool_inputs)

                # Gate 1 — Scope check (in-process, zero latency)
                tool = self.registry.get_tool(tool_name)
                if not tool or not self.registry.is_scope_allowed(tool.scope):
                    scope = tool.scope if tool else "unknown"
                    reason = f"Scope '{scope}' not in allowed scopes"
                    self.circuit_breaker.record_policy_violation(reason)
                    self.audit.log_policy_decision(AGENT_ID, tool_name, False, reason)
                    tool_results.append(_denied_result(block.id, reason))
                    continue

                # Gate 2 — OPA policy check (sidecar, ~1ms LAN latency)
                allowed, reason = self.policy.is_tool_call_allowed(
                    agent_id=AGENT_ID,
                    tool_name=tool_name,
                    tool_scope=tool.scope,
                    inputs=tool_inputs,
                )
                self.audit.log_policy_decision(AGENT_ID, tool_name, allowed, reason)

                if not allowed:
                    self.circuit_breaker.record_policy_violation(reason)
                    tool_results.append(_denied_result(block.id, reason))
                    continue

                # Gate 3 — Execute
                try:
                    result = self.registry.execute(tool_name, tool_inputs)
                    self.circuit_breaker.record_success()
                    self.audit.log_tool_result(AGENT_ID, tool_name, result)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": str(result),
                    })
                except Exception as exc:
                    self.circuit_breaker.record_failure(str(exc))
                    self.audit.log_tool_result(AGENT_ID, tool_name, None, error=str(exc))
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": f"[ERROR] {exc}",
                        "is_error": True,
                    })

            self.messages.append({"role": "user", "content": tool_results})


def _denied_result(tool_use_id: str, reason: str) -> dict:
    return {
        "type": "tool_result",
        "tool_use_id": tool_use_id,
        "content": f"[BLOCKED] {reason}",
        "is_error": True,
    }


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    task = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "List the files in the data directory and write a brief summary of each one to summary.txt."
    )
    agent = ScopedAgent()
    result = agent.run(task)
    print("\n── Agent result " + "─" * 50)
    print(result)
