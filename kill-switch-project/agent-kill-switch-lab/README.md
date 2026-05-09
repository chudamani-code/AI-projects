# Scoped AI Agent with Kill Switch

A production-pattern Python project demonstrating the core AI cloud security
controls that architect-level roles require: scoped permissions, OPA policy
enforcement, circuit breaker kill switch, and an append-only audit trail.

Built as an interview portfolio project by a Cloud Security Engineer upskilling
into AI Cloud Security Architecture.

---

## Architecture

```
User prompt
    │
    ▼
ScopedAgent.run()
    │
    ├─► [Kill switch] ─── file watcher (any operator drops a file to halt)
    │                  ── OS signal handler (SIGTERM from K8s/orchestrator)
    │
    ├─► Anthropic API
    │   └── tools = only scopes in allowed_scopes (LLM never sees the rest)
    │
    └─► For each tool_use block:
            │
            ├─► Gate 1: ToolRegistry.is_scope_allowed()       in-process, 0ms
            ├─► Gate 2: PolicyClient → OPA sidecar            ~1ms LAN
            ├─► Gate 3: CircuitBreaker state check            in-process, 0ms
            └─► ToolRegistry.execute()                        actual execution

Audit logger writes every event to logs/audit.jsonl (append-only JSONL)
```

---

## Files

```
agent-kill-switch-lab/
├── agent/
│   ├── main.py            # Agent loop — ties everything together
│   ├── circuit_breaker.py # CLOSED → OPEN → HALF_OPEN state machine
│   ├── tool_registry.py   # Tool inventory + scope enforcement
│   ├── policy_client.py   # OPA REST client (fail-closed)
│   ├── audit_logger.py    # Append-only JSONL audit trail
│   ├── Dockerfile
│   └── requirements.txt
├── opa/
│   ├── policy.rego        # Rego authorization rules
│   └── data.json          # Agent registry + allowed scopes
├── data/                  # Sample files the agent can read
├── logs/                  # audit.jsonl lands here
├── tests/
│   ├── test_circuit_breaker.py
│   └── test_tool_registry.py
└── docker-compose.yml
```

---

## Quickstart (local, no Docker)

### 1. Install dependencies
```bash
cd agent
pip install -r requirements.txt
```

### 2. Start OPA
```bash
# Install OPA: https://www.openpolicyagent.org/docs/latest/#1-download-opa
opa run --server opa/policy.rego opa/data.json
```

### 3. Set your API key and run
```bash
export ANTHROPIC_API_KEY=sk-ant-...
python agent/main.py "List the files and summarize their contents."
```

---

## Quickstart (Docker Compose)

```bash
export ANTHROPIC_API_KEY=sk-ant-...
docker compose up --build
```

OPA starts first. The agent waits for OPA's healthcheck before connecting.

---

## Kill switch demos

### File-based kill switch (simulates ops team intervention)
```bash
# In a second terminal while the agent is running:
echo "ops triggered halt — runbook #42" > /tmp/agent_kill

# The agent detects this file on its next loop iteration and halts.
# Remove the file to allow future runs:
rm /tmp/agent_kill
```

### Signal-based kill switch (simulates Kubernetes termination)
```bash
kill -TERM $(pgrep -f "python main.py")
```

### Automatic kill switch (circuit breaker trips on violations)
Set `AGENT_ID=agent-unknown` in your environment — OPA will deny every tool call.
After 2 violations, the circuit breaker trips automatically.

---

## OPA policy queries (manual testing)

```bash
# Should return {"result": true}
curl -s -X POST http://localhost:8181/v1/data/agent/allow \
  -H 'Content-Type: application/json' \
  -d '{
    "input": {
      "agent_id": "agent-001",
      "tool_name": "read_file",
      "tool_scope": "read:fs",
      "inputs": {"path": "notes.txt"},
      "context": {}
    }
  }' | python3 -m json.tool

# Should return {"result": false} — path traversal
curl -s -X POST http://localhost:8181/v1/data/agent/allow \
  -H 'Content-Type: application/json' \
  -d '{
    "input": {
      "agent_id": "agent-001",
      "tool_name": "read_file",
      "tool_scope": "read:fs",
      "inputs": {"path": "../../etc/passwd"},
      "context": {}
    }
  }' | python3 -m json.tool

# Fetch the denial reason
curl -s -X POST http://localhost:8181/v1/data/agent/deny_reason \
  -H 'Content-Type: application/json' \
  -d '{"input":{"agent_id":"unknown-agent","tool_name":"read_file","tool_scope":"read:fs","inputs":{}}}' \
  | python3 -m json.tool
```

---

## Run the tests

```bash
pip install pytest
python -m pytest tests/ -v
```

---

## Security controls demonstrated

| Control | Implementation | File |
|---|---|---|
| Scoped permissions | `ToolRegistry(allowed_scopes=[...])` | `tool_registry.py` |
| LLM never sees out-of-scope tools | `get_anthropic_tools()` filters by scope | `tool_registry.py` |
| Policy-as-code | OPA Rego rules | `opa/policy.rego` |
| Fail-closed policy | OPA unreachable → DENY | `policy_client.py` |
| Path traversal blocking | Rego `has_dangerous_input` rule | `opa/policy.rego` |
| Circuit breaker | 3-state FSM, trips on errors + violations | `circuit_breaker.py` |
| File-based kill switch | Checked every loop iteration | `main.py` |
| Signal-based kill switch | `SIGTERM` / `SIGINT` handler | `main.py` |
| Audit trail | Append-only JSONL, every event | `audit_logger.py` |
| Non-root container | `USER agentuser` in Dockerfile | `Dockerfile` |

---

## Extending this project

- **Add rate limiting**: Track calls-per-minute in OPA external data and add a
  `is_rate_limited` rule to the Rego policy.
- **Add a blast radius mapper**: Feed `allowed_scopes` from `data.json` into
  a Neo4j graph and compute reachability from a compromised agent node.
- **Add OpenTelemetry**: Export spans from `audit_logger.py` to Tempo/Jaeger
  for visual trace analysis.
- **Dynamic scope vending**: Replace the static `data.json` with a Vault
  secrets engine that issues time-limited scope grants per task.
- **Multi-agent trust levels**: Add a `trust_level` field per agent in
  `data.json` and write Rego rules that gate higher-risk scopes behind
  a higher trust level.
