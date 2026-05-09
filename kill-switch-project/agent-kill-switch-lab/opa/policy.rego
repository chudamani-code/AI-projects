# opa/policy.rego
#
# Authorization policy for AI agent tool calls.
# Evaluated by the OPA REST API at /v1/data/agent/allow
#
# Input shape:
# {
#   "agent_id":   "agent-001",
#   "tool_name":  "write_file",
#   "tool_scope": "write:fs",
#   "inputs":     { "path": "report.txt", "content": "..." },
#   "context":    {}
# }

package agent

import future.keywords.in

# ── Default deny (fail-closed) ────────────────────────────────────────────────
default allow := false
default deny_reason := "default deny"

# ── Main allow rule ───────────────────────────────────────────────────────────
# ALL conditions must be true for a tool call to be permitted.

allow if {
    is_known_agent
    is_allowed_scope
    not has_dangerous_input
}

# ── Sub-rules ─────────────────────────────────────────────────────────────────

is_known_agent if {
    input.agent_id in data.agents.allowed_ids
}

is_allowed_scope if {
    input.tool_scope in data.agents.allowed_scopes[input.agent_id]
}

# Block path traversal in any path input
has_dangerous_input if {
    some key, val in input.inputs
    is_string(val)
    contains(val, "..")
}

# Block absolute paths that look like system directories
has_dangerous_input if {
    input.inputs.path
    startswith(input.inputs.path, "/etc")
}

has_dangerous_input if {
    input.inputs.path
    startswith(input.inputs.path, "/proc")
}

has_dangerous_input if {
    input.inputs.path
    startswith(input.inputs.path, "/sys")
}

# Block writes larger than 1 MB
has_dangerous_input if {
    input.tool_name == "write_file"
    count(input.inputs.content) > 1000000
}

# ── Denial reason (only evaluated when allow = false) ─────────────────────────

deny_reason := msg if {
    not is_known_agent
    msg := concat("", ["Unknown agent ID: ", input.agent_id])
}

deny_reason := msg if {
    is_known_agent
    not is_allowed_scope
    msg := concat("", [
        "Scope '", input.tool_scope,
        "' not permitted for agent '", input.agent_id, "'"
    ])
}

deny_reason := "Path traversal detected in inputs" if {
    some key, val in input.inputs
    is_string(val)
    contains(val, "..")
}

deny_reason := msg if {
    input.inputs.path
    startswith(input.inputs.path, "/etc")
    msg := concat("", ["Write to system path blocked: ", input.inputs.path])
}

deny_reason := "Content exceeds 1 MB write limit" if {
    input.tool_name == "write_file"
    count(input.inputs.content) > 1000000
}
