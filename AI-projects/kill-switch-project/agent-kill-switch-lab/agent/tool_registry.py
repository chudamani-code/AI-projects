"""
tool_registry.py — every tool carries a scope label.

The agent is constructed with an explicit allowed_scopes list.
Only tools whose scope is in that list are ever sent to the LLM.
Attempts to call out-of-scope tools are blocked before OPA is even consulted.

Scope taxonomy (extend as needed):
  read:fs        read local filesystem
  write:fs       write local filesystem
  network:external  outbound HTTP/external APIs
  db:read        read from a database
  db:write       write to a database
  iam:read       read IAM/cloud config
"""
from dataclasses import dataclass
from typing import Any, Callable, Optional


@dataclass
class Tool:
    name: str
    description: str
    scope: str
    handler: Callable[..., Any]
    input_schema: dict


class ToolRegistry:
    def __init__(self, allowed_scopes: list[str]):
        self.allowed_scopes: set[str] = set(allowed_scopes)
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def get_tool(self, name: str) -> Optional[Tool]:
        return self._tools.get(name)

    def is_scope_allowed(self, scope: str) -> bool:
        return scope in self.allowed_scopes

    def get_anthropic_tools(self) -> list[dict]:
        """
        Return only the tools whose scope is permitted.
        The LLM never even learns that out-of-scope tools exist.
        """
        return [
            {
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
            }
            for t in self._tools.values()
            if t.scope in self.allowed_scopes
        ]

    def execute(self, name: str, inputs: dict) -> Any:
        tool = self._tools.get(name)
        if not tool:
            raise ValueError(f"Unknown tool: {name}")
        if tool.scope not in self.allowed_scopes:
            raise PermissionError(
                f"Tool '{name}' requires scope '{tool.scope}' which is not in "
                f"allowed scopes {self.allowed_scopes}"
            )
        return tool.handler(**inputs)
