"""
test_tool_registry.py — tests for scope enforcement at the registry layer.

Run: python -m pytest tests/ -v
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))

import pytest
from tool_registry import Tool, ToolRegistry


def _make_registry(scopes: list[str]) -> ToolRegistry:
    reg = ToolRegistry(allowed_scopes=scopes)
    reg.register(Tool(
        name="read_file",
        description="Read a file",
        scope="read:fs",
        handler=lambda path: f"contents of {path}",
        input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
    ))
    reg.register(Tool(
        name="web_search",
        description="Search the web",
        scope="network:external",
        handler=lambda query: f"results for {query}",
        input_schema={"type": "object", "properties": {"query": {"type": "string"}}},
    ))
    return reg


def test_allowed_scope_tool_appears_in_definitions():
    reg = _make_registry(["read:fs"])
    tools = reg.get_anthropic_tools()
    names = [t["name"] for t in tools]
    assert "read_file" in names


def test_denied_scope_tool_hidden_from_llm():
    reg = _make_registry(["read:fs"])
    tools = reg.get_anthropic_tools()
    names = [t["name"] for t in tools]
    assert "web_search" not in names  # LLM never sees this


def test_execute_allowed_tool_succeeds():
    reg = _make_registry(["read:fs"])
    result = reg.execute("read_file", {"path": "test.txt"})
    assert "contents of test.txt" in result


def test_execute_denied_scope_raises_permission_error():
    reg = _make_registry(["read:fs"])  # network:external NOT included
    with pytest.raises(PermissionError):
        reg.execute("web_search", {"query": "hello"})


def test_execute_unknown_tool_raises_value_error():
    reg = _make_registry(["read:fs"])
    with pytest.raises(ValueError):
        reg.execute("nonexistent_tool", {})


def test_scope_check_returns_false_for_missing_scope():
    reg = _make_registry(["read:fs"])
    assert reg.is_scope_allowed("read:fs") is True
    assert reg.is_scope_allowed("write:fs") is False
    assert reg.is_scope_allowed("network:external") is False
