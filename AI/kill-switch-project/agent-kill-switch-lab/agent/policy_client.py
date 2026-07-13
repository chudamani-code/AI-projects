"""
policy_client.py — talks to the OPA REST API before every tool call.

Fail-closed design: if OPA is unreachable, the call is DENIED.
This is the correct default for a security control.

OPA runs as a sidecar on http://opa:8181 (Docker) or http://localhost:8181 (local).
"""
import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


class PolicyClient:
    def __init__(self, opa_url: str = "http://localhost:8181", timeout: float = 2.0):
        self.opa_url = opa_url.rstrip("/")
        self.timeout = timeout

    def is_tool_call_allowed(
        self,
        agent_id: str,
        tool_name: str,
        tool_scope: str,
        inputs: dict,
        context: Optional[dict] = None,
    ) -> tuple[bool, str]:
        """
        Ask OPA whether this tool call is allowed.
        Returns (allowed: bool, reason: str).

        OPA evaluates /data/agent/allow and /data/agent/deny_reason.
        """
        payload = {
            "input": {
                "agent_id": agent_id,
                "tool_name": tool_name,
                "tool_scope": tool_scope,
                "inputs": inputs,
                "context": context or {},
            }
        }
        try:
            resp = httpx.post(
                f"{self.opa_url}/v1/data/agent/allow",
                json=payload,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            allowed: bool = resp.json().get("result", False)

            if allowed:
                return True, "policy allowed"

            # Fetch the specific denial reason
            reason_resp = httpx.post(
                f"{self.opa_url}/v1/data/agent/deny_reason",
                json=payload,
                timeout=self.timeout,
            )
            reason_resp.raise_for_status()
            reason: str = reason_resp.json().get("result", "policy denied (no reason)")
            return False, reason

        except httpx.HTTPError as exc:
            # OPA unreachable → fail closed
            msg = f"OPA unreachable ({exc}). Defaulting to DENY."
            logger.warning(msg)
            return False, msg
        except Exception as exc:
            msg = f"Unexpected error querying OPA: {exc}. Defaulting to DENY."
            logger.error(msg)
            return False, msg
