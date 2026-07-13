"""
engine.py — permission decision engine.

Responsibilities:
  1. Agent registry — who is allowed to request what
  2. Task config   — what base role and actions each task type uses
  3. Session policy builder — generates the least-privilege session policy
     for a specific task + resource_constraints combination
  4. Duration validator — enforces per-trust-level duration caps

The double-lock model:
  Base role (Terraform)  = broad capability gate  (e.g., "can read ANY S3")
  Session policy (here)  = narrow resource gate   (e.g., "only logs-bucket/2026/05/*")

Even if the session policy is bypassed, the base role still limits the blast radius.
Even if the base role is over-permissioned, the session policy still restricts the call.
"""
import json
import os
from dataclasses import dataclass, field
from typing import Optional

ACCOUNT_ID = os.getenv("AWS_ACCOUNT_ID", "000000000000")
REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")


# ── Agent registry ────────────────────────────────────────────────────────────

@dataclass
class AgentConfig:
    trust_level: str                   # LOW | MEDIUM | HIGH
    allowed_task_types: list[str]


AGENT_REGISTRY: dict[str, AgentConfig] = {
    "agent-reader":    AgentConfig(trust_level="LOW",    allowed_task_types=["read_s3"]),
    "agent-processor": AgentConfig(trust_level="MEDIUM", allowed_task_types=["read_s3", "write_s3", "invoke_lambda"]),
    "agent-admin":     AgentConfig(trust_level="HIGH",   allowed_task_types=["read_s3", "write_s3", "read_secrets", "invoke_lambda", "describe_ec2"]),
    "agent-analyst":   AgentConfig(trust_level="MEDIUM", allowed_task_types=["read_s3", "describe_ec2"]),
}


# ── Task configuration ────────────────────────────────────────────────────────

@dataclass
class TaskConfig:
    base_role_name: str
    actions: list[str]
    # Max duration seconds per trust level (None = not permitted)
    max_duration: dict[str, Optional[int]]
    required_constraints: list[str]     # fields in ResourceConstraints that must be non-empty
    minimum_trust: str = "LOW"          # minimum trust level to request this task type


TASK_CONFIGS: dict[str, TaskConfig] = {
    "read_s3": TaskConfig(
        base_role_name="role-agent-read-s3",
        actions=["s3:GetObject", "s3:ListBucket"],
        max_duration={"LOW": 3600, "MEDIUM": 7200, "HIGH": 14400},
        required_constraints=["s3_buckets"],
    ),
    "write_s3": TaskConfig(
        base_role_name="role-agent-write-s3",
        actions=["s3:PutObject"],
        max_duration={"LOW": None, "MEDIUM": 1800, "HIGH": 3600},
        required_constraints=["s3_buckets"],
        minimum_trust="MEDIUM",
    ),
    "read_secrets": TaskConfig(
        base_role_name="role-agent-secrets",
        actions=["secretsmanager:GetSecretValue"],
        max_duration={"LOW": None, "MEDIUM": 900, "HIGH": 1800},
        required_constraints=["secret_names"],
        minimum_trust="MEDIUM",
    ),
    "invoke_lambda": TaskConfig(
        base_role_name="role-agent-lambda",
        actions=["lambda:InvokeFunction"],
        max_duration={"LOW": None, "MEDIUM": 3600, "HIGH": 7200},
        required_constraints=["function_names"],
        minimum_trust="MEDIUM",
    ),
    "describe_ec2": TaskConfig(
        base_role_name="role-agent-ec2",
        actions=["ec2:DescribeInstances", "ec2:DescribeSecurityGroups"],
        max_duration={"LOW": None, "MEDIUM": 3600, "HIGH": 7200},
        required_constraints=[],      # EC2 Describe* doesn't support resource-level restrictions
        minimum_trust="MEDIUM",
    ),
}

TRUST_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


# ── Validation ────────────────────────────────────────────────────────────────

class VendingError(Exception):
    """Raised when a credential request is invalid or unauthorised."""
    pass


def validate_request(
    agent_id: str,
    task_type: str,
    resource_constraints,
    duration_seconds: int,
) -> tuple[AgentConfig, TaskConfig]:
    """
    Validate a credential request. Returns (agent_config, task_config) on success.
    Raises VendingError with a descriptive message on failure.
    """
    # Agent must be in the registry
    agent = AGENT_REGISTRY.get(agent_id)
    if not agent:
        raise VendingError(f"Unknown agent '{agent_id}'")

    # Task type must exist
    task = TASK_CONFIGS.get(task_type)
    if not task:
        raise VendingError(f"Unknown task_type '{task_type}'")

    # Agent must be authorised for this task type
    if task_type not in agent.allowed_task_types:
        raise VendingError(
            f"Agent '{agent_id}' (trust={agent.trust_level}) is not authorised "
            f"for task_type '{task_type}'. Allowed: {agent.allowed_task_types}"
        )

    # Agent trust level must meet task minimum
    if TRUST_ORDER.get(agent.trust_level, 0) < TRUST_ORDER.get(task.minimum_trust, 0):
        raise VendingError(
            f"Task '{task_type}' requires minimum trust level '{task.minimum_trust}', "
            f"but agent '{agent_id}' has trust level '{agent.trust_level}'"
        )

    # Duration must be within the per-trust-level cap
    max_dur = task.max_duration.get(agent.trust_level)
    if max_dur is None:
        raise VendingError(
            f"Task '{task_type}' is not available to agents with trust level '{agent.trust_level}'"
        )
    if duration_seconds > max_dur:
        raise VendingError(
            f"Requested duration {duration_seconds}s exceeds maximum {max_dur}s "
            f"for trust level '{agent.trust_level}' on task '{task_type}'"
        )

    # Required resource constraints must be present
    for field in task.required_constraints:
        val = getattr(resource_constraints, field, None)
        if not val:
            raise VendingError(
                f"Task '{task_type}' requires resource constraint '{field}' to be non-empty"
            )

    return agent, task


# ── Session policy builder ────────────────────────────────────────────────────

def build_session_policy(task_type: str, resource_constraints) -> dict:
    """
    Build the least-privilege session policy for a specific task execution.

    The session policy is passed to STS AssumeRole and FURTHER restricts
    what the assumed role can do — even if the base role is broad.

    AWS evaluates: effective_permissions = base_role_policy ∩ session_policy
    So the session policy can only restrict, never expand.
    """
    statements = []

    if task_type == "read_s3":
        buckets = resource_constraints.s3_buckets
        prefix = resource_constraints.s3_prefix.lstrip("/")

        # Allow GetObject on specific bucket + prefix
        object_resources = []
        for bucket in buckets:
            if prefix:
                object_resources.append(f"arn:aws:s3:::{bucket}/{prefix}*")
            else:
                object_resources.append(f"arn:aws:s3:::{bucket}/*")

        statements.append({
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": object_resources,
        })
        statements.append({
            "Effect": "Allow",
            "Action": ["s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{b}" for b in buckets],
            **({"Condition": {"StringLike": {"s3:prefix": [f"{prefix}*"]}}} if prefix else {}),
        })

    elif task_type == "write_s3":
        buckets = resource_constraints.s3_buckets
        prefix = resource_constraints.s3_prefix.lstrip("/")
        resources = []
        for bucket in buckets:
            resources.append(f"arn:aws:s3:::{bucket}/{prefix}*" if prefix else f"arn:aws:s3:::{bucket}/*")

        statements.append({
            "Effect": "Allow",
            "Action": ["s3:PutObject"],
            "Resource": resources,
        })

    elif task_type == "read_secrets":
        secret_names = resource_constraints.secret_names
        resources = [
            f"arn:aws:secretsmanager:{REGION}:{ACCOUNT_ID}:secret:{name}*"
            for name in secret_names
        ]
        statements.append({
            "Effect": "Allow",
            "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
            "Resource": resources,
        })

    elif task_type == "invoke_lambda":
        function_names = resource_constraints.function_names
        resources = [
            f"arn:aws:lambda:{REGION}:{ACCOUNT_ID}:function:{name}"
            for name in function_names
        ]
        statements.append({
            "Effect": "Allow",
            "Action": ["lambda:InvokeFunction"],
            "Resource": resources,
        })

    elif task_type == "describe_ec2":
        # EC2 Describe* doesn't support resource-level restrictions
        # Session policy must allow * but base role is read-only
        statements.append({
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeVpcs",
                "ec2:DescribeSubnets",
            ],
            "Resource": "*",
        })

    return {"Version": "2012-10-17", "Statement": statements}


def describe_effective_permissions(task_type: str, resource_constraints) -> list[str]:
    """
    Returns a human-readable list of what the credential actually allows.
    Stored in the credential record and returned to the caller.
    """
    task = TASK_CONFIGS[task_type]
    lines = []

    if task_type == "read_s3":
        buckets = resource_constraints.s3_buckets
        prefix = resource_constraints.s3_prefix
        path = f"{', '.join(buckets)}/{prefix}*" if prefix else f"{', '.join(buckets)}/*"
        lines.append(f"s3:GetObject on {path}")
        lines.append(f"s3:ListBucket on {', '.join(buckets)}")

    elif task_type == "write_s3":
        buckets = resource_constraints.s3_buckets
        prefix = resource_constraints.s3_prefix
        path = f"{', '.join(buckets)}/{prefix}*" if prefix else f"{', '.join(buckets)}/*"
        lines.append(f"s3:PutObject on {path}")

    elif task_type == "read_secrets":
        lines.append(f"secretsmanager:GetSecretValue on {', '.join(resource_constraints.secret_names)}")

    elif task_type == "invoke_lambda":
        lines.append(f"lambda:InvokeFunction on {', '.join(resource_constraints.function_names)}")

    elif task_type == "describe_ec2":
        lines.append("ec2:Describe* (read-only, all resources)")

    return lines
