"""
models.py — request/response shapes for the role vending API.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, field_validator


# ── Request models ────────────────────────────────────────────────────────────

class ResourceConstraints(BaseModel):
    """
    Narrows the session policy to specific resources.
    Only the fields relevant to the requested task_type are used.
    """
    # S3
    s3_buckets: list[str] = Field(default_factory=list)
    s3_prefix: str = ""

    # Secrets Manager
    secret_names: list[str] = Field(default_factory=list)

    # Lambda
    function_names: list[str] = Field(default_factory=list)

    # EC2 (no resource-level restrictions available for Describe*)
    regions: list[str] = Field(default_factory=list)


class IssueCredentialRequest(BaseModel):
    agent_id: str = Field(..., description="Agent requesting the credentials")
    task_type: str = Field(..., description="Type of task to be performed")
    task_description: str = Field(..., max_length=500, description="Human-readable description of the task")
    resource_constraints: ResourceConstraints = Field(default_factory=ResourceConstraints)
    duration_seconds: int = Field(default=900, ge=900, le=43200, description="Credential lifetime (15min–12hr)")
    context: dict = Field(default_factory=dict, description="Arbitrary metadata stored in audit log")

    @field_validator("task_type")
    @classmethod
    def validate_task_type(cls, v: str) -> str:
        from engine import TASK_CONFIGS
        if v not in TASK_CONFIGS:
            raise ValueError(f"Unknown task_type '{v}'. Valid: {list(TASK_CONFIGS)}")
        return v


class RevokeCredentialRequest(BaseModel):
    reason: str = Field(default="manual revocation", max_length=500)


# ── Response models ───────────────────────────────────────────────────────────

class IssuedCredential(BaseModel):
    credential_id: str
    agent_id: str
    task_type: str
    task_description: str

    # STS credential fields
    access_key_id: str
    secret_access_key: str
    session_token: str

    # Lifecycle
    issued_at: datetime
    expires_at: datetime
    duration_seconds: int

    # Role details
    role_arn: str
    role_name: str

    # What the session policy actually allows (human-readable)
    effective_permissions: list[str]

    # Audit
    resource_constraints: ResourceConstraints
    context: dict


class CredentialSummary(BaseModel):
    """Returned in list endpoints — no secret values."""
    credential_id: str
    agent_id: str
    task_type: str
    task_description: str
    status: str          # active | expired | revoked
    issued_at: datetime
    expires_at: datetime
    duration_seconds: int
    role_arn: str
    effective_permissions: list[str]
    revoke_reason: Optional[str] = None


class AuditEntry(BaseModel):
    id: int
    ts: float
    event: str
    credential_id: Optional[str]
    agent_id: Optional[str]
    task_type: Optional[str]
    role_arn: Optional[str]
    duration_seconds: Optional[int]
    resource_constraints: Optional[dict]
    context: Optional[dict]
    details: Optional[str]


class AgentInfo(BaseModel):
    agent_id: str
    trust_level: str
    allowed_task_types: list[str]
    max_duration_by_task: dict[str, int]
