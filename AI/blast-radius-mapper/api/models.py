"""
models.py — Pydantic response models.

These define the shape of every API response so the frontend
gets consistent, typed data to work with.
"""
from typing import Optional
from pydantic import BaseModel


# ── Graph nodes ───────────────────────────────────────────────────────────────

class AgentNode(BaseModel):
    id: str
    name: str
    trust_level: str          # LOW | MEDIUM | HIGH
    description: str


class ToolNode(BaseModel):
    name: str
    scope: str
    description: str


class ResourceNode(BaseModel):
    id: str
    name: str
    type: str                 # S3Bucket | Database | SecretStore | Lambda | EC2 | API
    sensitivity: str          # LOW | MEDIUM | HIGH | CRITICAL
    description: str


class ScopeNode(BaseModel):
    name: str


# ── Blast radius analysis ─────────────────────────────────────────────────────

class AccessPath(BaseModel):
    """One route from an agent to a resource."""
    tool_name: str
    scope_name: str
    resource: ResourceNode
    access_type: str          # read | write | invoke | assume


class LateralPath(BaseModel):
    """A resource reachable via lateral movement from a directly accessible resource."""
    pivot_resource: ResourceNode      # the resource the agent can directly access
    lateral_resource: ResourceNode    # the resource reached via lateral movement
    method: str                       # env_vars | instance_profile | imds | log_injection
    hop_count: int


class BlastRadiusReport(BaseModel):
    agent_id: str
    agent: AgentNode
    direct_resources: list[ResourceNode]
    lateral_resources: list[ResourceNode]
    access_paths: list[AccessPath]
    lateral_paths: list[LateralPath]
    total_unique_resources: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    risk_score: int                   # 0–100 weighted by sensitivity


# ── What-if analysis ──────────────────────────────────────────────────────────

class WhatIfRequest(BaseModel):
    agent_id: str
    add_scope: str            # e.g. "scope:s3:read"


class WhatIfReport(BaseModel):
    agent_id: str
    add_scope: str
    new_direct_resources: list[ResourceNode]      # newly reachable
    new_lateral_resources: list[ResourceNode]     # newly reachable via lateral
    incremental_risk_delta: int
    description: str


# ── Attack path ───────────────────────────────────────────────────────────────

class AttackStep(BaseModel):
    node_type: str            # Agent | Tool | Scope | Resource
    node_id: str
    node_label: str
    edge_label: str           # relationship type (or "" for last node)


class AttackPathReport(BaseModel):
    agent_id: str
    target_resource_id: str
    paths: list[list[AttackStep]]
    shortest_hop_count: int


# ── Vis.js graph format ───────────────────────────────────────────────────────

class VisNode(BaseModel):
    id: str
    label: str
    group: str                # agent | tool | scope | resource
    title: str                # hover tooltip (HTML)
    sensitivity: Optional[str] = None


class VisEdge(BaseModel):
    from_: str
    to: str
    label: str
    dashes: bool = False

    class Config:
        populate_by_name = True


class VisGraph(BaseModel):
    nodes: list[VisNode]
    edges: list[VisEdge]
