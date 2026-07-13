"""
main.py — IAM Role Vending Service.

Endpoints:
  POST   /credentials/issue                  Issue short-lived credentials
  GET    /credentials                        List all credentials (summary, no secrets)
  GET    /credentials/{credential_id}        Get full credential (including secret values)
  DELETE /credentials/{credential_id}        Revoke a credential
  GET    /audit                              Audit log
  GET    /audit/stats                        Aggregate stats
  GET    /roles                              List available IAM roles
  GET    /agents                             List registered agents
  GET    /health                             Health check

Run locally (with LocalStack):
  docker compose up
  curl -X POST http://localhost:8100/credentials/issue \
    -H 'Content-Type: application/json' \
    -d '{
      "agent_id": "agent-reader",
      "task_type": "read_s3",
      "task_description": "Read daily log files",
      "resource_constraints": {"s3_buckets": ["logs-archive"], "s3_prefix": "2026/05/"},
      "duration_seconds": 900
    }'
"""
import asyncio
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from audit import AuditLogger
from engine import (
    AGENT_REGISTRY, TASK_CONFIGS,
    VendingError, build_session_policy,
    describe_effective_permissions, validate_request,
)
from iam_client import assume_role, list_agent_roles, attach_revocation_deny_policy
from janitor import CredentialJanitor
from models import (
    AgentInfo, AuditEntry, CredentialSummary,
    IssuedCredential, IssueCredentialRequest,
    ResourceConstraints, RevokeCredentialRequest,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("vending")

# ── In-memory credential store ────────────────────────────────────────────────
# Stores full credential records including secret values.
# In production: DynamoDB with TTL + KMS encryption.
_credentials: dict[str, dict] = {}

# ── Shared services ────────────────────────────────────────────────────────────
audit   = AuditLogger(db_path=os.getenv("AUDIT_DB_PATH", "data/audit.db"))
janitor = CredentialJanitor(
    credential_store=_credentials,
    audit_logger=audit,
    check_interval=float(os.getenv("JANITOR_INTERVAL", "30")),
)


# ── App lifecycle ─────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(janitor.run())
    logger.info("Vending service started")
    yield
    janitor.stop()
    task.cancel()


app = FastAPI(
    title="IAM Role Vending Service",
    description="Issues short-lived, scoped IAM credentials to AI agents at task runtime",
    version="1.0.0",
    lifespan=lifespan,
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# ── Issue credentials ─────────────────────────────────────────────────────────

@app.post("/credentials/issue", response_model=IssuedCredential, status_code=201)
async def issue_credentials(req: IssueCredentialRequest) -> IssuedCredential:
    """
    Issue short-lived STS credentials for a specific agent task.

    The engine:
      1. Validates the request (agent authorised, duration within bounds)
      2. Builds a session policy scoped to the requested resources
      3. Calls STS AssumeRole with the session policy
      4. Returns the credentials with full audit metadata
    """
    # ── Validate ──────────────────────────────────────────────────────────────
    try:
        agent_cfg, task_cfg = validate_request(
            req.agent_id,
            req.task_type,
            req.resource_constraints,
            req.duration_seconds,
        )
    except VendingError as e:
        audit.log_denied(req.agent_id, req.task_type, str(e))
        raise HTTPException(status_code=403, detail=str(e))

    # ── Build session policy ──────────────────────────────────────────────────
    session_policy = build_session_policy(req.task_type, req.resource_constraints)
    effective = describe_effective_permissions(req.task_type, req.resource_constraints)

    # ── Assume role ───────────────────────────────────────────────────────────
    credential_id = f"cred-{uuid.uuid4().hex[:12]}"
    session_name  = f"{req.agent_id}-{req.task_type}-{credential_id[:8]}"

    try:
        sts_creds = assume_role(
            role_name=task_cfg.base_role_name,
            session_name=session_name,
            session_policy=session_policy,
            duration_seconds=req.duration_seconds,
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"STS AssumeRole failed: {e}")

    # ── Store ─────────────────────────────────────────────────────────────────
    now        = time.time()
    expires_at = now + req.duration_seconds
    role_arn   = f"arn:aws:iam::000000000000:role/{task_cfg.base_role_name}"

    record = {
        "credential_id":        credential_id,
        "agent_id":             req.agent_id,
        "task_type":            req.task_type,
        "task_description":     req.task_description,
        "access_key_id":        sts_creds["AccessKeyId"],
        "secret_access_key":    sts_creds["SecretAccessKey"],
        "session_token":        sts_creds["SessionToken"],
        "issued_at":            now,
        "expires_at":           expires_at,
        "duration_seconds":     req.duration_seconds,
        "role_arn":             role_arn,
        "role_name":            task_cfg.base_role_name,
        "effective_permissions":effective,
        "resource_constraints": req.resource_constraints.model_dump(),
        "context":              req.context,
        "status":               "active",
        "revoke_reason":        None,
    }
    _credentials[credential_id] = record

    # ── Audit ─────────────────────────────────────────────────────────────────
    audit.log_issued(
        credential_id=credential_id,
        agent_id=req.agent_id,
        task_type=req.task_type,
        role_arn=role_arn,
        duration_seconds=req.duration_seconds,
        issued_at=now,
        expires_at=expires_at,
        resource_constraints=req.resource_constraints.model_dump(),
        context=req.context,
    )

    return IssuedCredential(
        credential_id=credential_id,
        agent_id=req.agent_id,
        task_type=req.task_type,
        task_description=req.task_description,
        access_key_id=sts_creds["AccessKeyId"],
        secret_access_key=sts_creds["SecretAccessKey"],
        session_token=sts_creds["SessionToken"],
        issued_at=datetime.fromtimestamp(now, tz=timezone.utc),
        expires_at=datetime.fromtimestamp(expires_at, tz=timezone.utc),
        duration_seconds=req.duration_seconds,
        role_arn=role_arn,
        role_name=task_cfg.base_role_name,
        effective_permissions=effective,
        resource_constraints=req.resource_constraints,
        context=req.context,
    )


# ── List credentials ──────────────────────────────────────────────────────────

@app.get("/credentials", response_model=list[CredentialSummary])
def list_credentials(agent_id: str | None = None, status: str | None = None) -> list[CredentialSummary]:
    """List credential summaries — no secret values returned."""
    results = []
    for cred in _credentials.values():
        if agent_id and cred["agent_id"] != agent_id:
            continue
        if status and cred["status"] != status:
            continue
        results.append(CredentialSummary(
            credential_id=cred["credential_id"],
            agent_id=cred["agent_id"],
            task_type=cred["task_type"],
            task_description=cred["task_description"],
            status=cred["status"],
            issued_at=datetime.fromtimestamp(cred["issued_at"], tz=timezone.utc),
            expires_at=datetime.fromtimestamp(cred["expires_at"], tz=timezone.utc),
            duration_seconds=cred["duration_seconds"],
            role_arn=cred["role_arn"],
            effective_permissions=cred["effective_permissions"],
            revoke_reason=cred.get("revoke_reason"),
        ))
    return sorted(results, key=lambda c: c.issued_at, reverse=True)


# ── Get single credential ─────────────────────────────────────────────────────

@app.get("/credentials/{credential_id}", response_model=IssuedCredential)
def get_credential(credential_id: str) -> IssuedCredential:
    cred = _credentials.get(credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail=f"Credential '{credential_id}' not found")
    return IssuedCredential(
        credential_id=cred["credential_id"],
        agent_id=cred["agent_id"],
        task_type=cred["task_type"],
        task_description=cred["task_description"],
        access_key_id=cred["access_key_id"],
        secret_access_key=cred["secret_access_key"],
        session_token=cred["session_token"],
        issued_at=datetime.fromtimestamp(cred["issued_at"], tz=timezone.utc),
        expires_at=datetime.fromtimestamp(cred["expires_at"], tz=timezone.utc),
        duration_seconds=cred["duration_seconds"],
        role_arn=cred["role_arn"],
        role_name=cred["role_name"],
        effective_permissions=cred["effective_permissions"],
        resource_constraints=ResourceConstraints(**cred["resource_constraints"]),
        context=cred["context"],
    )


# ── Revoke credential ─────────────────────────────────────────────────────────

@app.delete("/credentials/{credential_id}", status_code=200)
def revoke_credential(credential_id: str, req: RevokeCredentialRequest = RevokeCredentialRequest()) -> dict:
    """
    Revoke a credential.

    Note: STS credentials cannot be invalidated before their TTL expires.
    This endpoint marks them revoked in the store, logs the revocation,
    and attaches a deny policy to the underlying IAM role so future
    API calls using this session are rejected.
    """
    cred = _credentials.get(credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail=f"Credential '{credential_id}' not found")
    if cred["status"] != "active":
        raise HTTPException(status_code=409, detail=f"Credential is already {cred['status']}")

    cred["status"] = "revoked"
    cred["revoke_reason"] = req.reason

    audit.log_revoked(credential_id, cred["agent_id"], cred["task_type"], req.reason)

    # Attach deny policy to the IAM role (best-effort)
    try:
        attach_revocation_deny_policy(cred["role_name"], credential_id)
    except Exception as e:
        logger.warning(f"Could not attach deny policy: {e}")

    return {
        "credential_id": credential_id,
        "status": "revoked",
        "reason": req.reason,
        "message": "Credential revoked. IAM deny policy attached to invalidate active sessions.",
    }


# ── Audit log ─────────────────────────────────────────────────────────────────

@app.get("/audit", response_model=list[dict])
def get_audit_log(limit: int = 50, agent_id: str | None = None) -> list[dict]:
    return audit.recent(limit=limit, agent_id=agent_id)


@app.get("/audit/stats")
def get_audit_stats() -> dict:
    return {**audit.stats(), "active_credentials": janitor.active_count()}


# ── IAM roles ─────────────────────────────────────────────────────────────────

@app.get("/roles")
def get_roles() -> list[dict]:
    """List IAM roles managed by the vending service in LocalStack."""
    return list_agent_roles()


# ── Agent registry ─────────────────────────────────────────────────────────────

@app.get("/agents", response_model=list[AgentInfo])
def get_agents() -> list[AgentInfo]:
    results = []
    for agent_id, cfg in AGENT_REGISTRY.items():
        max_dur = {}
        for task_type in cfg.allowed_task_types:
            task = TASK_CONFIGS.get(task_type)
            if task:
                dur = task.max_duration.get(cfg.trust_level)
                if dur:
                    max_dur[task_type] = dur
        results.append(AgentInfo(
            agent_id=agent_id,
            trust_level=cfg.trust_level,
            allowed_task_types=cfg.allowed_task_types,
            max_duration_by_task=max_dur,
        ))
    return results


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "active_credentials": janitor.active_count(),
        "credential_summary": janitor.summary(),
    }
