"""
test_vending.py — unit tests for the vending engine and audit logger.
No LocalStack or network required — all tests run locally.

Run: python tests/test_vending.py
"""
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "vending"))

from engine import (
    AGENT_REGISTRY, TASK_CONFIGS, VendingError,
    build_session_policy, describe_effective_permissions, validate_request,
)
from audit import AuditLogger
from janitor import CredentialJanitor


# ── Helpers ───────────────────────────────────────────────────────────────────

class MockConstraints:
    def __init__(self, **kwargs):
        self.s3_buckets    = kwargs.get("s3_buckets", [])
        self.s3_prefix     = kwargs.get("s3_prefix", "")
        self.secret_names  = kwargs.get("secret_names", [])
        self.function_names= kwargs.get("function_names", [])
        self.regions       = kwargs.get("regions", [])

    def model_dump(self):
        return {k: v for k, v in self.__dict__.items()}


def assert_raises(exc_type, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
        assert False, f"Expected {exc_type.__name__} but no exception was raised"
    except exc_type as e:
        return str(e)
    except Exception as e:
        assert False, f"Expected {exc_type.__name__}, got {type(e).__name__}: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# Validation tests
# ─────────────────────────────────────────────────────────────────────────────

def test_valid_request_reader_read_s3():
    c = MockConstraints(s3_buckets=["logs-archive"])
    agent, task = validate_request("agent-reader", "read_s3", c, 900)
    assert agent.trust_level == "LOW"
    assert task.base_role_name == "role-agent-read-s3"
    print("PASS: valid request — agent-reader + read_s3")


def test_unknown_agent_raises():
    c = MockConstraints(s3_buckets=["logs"])
    msg = assert_raises(VendingError, validate_request, "agent-unknown", "read_s3", c, 900)
    assert "Unknown agent" in msg
    print("PASS: unknown agent raises VendingError")


def test_unauthorised_task_raises():
    # agent-reader is not allowed to write S3
    c = MockConstraints(s3_buckets=["output"])
    msg = assert_raises(VendingError, validate_request, "agent-reader", "write_s3", c, 900)
    assert "not authorised" in msg
    print("PASS: unauthorised task raises VendingError")


def test_duration_exceeds_cap_raises():
    c = MockConstraints(s3_buckets=["logs"])
    # LOW trust agent, read_s3 max = 3600s
    msg = assert_raises(VendingError, validate_request, "agent-reader", "read_s3", c, 7200)
    assert "exceeds maximum" in msg
    print("PASS: duration over cap raises VendingError")


def test_missing_required_constraint_raises():
    # read_s3 requires s3_buckets to be non-empty
    c = MockConstraints()   # empty s3_buckets
    msg = assert_raises(VendingError, validate_request, "agent-reader", "read_s3", c, 900)
    assert "s3_buckets" in msg
    print("PASS: missing required constraint raises VendingError")


def test_low_trust_cannot_read_secrets():
    # agent-reader (LOW) is not allowed to read secrets (requires MEDIUM)
    c = MockConstraints(secret_names=["db-password"])
    msg = assert_raises(VendingError, validate_request, "agent-reader", "read_secrets", c, 900)
    assert "not authorised" in msg or "minimum trust" in msg
    print("PASS: LOW trust agent blocked from read_secrets")


def test_medium_trust_can_write_s3():
    c = MockConstraints(s3_buckets=["output-bucket"])
    agent, task = validate_request("agent-processor", "write_s3", c, 900)
    assert task.base_role_name == "role-agent-write-s3"
    print("PASS: MEDIUM trust agent can write_s3")


def test_high_trust_gets_longer_duration():
    c = MockConstraints(secret_names=["api-key"])
    # HIGH trust agent can get 1800s on read_secrets; LOW would be blocked
    agent, task = validate_request("agent-admin", "read_secrets", c, 1800)
    assert agent.trust_level == "HIGH"
    print("PASS: HIGH trust agent gets longer duration on read_secrets")


# ─────────────────────────────────────────────────────────────────────────────
# Session policy tests
# ─────────────────────────────────────────────────────────────────────────────

def test_read_s3_session_policy_scope():
    c = MockConstraints(s3_buckets=["logs-archive"], s3_prefix="2026/05/")
    policy = build_session_policy("read_s3", c)
    assert policy["Version"] == "2012-10-17"
    # Should contain GetObject restricted to the specific prefix
    resources = [r for s in policy["Statement"] for r in s.get("Resource", [])]
    assert any("logs-archive/2026/05/" in r for r in resources), f"Expected prefix in resources: {resources}"
    # Should NOT allow access to other buckets
    assert not any("other-bucket" in r for r in resources)
    print("PASS: read_s3 session policy scoped to bucket + prefix")


def test_write_s3_policy_only_allows_put():
    c = MockConstraints(s3_buckets=["output"], s3_prefix="results/")
    policy = build_session_policy("write_s3", c)
    actions = [a for s in policy["Statement"] for a in s.get("Action", [])]
    assert "s3:PutObject" in actions
    assert "s3:GetObject" not in actions, "Write policy should not allow GetObject"
    print("PASS: write_s3 session policy contains only PutObject")


def test_read_secrets_policy_resource_scoped():
    c = MockConstraints(secret_names=["db-password", "api-key"])
    policy = build_session_policy("read_secrets", c)
    resources = [r for s in policy["Statement"] for r in s.get("Resource", [])]
    assert any("db-password" in r for r in resources)
    assert any("api-key" in r for r in resources)
    # Should not allow * resource
    assert "*" not in resources
    print("PASS: read_secrets session policy scoped to named secrets")


def test_invoke_lambda_policy_resource_scoped():
    c = MockConstraints(function_names=["data-processor", "report-generator"])
    policy = build_session_policy("invoke_lambda", c)
    resources = [r for s in policy["Statement"] for r in s.get("Resource", [])]
    assert any("data-processor" in r for r in resources)
    assert "*" not in resources
    print("PASS: invoke_lambda session policy scoped to function names")


def test_session_policy_is_valid_json():
    c = MockConstraints(s3_buckets=["test-bucket"])
    policy = build_session_policy("read_s3", c)
    # Must be serialisable (boto3 will pass it as a string)
    s = json.dumps(policy)
    parsed = json.loads(s)
    assert parsed["Version"] == "2012-10-17"
    print("PASS: session policy is valid JSON")


# ─────────────────────────────────────────────────────────────────────────────
# Effective permissions description tests
# ─────────────────────────────────────────────────────────────────────────────

def test_effective_permissions_read_s3():
    c = MockConstraints(s3_buckets=["logs-archive"], s3_prefix="2026/")
    perms = describe_effective_permissions("read_s3", c)
    assert len(perms) >= 1
    assert any("logs-archive" in p for p in perms)
    print("PASS: effective permissions description — read_s3")


def test_effective_permissions_secrets():
    c = MockConstraints(secret_names=["db-credentials"])
    perms = describe_effective_permissions("read_secrets", c)
    assert any("db-credentials" in p for p in perms)
    print("PASS: effective permissions description — read_secrets")


# ─────────────────────────────────────────────────────────────────────────────
# Audit logger tests
# ─────────────────────────────────────────────────────────────────────────────

def test_audit_logger_records_issuance():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db = f.name
    a = AuditLogger(db_path=db)
    now = time.time()
    a.log_issued("cred-abc", "agent-reader", "read_s3", "arn:...", 900,
                 now, now + 900, {"s3_buckets": ["logs"]}, {"job_id": "123"})
    rows = a.recent(limit=10)
    assert len(rows) == 1
    assert rows[0]["event"] == "credential_issued"
    assert rows[0]["credential_id"] == "cred-abc"
    print("PASS: audit logger records credential issuance")


def test_audit_logger_records_denial():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db = f.name
    a = AuditLogger(db_path=db)
    a.log_denied("agent-reader", "write_s3", "not authorised for task")
    rows = a.recent()
    assert rows[0]["event"] == "vending_denied"
    print("PASS: audit logger records denial")


def test_audit_logger_stats():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db = f.name
    a = AuditLogger(db_path=db)
    now = time.time()
    a.log_issued("c1","agent-reader","read_s3","arn:...",900,now,now+900,{},{})
    a.log_issued("c2","agent-processor","write_s3","arn:...",900,now,now+900,{},{})
    a.log_denied("agent-reader","write_s3","blocked")
    a.log_revoked("c1","agent-reader","read_s3","manual")
    stats = a.stats()
    assert stats["credentials_issued"] == 2
    assert stats["requests_denied"]    == 1
    assert stats["credentials_revoked"]== 1
    print("PASS: audit logger stats are accurate")


# ─────────────────────────────────────────────────────────────────────────────
# Janitor tests
# ─────────────────────────────────────────────────────────────────────────────

def test_janitor_marks_expired_credentials():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db = f.name
    a = AuditLogger(db_path=db)
    store = {
        "cred-1": {"agent_id": "agent-reader", "task_type": "read_s3",
                   "expires_at": time.time() - 10,  # already expired
                   "status": "active"},
        "cred-2": {"agent_id": "agent-processor", "task_type": "write_s3",
                   "expires_at": time.time() + 900,  # still valid
                   "status": "active"},
    }
    j = CredentialJanitor(store, a, check_interval=999)
    j._sweep()
    assert store["cred-1"]["status"] == "expired"
    assert store["cred-2"]["status"] == "active"
    rows = a.recent()
    assert any(r["event"] == "credential_expired" and r["credential_id"] == "cred-1" for r in rows)
    print("PASS: janitor marks expired credentials and logs them")


def test_janitor_does_not_expire_active_credentials():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db = f.name
    a = AuditLogger(db_path=db)
    store = {"cred-1": {"agent_id": "x", "task_type": "read_s3",
                        "expires_at": time.time() + 3600, "status": "active"}}
    j = CredentialJanitor(store, a)
    j._sweep()
    assert store["cred-1"]["status"] == "active"
    assert a.stats()["credentials_expired"] == 0
    print("PASS: janitor does not touch active credentials")


def test_janitor_active_count():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db = f.name
    a  = AuditLogger(db_path=db)
    store = {
        "c1": {"agent_id":"x","task_type":"read_s3","expires_at":time.time()+900,"status":"active"},
        "c2": {"agent_id":"y","task_type":"write_s3","expires_at":time.time()+900,"status":"active"},
        "c3": {"agent_id":"z","task_type":"read_s3","expires_at":time.time()-1,"status":"expired"},
    }
    j = CredentialJanitor(store, a)
    assert j.active_count() == 2
    print("PASS: janitor active_count excludes expired/revoked")


# ─────────────────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────────────────

ALL_TESTS = [
    test_valid_request_reader_read_s3,
    test_unknown_agent_raises,
    test_unauthorised_task_raises,
    test_duration_exceeds_cap_raises,
    test_missing_required_constraint_raises,
    test_low_trust_cannot_read_secrets,
    test_medium_trust_can_write_s3,
    test_high_trust_gets_longer_duration,
    test_read_s3_session_policy_scope,
    test_write_s3_policy_only_allows_put,
    test_read_secrets_policy_resource_scoped,
    test_invoke_lambda_policy_resource_scoped,
    test_session_policy_is_valid_json,
    test_effective_permissions_read_s3,
    test_effective_permissions_secrets,
    test_audit_logger_records_issuance,
    test_audit_logger_records_denial,
    test_audit_logger_stats,
    test_janitor_marks_expired_credentials,
    test_janitor_does_not_expire_active_credentials,
    test_janitor_active_count,
]

GROUPS = {
    "Validation — agent + task authorisation":  ALL_TESTS[:8],
    "Session policy — least-privilege scoping":  ALL_TESTS[8:13],
    "Effective permissions — human-readable":    ALL_TESTS[13:15],
    "Audit logger — tamper-evident logging":     ALL_TESTS[15:18],
    "Janitor — automatic credential expiry":     ALL_TESTS[18:],
}

if __name__ == "__main__":
    passed = failed = 0
    for group, tests in GROUPS.items():
        print(f"\n{'─'*60}")
        print(f"  {group}")
        print(f"{'─'*60}")
        for fn in tests:
            try:
                fn()
                passed += 1
            except Exception as e:
                print(f"  FAIL [{fn.__name__}]: {e}")
                failed += 1

    print(f"\n{'═'*60}")
    print(f"  Results: {passed} passed, {failed} failed / {len(ALL_TESTS)} total")
    print(f"{'═'*60}")
    sys.exit(0 if failed == 0 else 1)
