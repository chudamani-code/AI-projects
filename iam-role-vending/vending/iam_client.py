"""
iam_client.py — boto3 wrapper for LocalStack IAM and STS.

All AWS calls go to http://localstack:4566 (or LOCALSTACK_ENDPOINT env var).
The external ID is required on every AssumeRole call — prevents confused-deputy attacks.
"""
import json
import logging
import os
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger("iam_client")

LOCALSTACK_ENDPOINT = os.getenv("LOCALSTACK_ENDPOINT", "http://localstack:4566")
AWS_REGION          = os.getenv("AWS_DEFAULT_REGION",  "us-east-1")
AWS_ACCOUNT_ID      = os.getenv("AWS_ACCOUNT_ID",      "000000000000")
EXTERNAL_ID         = os.getenv("VENDING_EXTERNAL_ID", "vending-svc-ext-id-2026")

_boto_kwargs = dict(
    region_name          = AWS_REGION,
    endpoint_url         = LOCALSTACK_ENDPOINT,
    aws_access_key_id    = "test",
    aws_secret_access_key= "test",
)


def _sts():
    return boto3.client("sts", **_boto_kwargs)


def _iam():
    return boto3.client("iam", **_boto_kwargs)


def assume_role(
    role_name: str,
    session_name: str,
    session_policy: dict,
    duration_seconds: int,
) -> dict:
    """
    Call STS AssumeRole with a narrowing session policy.

    Returns the raw STS Credentials dict:
      { AccessKeyId, SecretAccessKey, SessionToken, Expiration }

    The session_policy further restricts what the assumed role can do —
    even if the base role has broader permissions.
    """
    role_arn = f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/{role_name}"
    session_policy_str = json.dumps(session_policy)

    logger.info(
        f"AssumeRole: role={role_name} session={session_name} "
        f"duration={duration_seconds}s external_id=***"
    )

    try:
        response = _sts().assume_role(
            RoleArn         = role_arn,
            RoleSessionName = session_name,   # logged in CloudTrail
            ExternalId      = EXTERNAL_ID,    # confused-deputy protection
            Policy          = session_policy_str,
            DurationSeconds = duration_seconds,
        )
        creds = response["Credentials"]
        logger.info(f"AssumeRole succeeded: key={creds['AccessKeyId'][:8]}…")
        return creds

    except ClientError as e:
        code = e.response["Error"]["Code"]
        logger.error(f"AssumeRole failed: {code} — {e.response['Error']['Message']}")
        raise


def role_exists(role_name: str) -> bool:
    """Check whether a role exists in LocalStack IAM."""
    try:
        _iam().get_role(RoleName=role_name)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return False
        raise


def list_agent_roles() -> list[dict]:
    """List all IAM roles managed by the vending service."""
    try:
        paginator = _iam().get_paginator("list_roles")
        roles = []
        for page in paginator.paginate():
            for role in page["Roles"]:
                tags = {t["Key"]: t["Value"] for t in role.get("Tags", [])}
                if tags.get("ManagedBy") == "iam-role-vending":
                    roles.append({
                        "role_name": role["RoleName"],
                        "role_arn": role["Arn"],
                        "task_type": tags.get("TaskType", "unknown"),
                        "max_session_duration": role.get("MaxSessionDuration", 3600),
                        "created": str(role["CreateDate"]),
                    })
        return roles
    except ClientError as e:
        logger.warning(f"Could not list roles: {e}")
        return []


def attach_revocation_deny_policy(role_name: str, credential_id: str) -> None:
    """
    Attach an inline deny policy to a role to revoke a specific session.

    Note: STS credentials cannot be truly revoked — they remain valid until expiry.
    The AWS-recommended approach is to attach a deny-all policy with a condition
    on the issue time, invalidating sessions issued before a certain timestamp.
    In production, use: AWSRevokeOlderSessions managed policy.
    """
    policy_name = f"revoke-{credential_id[:12]}"
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": f"DenyRevoked{credential_id[:8]}",
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:PrincipalTag/CredentialId": credential_id
                }
            }
        }]
    }
    try:
        _iam().put_role_policy(
            RoleName       = role_name,
            PolicyName     = policy_name,
            PolicyDocument = json.dumps(deny_policy),
        )
        logger.info(f"Attached deny policy {policy_name} to role {role_name}")
    except ClientError as e:
        logger.warning(f"Could not attach deny policy: {e}")
