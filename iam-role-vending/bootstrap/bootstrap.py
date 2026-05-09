#!/usr/bin/env python3
"""
bootstrap.py — Creates IAM roles and policies in LocalStack.
Run inside Docker: handled automatically by docker-compose.
Run from host:     LOCALSTACK_ENDPOINT=http://localhost:4566 python bootstrap.py
"""
import json, logging, os, sys, time
import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("bootstrap")

ENDPOINT    = os.getenv("LOCALSTACK_ENDPOINT", "http://localstack:4566")
REGION      = "us-east-1"
ACCOUNT_ID  = "000000000000"
EXTERNAL_ID = os.getenv("VENDING_EXTERNAL_ID", "vending-svc-ext-id-2026")

_kw  = dict(region_name=REGION, endpoint_url=ENDPOINT,
            aws_access_key_id="test", aws_secret_access_key="test")
iam  = boto3.client("iam", **_kw)

TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Sid": "AllowVendingServiceToAssume",
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"},
        "Action": "sts:AssumeRole",
        "Condition": {"StringEquals": {"sts:ExternalId": EXTERNAL_ID}},
    }]
})

ROLES = [
    ("role-agent-read-s3",  "read_s3",      3600, "policy-agent-read-s3",
     ["s3:GetObject","s3:ListBucket","s3:GetBucketLocation"]),
    ("role-agent-write-s3", "write_s3",     3600, "policy-agent-write-s3",
     ["s3:PutObject","s3:PutObjectAcl"]),
    ("role-agent-secrets",  "read_secrets", 3600, "policy-agent-secrets",
     ["secretsmanager:GetSecretValue","secretsmanager:DescribeSecret"]),
    ("role-agent-lambda",   "invoke_lambda", 3600, "policy-agent-lambda",
     ["lambda:InvokeFunction","lambda:GetFunction"]),
    ("role-agent-ec2",      "describe_ec2",  3600, "policy-agent-ec2",
     ["ec2:Describe*"]),
]

def wait_for_localstack(retries=30):
    import urllib.request
    for i in range(retries):
        try:
            urllib.request.urlopen(f"{ENDPOINT}/_localstack/health", timeout=2)
            log.info("LocalStack is ready")
            return
        except Exception:
            log.info(f"Waiting for LocalStack ({i+1}/{retries})...")
            time.sleep(2)
    sys.exit("LocalStack did not become ready in time")

def create_policy(name, actions):
    doc = json.dumps({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":actions,"Resource":"*"}]})
    try:
        r   = iam.create_policy(PolicyName=name, PolicyDocument=doc)
        arn = r["Policy"]["Arn"]
        log.info(f"  Created policy: {name}")
        return arn
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            arn = f"arn:aws:iam::{ACCOUNT_ID}:policy/{name}"
            log.info(f"  Policy exists: {name}")
            return arn
        raise

def create_role(name, task_type, max_session, policy_arn):
    try:
        iam.create_role(RoleName=name, AssumeRolePolicyDocument=TRUST,
                        MaxSessionDuration=max_session,
                        Tags=[{"Key":"ManagedBy","Value":"iam-role-vending"},
                              {"Key":"TaskType","Value":task_type}])
        log.info(f"  Created role: {name}")
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityAlreadyExists": raise
        log.info(f"  Role exists: {name}")
    try:
        iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    except ClientError: pass

def main():
    wait_for_localstack()
    log.info("Bootstrapping IAM roles in LocalStack...")
    for role_name, task_type, max_sess, pol_name, actions in ROLES:
        log.info(f"Role: {role_name}")
        create_role(role_name, task_type, max_sess, create_policy(pol_name, actions))
    log.info("Bootstrap complete — 5 roles ready.")

if __name__ == "__main__":
    main()
