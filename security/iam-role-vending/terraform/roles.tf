# roles.tf
#
# One base IAM role per task type.
#
# DESIGN PRINCIPLE — double-lock permission model:
#   Base role  = maximum possible permissions for this task class
#   Session policy (set at AssumeRole time) = actual minimum for THIS task
#
# The base role is what Terraform manages.
# The session policy is generated dynamically by the vending engine.
#
# External ID on the trust policy prevents the "confused deputy" attack:
# only the vending service, which holds the ExternalId secret, can
# call AssumeRole on these roles.

# ── Trust policy (shared by all agent roles) ──────────────────────────────────
data "aws_iam_policy_document" "agent_trust" {
  statement {
    sid     = "AllowVendingServiceToAssume"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }

    # Confused-deputy protection: caller must supply the ExternalId
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.vending_external_id]
    }
  }
}

# ── Role: read S3 ─────────────────────────────────────────────────────────────
resource "aws_iam_role" "agent_read_s3" {
  name                 = "role-agent-read-s3"
  description          = "Base role for agents that need to read from S3"
  assume_role_policy   = data.aws_iam_policy_document.agent_trust.json
  max_session_duration = 3600   # hard cap: 1 hour

  tags = {
    ManagedBy = "iam-role-vending"
    TaskType  = "read_s3"
  }
}

resource "aws_iam_role_policy_attachment" "agent_read_s3" {
  role       = aws_iam_role.agent_read_s3.name
  policy_arn = aws_iam_policy.read_s3.arn
}

# ── Role: write S3 ────────────────────────────────────────────────────────────
resource "aws_iam_role" "agent_write_s3" {
  name                 = "role-agent-write-s3"
  description          = "Base role for agents that need to write to S3"
  assume_role_policy   = data.aws_iam_policy_document.agent_trust.json
  max_session_duration = 1800   # 30 minutes max for write operations

  tags = {
    ManagedBy = "iam-role-vending"
    TaskType  = "write_s3"
  }
}

resource "aws_iam_role_policy_attachment" "agent_write_s3" {
  role       = aws_iam_role.agent_write_s3.name
  policy_arn = aws_iam_policy.write_s3.arn
}

# ── Role: read secrets ────────────────────────────────────────────────────────
resource "aws_iam_role" "agent_secrets" {
  name                 = "role-agent-secrets"
  description          = "Base role for agents that need secret retrieval"
  assume_role_policy   = data.aws_iam_policy_document.agent_trust.json
  max_session_duration = 900    # 15 minutes max — secrets are high-value

  tags = {
    ManagedBy = "iam-role-vending"
    TaskType  = "read_secrets"
  }
}

resource "aws_iam_role_policy_attachment" "agent_secrets" {
  role       = aws_iam_role.agent_secrets.name
  policy_arn = aws_iam_policy.read_secrets.arn
}

# ── Role: invoke Lambda ───────────────────────────────────────────────────────
resource "aws_iam_role" "agent_lambda" {
  name                 = "role-agent-lambda"
  description          = "Base role for agents that need to invoke Lambda functions"
  assume_role_policy   = data.aws_iam_policy_document.agent_trust.json
  max_session_duration = 3600

  tags = {
    ManagedBy = "iam-role-vending"
    TaskType  = "invoke_lambda"
  }
}

resource "aws_iam_role_policy_attachment" "agent_lambda" {
  role       = aws_iam_role.agent_lambda.name
  policy_arn = aws_iam_policy.invoke_lambda.arn
}

# ── Role: describe EC2 ────────────────────────────────────────────────────────
resource "aws_iam_role" "agent_ec2" {
  name                 = "role-agent-ec2"
  description          = "Base role for agents that need EC2 read access"
  assume_role_policy   = data.aws_iam_policy_document.agent_trust.json
  max_session_duration = 3600

  tags = {
    ManagedBy = "iam-role-vending"
    TaskType  = "describe_ec2"
  }
}

resource "aws_iam_role_policy_attachment" "agent_ec2" {
  role       = aws_iam_role.agent_ec2.name
  policy_arn = aws_iam_policy.describe_ec2.arn
}
