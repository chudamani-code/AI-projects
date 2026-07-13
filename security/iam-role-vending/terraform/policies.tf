# policies.tf — base IAM policies attached to each role.
# These are intentionally broad at the resource level ("*").
# The session policy applied at AssumeRole time provides resource-level restriction.

resource "aws_iam_policy" "read_s3" {
  name        = "policy-agent-read-s3"
  description = "Allows S3 read operations (session policy restricts to specific buckets)"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_policy" "write_s3" {
  name        = "policy-agent-write-s3"
  description = "Allows S3 write operations (session policy restricts to specific buckets)"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:PutObject", "s3:PutObjectAcl"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_policy" "read_secrets" {
  name        = "policy-agent-secrets"
  description = "Allows Secrets Manager read (session policy restricts to specific secrets)"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_policy" "invoke_lambda" {
  name        = "policy-agent-lambda"
  description = "Allows Lambda invocation (session policy restricts to specific functions)"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["lambda:InvokeFunction", "lambda:GetFunction"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_policy" "describe_ec2" {
  name        = "policy-agent-ec2"
  description = "Read-only EC2 describe permissions"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ec2:Describe*"]
      Resource = "*"
    }]
  })
}
