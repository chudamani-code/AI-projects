output "role_arns" {
  description = "ARNs of all vended agent roles"
  value = {
    read_s3    = aws_iam_role.agent_read_s3.arn
    write_s3   = aws_iam_role.agent_write_s3.arn
    secrets    = aws_iam_role.agent_secrets.arn
    lambda     = aws_iam_role.agent_lambda.arn
    ec2        = aws_iam_role.agent_ec2.arn
  }
}

output "external_id" {
  description = "ExternalId required in every AssumeRole call"
  value       = var.vending_external_id
  sensitive   = true
}
