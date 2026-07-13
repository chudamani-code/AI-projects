package terraform.security.s3_encryption

# Deny any aws_s3_bucket resource that does not enforce
# server-side encryption (AES256 or aws:kms).

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    rule := resource.change.after.rule[_]
    sse := rule.apply_server_side_encryption_by_default[_]
    not sse.sse_algorithm == "AES256"
    not sse.sse_algorithm == "aws:kms"
    msg := sprintf("S3 bucket %v does not enforce AES256/KMS encryption", [resource.address])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    resource.change.after.acl == "public-read"
    msg := sprintf("S3 bucket %v is publicly readable", [resource.address])
}
