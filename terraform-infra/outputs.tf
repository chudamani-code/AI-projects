output "secure_bucket_arn" {
  description = "ARN of the encrypted, access-blocked S3 bucket"
  value       = aws_s3_bucket.secure_data.arn
}

output "cloudtrail_arn" {
  description = "ARN of the organization CloudTrail trail"
  value       = aws_cloudtrail.org_trail.arn
}
