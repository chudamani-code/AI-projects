variable "account_id" {
  description = "AWS account ID (000000000000 for LocalStack)"
  default     = "000000000000"
}

variable "region" {
  description = "AWS region"
  default     = "us-east-1"
}

# External ID prevents the confused-deputy attack:
# Only the vending service (which knows this value) can assume these roles.
variable "vending_external_id" {
  description = "Secret value the vending service must supply when assuming roles"
  default     = "vending-svc-ext-id-2026"
}
