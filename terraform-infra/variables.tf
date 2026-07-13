variable "project_name" {
  description = "Name of the project, used as a prefix for resource naming"
  type        = string
  default     = "ai-projects"
}

variable "environment" {
  description = "Deployment environment (e.g. dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "aws_region" {
  description = "AWS region to deploy resources into"
  type        = string
  default     = "us-east-1"
}
