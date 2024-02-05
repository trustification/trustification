terraform {
  required_version = ">= 1.5.0"
}

locals {
  document_types = toset(["bombastic", "vexination", "v11y"])
}

variable "availability-zone" {
  type        = string
  default     = "eu-west-1a"
  description = "The AWS availability zone to create RDS resources in. Must be part of the 'region'."
}

variable "environment" {
  type        = string
  default     = "default"
  description = "An environment, using for tagging and creating a suffix for AWS resources"
}

variable "namespace" {
  type        = string
  default     = "trustification"
  description = "The Kubernetes namespaces the resources will be created in"
}
