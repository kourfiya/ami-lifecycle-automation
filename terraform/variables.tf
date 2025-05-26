# -----------------------------------------------------------------------------
# Variables: Common AWS Provider 
# -----------------------------------------------------------------------------

variable "aws_region" {
  description = "(Required) - The AWS region (e.g. ap-southeast-2). Autoloaded from region.tfvars."
}

variable "aws_account_id" {
  description = "(Required) - The AWS account id of the provider being deployed to (e.g. 12345678). Autoloaded from account.tfvars"
}

variable "namespace" {
  type        = string
  default     = ""
  description = "(Optional) - Namespace, which could be your abbreviated product team, e.g. 'rci', 'mi', 'hp', or 'core'"
}

variable "name" {
  type        = string
  default     = ""
  description = "(Optional) - Solution name, e.g. 'vault', 'consul', 'keycloak', 'k8s', or 'baseline'"
}


# -----------------------------------------------------------------------------
# Variables: Cloudtrail variables
# -----------------------------------------------------------------------------

variable "ami_protection_tag_key" {
  description = "Tag key used to prevent AMI deletion"
  type        = string
  default     = "do_not_delete"
}

variable "existing_cloudtrail_bucket_name" {
  description = "Tag key used to prevent AMI deletion"
  type        = string
  default     = ""
}