data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

data "aws_partition" "current" {}

data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/assets/ami_lifecycle.zip"
  source_file = "${path.module}/assets/ami_lifecycle.py"
}

data "aws_s3_bucket" "existing_cloudtrail_bucket" {
  count  = var.existing_cloudtrail_bucket_name != "" ? 1 : 0
  bucket = var.existing_cloudtrail_bucket_name
}

