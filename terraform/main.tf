
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = "cloudtrail-logs-${var.aws_account_id}-${var.aws_region}"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    id     = "expire-cloudtrail-logs"
    status = "Enabled"

    filter {
      prefix = ""
    }

    expiration {
      days                         = 60
    }

    noncurrent_version_expiration {
      noncurrent_days = 1
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}


resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "athena_results" {
  bucket        = "athena-results-${var.aws_account_id}-${var.aws_region}"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  rule {
    id     = "collect"
    status = "Enabled"

    filter {
      prefix = "collect"
    }

    expiration {
      days                         = 60
    }

    noncurrent_version_expiration {
      noncurrent_days = 1
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

resource "aws_s3_bucket_public_access_block" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "query_results_prefix" {
  bucket       = aws_s3_bucket.athena_results.id
  key          = "query-results/"
  content_type = "application/x-directory"
}

resource "aws_lambda_function" "ami_cleanup_lambda" {
  function_name = "ami_cleanup_lambda"
  role          = aws_iam_role.ami_cleanup_lambda_role.arn
  handler       = "ami_lifecycle.lambda_handler"
  runtime       = "python3.12"
  timeout       = 300
  memory_size   = 1064

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

tags = {
  Name        = "ami-cleanup-lambda"
  Purpose     = "ami-cleanup"
}

  environment {
    variables = {
      LOG_LEVEL             = "INFO"
      ATHENA_DATABASE       = aws_cloudtrail.management_trail.id
      ATHENA_TABLE          = "${aws_cloudtrail.management_trail.id}_logs"
      ATHENA_RESULTS_BUCKET = aws_s3_bucket.athena_results.id
      AMI_PROTECTION_TAG    = var.ami_protection_tag_key
    }
  }
}

resource "aws_cloudwatch_event_rule" "ami_cleanup_schedule" {
  name                = "ami_cleanup_schedule"
  description         = "Trigger AMI cleanup Lambda on schedule"
  schedule_expression = "cron(0 0 1 * ? *)"
}

resource "aws_cloudwatch_event_target" "ami_cleanup_target" {
  rule      = aws_cloudwatch_event_rule.ami_cleanup_schedule.name
  target_id = "ami-cleanup-lambda"
  arn       = aws_lambda_function.ami_cleanup_lambda.arn
}

resource "aws_lambda_permission" "allow_cloudwatch" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ami_cleanup_lambda.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ami_cleanup_schedule.arn
}


resource "aws_cloudtrail" "management_trail" {
  name                          = "cloudtrail-management-events-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.cloudtrail.arn


  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail_bucket_policy]
}

resource "aws_glue_catalog_database" "cloudtrail_db" {
  name = aws_cloudtrail.management_trail.id
}

resource "aws_glue_catalog_table" "cloudtrail_table" {
  name          = "${aws_cloudtrail.management_trail.id}_logs}"
  database_name = aws_glue_catalog_database.cloudtrail_db.name

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification"  = "json"
    "compressionType" = "none"
    "typeOfData"      = "file"
    "EXTERNAL"        = "TRUE"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.cloudtrail_logs.id}/AWSLogs/${data.aws_caller_identity.current.account_id}/CloudTrail/${var.aws_region}/"
    input_format  = "com.amazon.emr.cloudtrail.CloudTrailInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      name                  = "${aws_cloudtrail.management_trail.id}-serde"
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"

      parameters = {
        "serialization.format" = "1"
      }
    }

    columns {
      name = "eventversion"
      type = "string"
    }
    columns {
      name = "useridentity"
      type = "struct<type:string,principalId:string,arn:string,accountId:string,invokedBy:string,accessKeyId:string,userName:string,sessionContext:struct<attributes:struct<mfaAuthenticated:string,creationDate:string>,sessionIssuer:struct<type:string,principalId:string,arn:string,accountId:string,username:string>,ec2RoleDelivery:string,webIdFederationData:struct<federatedProvider:string,attributes:map<string,string>>>>"
    }
    columns {
      name = "eventtime"
      type = "string"
    }
    columns {
      name = "eventsource"
      type = "string"
    }
    columns {
      name = "eventname"
      type = "string"
    }
    columns {
      name = "awsregion"
      type = "string"
    }
    columns {
      name = "sourceipaddress"
      type = "string"
    }
    columns {
      name = "useragent"
      type = "string"
    }
    columns {
      name = "errorcode"
      type = "string"
    }
    columns {
      name = "errormessage"
      type = "string"
    }
    columns {
      name = "requestparameters"
      type = "string"
    }
    columns {
      name = "responseelements"
      type = "string"
    }
    columns {
      name = "additionaleventdata"
      type = "string"
    }
    columns {
      name = "requestid"
      type = "string"
    }
    columns {
      name = "eventid"
      type = "string"
    }
    columns {
      name = "resources"
      type = "array<struct<arn:string,accountId:string,type:string>>"
    }
    columns {
      name = "eventtype"
      type = "string"
    }
    columns {
      name = "apiversion"
      type = "string"
    }
    columns {
      name = "readonly"
      type = "string"
    }
    columns {
      name = "recipientaccountid"
      type = "string"
    }
    columns {
      name = "serviceeventdetails"
      type = "string"
    }
    columns {
      name = "sharedeventid"
      type = "string"
    }
    columns {
      name = "vpcendpointid"
      type = "string"
    }
    columns {
      name = "tlsdetails"
      type = "struct<tlsVersion:string,cipherSuite:string,clientProvidedHostHeader:string>"
    }
  }

  partition_keys {
    name = "year"
    type = "string"
  }
  partition_keys {
    name = "month"
    type = "string"
  }
  partition_keys {
    name = "day"
    type = "string"
  }
}

resource "aws_rbin_rule" "ami_retention_rule" {
  description   = "Retention rule for AMIs"
  resource_type = "EC2_IMAGE"

  retention_period {
    retention_period_value = 90
    retention_period_unit  = "DAYS"
  }

  tags = {
    Name    = "AMI Recycle Bin Rule"
    Purpose = "Temporary storage for deregistered AMIs"
  }
}

resource "aws_rbin_rule" "snapshot_retention_rule" {
  description   = "Retention rule for EBS Snapshots"
  resource_type = "EBS_SNAPSHOT"

  retention_period {
    retention_period_value = 90
    retention_period_unit  = "DAYS"
  }

  tags = {
    Name    = "Snapshot Recycle Bin Rule"
    Purpose = "Temporary storage for deleted snapshots"
  }
}

resource "aws_iam_role_policy_attachment" "recycle_bin_role_policy_attachment" {
  policy_arn = aws_iam_policy.recycle_bin_policy.arn
  role       = aws_iam_role.recycle_bin_role.name
}