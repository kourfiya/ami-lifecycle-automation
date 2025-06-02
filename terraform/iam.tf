# KMS Key Policy for CloudTrail
data "aws_iam_policy_document" "cloudtrail_kms_policy" {
  # Allow specific administrators to manage the key
  statement {
    sid    = "EnableKeyAdministration"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = var.kms_admin_arns
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }

  # Allow CloudTrail service to use the key
  statement {
    sid    = "AllowCloudTrailService"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = [
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
      "kms:Decrypt"
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values = [
        "arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/*"
      ]
    }
  }

  # Allow S3 service for CloudTrail bucket operations
  statement {
    sid    = "AllowS3Service"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey"
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${data.aws_region.current.name}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "ami_cleanup_lambda_kms_policy" {
  name = "ami_cleanup_lambda-kms-policy"
  role = aws_iam_role.ami_cleanup_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.cloudtrail.arn
        Condition = {
          StringEquals = {
            "kms:ViaService" = [
              "s3.${data.aws_region.current.name}.amazonaws.com",
              "athena.${data.aws_region.current.name}.amazonaws.com"
            ]
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "ami_cleanup_lambda_recycle_bin_policy" {
  name = "ami_cleanup_lambda-recycle-bin-policy"
  role = aws_iam_role.ami_cleanup_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "rbin:PutRetentionRule",
          "rbin:GetRetentionRule",
          "rbin:ListRetentionRules"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeImageAttribute",
          "ec2:ModifyImageAttribute"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role" "cloudtrail_role" {
  name = "${aws_s3_bucket.cloudtrail_logs.id}-logging-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_s3_bucket_policy" "cloudtrail_bucket_policy" {
  count = var.existing_cloudtrail_bucket_name == "" ? 1 : 0

  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck",
        Effect = "Allow",
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        },
        Action   = "s3:GetBucketAcl",
        Resource = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite",
        Effect = "Allow",
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        },
        Action   = "s3:PutObject",
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket.cloudtrail_logs]
}

resource "aws_iam_role_policy" "cloudtrail_s3_policy" {
  name = "${aws_s3_bucket.cloudtrail_logs.id}-s3-policy"
  role = aws_iam_role.cloudtrail_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetBucketLocation"
        ]
        Resource = [
          var.existing_cloudtrail_bucket_name == "" ? aws_s3_bucket.cloudtrail_logs.arn : "arn:aws:s3:::${var.existing_cloudtrail_bucket_name}",
          var.existing_cloudtrail_bucket_name == "" ? "${aws_s3_bucket.cloudtrail_logs.arn}/*" : "arn:aws:s3:::${var.existing_cloudtrail_bucket_name}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role" "lambda_cloudtrail_role" {
  name = "${aws_lambda_function.ami_cleanup_lambda.id}-cloudtrail-processing-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_cloudtrail_policy" {
  name = "${aws_lambda_function.ami_cleanup_lambda.id}-cloudtrail-full-access-policy"
  role = aws_iam_role.lambda_cloudtrail_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = [
          "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${aws_lambda_function.ami_cleanup_lambda.id}:*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = [
          var.existing_cloudtrail_bucket_name == "" ? aws_s3_bucket.cloudtrail_logs.arn : "arn:aws:s3:::${var.existing_cloudtrail_bucket_name}",
          aws_s3_bucket.athena_results.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = [
          var.existing_cloudtrail_bucket_name == "" ? "${aws_s3_bucket.cloudtrail_logs.arn}/*" : "arn:aws:s3:::${var.existing_cloudtrail_bucket_name}/*",
          "${aws_s3_bucket.athena_results.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetBucketLocation"
        ]
        Resource = [
          var.existing_cloudtrail_bucket_name == "" ? aws_s3_bucket.cloudtrail_logs.arn : "arn:aws:s3:::${var.existing_cloudtrail_bucket_name}",
          aws_s3_bucket.athena_results.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "athena:StartQueryExecution",
          "athena:GetQueryExecution",
          "athena:GetQueryResults",
          "athena:StopQueryExecution"
        ]
        Resource = [
          "arn:${data.aws_partition.current.partition}:athena:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:workgroup/primary"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "glue:GetTable",
          "glue:GetPartitions",
          "glue:GetDatabase",
          "glue:BatchCreatePartition"
        ]
        Resource = [
          "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:catalog",
          "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:database/*",
          "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:table/*/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "iam:PassRole"
        ]
        Resource = [
          "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/${aws_iam_role.athena_query_role.id}"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "athena_query_policy" {
  name = "athena_query-access-policy"
  role = aws_iam_role.athena_query_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetBucketLocation",
          "s3:ListBucket"
        ]
        Resource = [
          var.existing_cloudtrail_bucket_name == "" ? aws_s3_bucket.cloudtrail_logs.arn : "arn:aws:s3:::${var.existing_cloudtrail_bucket_name}",
          aws_s3_bucket.athena_results.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListMultipartUploadParts",
          "s3:AbortMultipartUpload",
          "s3:PutObject"
        ]
        Resource = [
          var.existing_cloudtrail_bucket_name == "" ? "${aws_s3_bucket.cloudtrail_logs.arn}/*" : "arn:aws:s3:::${var.existing_cloudtrail_bucket_name}/*",
          "${aws_s3_bucket.athena_results.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "athena:StartQueryExecution",
          "athena:GetQueryExecution",
          "athena:GetQueryResults",
          "athena:StopQueryExecution"
        ]
        Resource = [
          "arn:${data.aws_partition.current.partition}:athena:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:workgroup/primary"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "glue:GetTable",
          "glue:GetPartitions",
          "glue:GetDatabase"
        ]
        Resource = [
          "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:catalog",
          "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:database/*",
          "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:table/*/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role" "athena_query_role" {
  name = "athena_query-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "athena.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role" "ami_cleanup_lambda_role" {
  name = "ami-cleanup-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "ami_cleanup_lambda_policy" {
  name = "ami_cleanup_lambda-policy"
  role = aws_iam_role.ami_cleanup_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = [
          "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${aws_lambda_function.ami_cleanup_lambda.id}:*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeImages",
          "ec2:DescribeInstances"
        ]
        Resource = "*" 
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateTags"
        ]
        Resource = [
          "arn:${data.aws_partition.current.partition}:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:image/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "athena:StartQueryExecution",
          "athena:GetQueryExecution",
          "athena:GetQueryResults",
          "athena:StopQueryExecution"
        ]
        Resource = [
          "arn:${data.aws_partition.current.partition}:athena:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:workgroup/primary"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetBucketLocation",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:${data.aws_partition.current.partition}:s3:::${aws_s3_bucket.athena_results.id}"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListMultipartUploadParts",
          "s3:AbortMultipartUpload",
          "s3:PutObject"
        ]
        Resource = [
          "arn:${data.aws_partition.current.partition}:s3:::${aws_s3_bucket.athena_results.id}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "glue:GetTable",
          "glue:GetPartitions",
          "glue:GetDatabase",
          "glue:BatchCreatePartition"
        ]
        Resource = [
          "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:catalog",
          "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:database/*",
          "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:table/*/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.ami_cleanup_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_policy" "recycle_bin_policy" {
  name        = "${aws_rbin_rule.snapshot_retention_rule.id}-Policy"
  path        = "/"
  description = "IAM policy for managing Recycle Bin rules"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "rbin:CreateRule",
          "rbin:UpdateRule",
          "rbin:GetRule",
          "rbin:ListRules",
          "rbin:DeleteRule",
          "rbin:TagResource",
          "rbin:UntagResource",
        ]
        Effect = "Allow"
        Resource = [
          "arn:aws:rbin:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:rule/${aws_rbin_rule.ami_retention_rule.id}",
          "arn:aws:rbin:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:rule/${aws_rbin_rule.snapshot_retention_rule.id}"
        ]
      },
    ]
  })
}

resource "aws_iam_role" "recycle_bin_role" {
  name = "${aws_rbin_rule.ami_retention_rule.id}-Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}