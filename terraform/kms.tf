resource "aws_kms_key" "cloudtrail" {
  description             = "KMS Key for CloudTrail logs encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.cloudtrail_kms_policy.json

  tags = {
    Name = "CloudTrail-KMS-Key"
  }
}

resource "aws_kms_alias" "cloudtrail" {
  name          = "alias/cloudtrail-key"
  target_key_id = aws_kms_key.cloudtrail.key_id
}