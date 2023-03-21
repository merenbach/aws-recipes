terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.59.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.4.3"
    }
  }

  required_version = "~> 1.4.2"
}

provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {
      Environment = "Generator"
      Name        = "Example"
    }
  }
}

resource "random_pet" "this" {
  prefix = var.resource_naming_prefix
  length = 2
}

data "aws_iam_policy_document" "a" {
  statement {
    sid    = "Enable IAM User Permissions"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.id}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }

  # statement {
  #   sid    = "Allow CloudFront to use the key to deliver logs"
  #   effect = "Allow"

  #   principals {
  #     type        = "Service"
  #     identifiers = ["delivery.logs.amazonaws.com"]
  #   }

  #   actions = [
  #     "kms:GenerateDataKey*",
  #     "kms:Decrypt",
  #   ]
  #   resources = ["*"]
  # }
}

resource "aws_kms_key" "a" {
  deletion_window_in_days = 10
  description             = "${random_pet.this.id} key"
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.a.json
}

resource "aws_kms_alias" "a" {
  name          = "alias/${random_pet.this.id}-key-alias"
  target_key_id = aws_kms_key.a.key_id
}

resource "aws_s3_bucket" "b" {
  bucket = random_pet.this.id
}

resource "aws_s3_bucket_server_side_encryption_configuration" "b" {
  bucket = aws_s3_bucket.b.id

  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.a.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "b" {
  bucket = aws_s3_bucket.b.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "b" {
  bucket = aws_s3_bucket.b.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "b" {
  bucket = aws_s3_bucket.b.id

  rule {
    id     = "default"
    status = "Enabled"

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }

    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "STANDARD_IA"
    }

    noncurrent_version_transition {
      noncurrent_days = 60
      storage_class   = "ONEZONE_IA"
    }

    noncurrent_version_expiration {
      noncurrent_days = var.version_retention_days
    }
  }
}

resource "aws_s3_bucket_policy" "b" {
  bucket = aws_s3_bucket.b.id
  policy = data.aws_iam_policy_document.b.json
}

data "aws_iam_policy_document" "b" {
  statement {
    sid = "AllowSSLRequestsOnly"

    actions = ["s3:*"]
    effect  = "Deny"
    resources = [
      aws_s3_bucket.b.arn,
      "${aws_s3_bucket.b.arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = [false]
    }
  }
}

# resource "aws_s3_bucket_object_lock_configuration" "logs" {
#   bucket = aws_s3_bucket.logs.id

#   rule {
#     default_retention {
#       mode = "GOVERNANCE"
#       days = var.access_log_retention_days
#     }
#   }
# }

# data "aws_iam_policy_document" "logs" {
#   statement {
#     sid = "AllowSSLRequestsOnly"

#     actions = ["s3:*"]
#     effect  = "Deny"
#     resources = [
#       aws_s3_bucket.logs.arn,
#       "${aws_s3_bucket.logs.arn}/*",
#     ]

#     principals {
#       type        = "*"
#       identifiers = ["*"]
#     }

#     condition {
#       test     = "Bool"
#       variable = "aws:SecureTransport"
#       values   = [false]
#     }
#   }
# }

resource "aws_dynamodb_table" "d" {
  name         = random_pet.this.id
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockId"

  attribute {
    name = "LockId"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.a.arn
  }

  point_in_time_recovery {
    enabled = true
  }
}
