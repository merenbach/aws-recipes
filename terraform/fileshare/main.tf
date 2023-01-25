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

  statement {
    sid    = "Allow CloudFront to use the key to deliver logs"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    actions = [
      "kms:GenerateDataKey*",
      "kms:Decrypt",
    ]
    resources = ["*"]
  }
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
  bucket = "${random_pet.this.id}-files"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "b" {
  bucket = aws_s3_bucket.b.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
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
  }
}

resource "aws_s3_bucket_policy" "b" {
  bucket = aws_s3_bucket.b.id
  policy = data.aws_iam_policy_document.b.json
}

resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
  comment = "access-identity-${aws_s3_bucket.b.bucket_regional_domain_name}"
}

data "aws_iam_policy_document" "b" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.b.arn}/*"]

    principals {
      type        = "AWS"
      identifiers = [aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn]
    }
  }

  statement {
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.b.arn]

    principals {
      type        = "AWS"
      identifiers = [aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn]
    }
  }

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

locals {
  # Cache here because this is reused in multiple places
  s3_origin_id = "S3-${aws_s3_bucket.b.id}"
}

resource "aws_cloudfront_distribution" "s3_distribution" {
  aliases             = var.cloudfront_aliases # will be null if unspecified
  comment             = "Proxy to s3://${aws_s3_bucket.b.id}"
  default_root_object = "index.html"
  enabled             = true
  http_version        = "http2and3" # default is "http2"  
  is_ipv6_enabled     = true
  price_class         = "PriceClass_100" # use PriceClass_200 or PriceClass_All for greater reach

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true
    cache_policy_id        = var.cloudfront_cache_policy_id
    target_origin_id       = local.s3_origin_id
    viewer_protocol_policy = "redirect-to-https"
  }

  logging_config {
    include_cookies = false
    bucket          = aws_s3_bucket.logs.bucket_domain_name
    # prefix          = "myprefix"
  }

  origin {
    domain_name = aws_s3_bucket.b.bucket_regional_domain_name
    origin_id   = local.s3_origin_id

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = var.cloudfront_allow_from == null ? "none" : "whitelist"
      locations        = var.cloudfront_allow_from
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = var.cloudfront_certificate_arn == null ? true : false
    acm_certificate_arn            = var.cloudfront_certificate_arn
    minimum_protocol_version       = var.cloudfront_certificate_arn != null ? "TLSv1.2_2021" : null
  }
}

resource "aws_s3_bucket" "logs" {
  bucket              = "${random_pet.this.id}-logs"
  object_lock_enabled = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.a.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    object_ownership = "ObjectWriter"
  }
}

resource "aws_s3_bucket_acl" "logs" {
  bucket = aws_s3_bucket.logs.id

  access_control_policy {
    grant {
      grantee {
        # awslogsdelivery, per <https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html#AccessLogsKMSPermissions>
        id   = "c4c1ede66af53448b93c283ce9448c4ba468c9432aa01d700d3878632f77d2d0"
        type = "CanonicalUser"
      }
      permission = "FULL_CONTROL"
    }

    owner {
      id = data.aws_canonical_user_id.current.id
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

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
      noncurrent_days = var.access_log_retention_days
    }

    expiration {
      days = var.access_log_retention_days
    }
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.access_log_retention_days
    }
  }
}

data "aws_iam_policy_document" "logs" {
  statement {
    sid = "AllowSSLRequestsOnly"

    actions = ["s3:*"]
    effect  = "Deny"
    resources = [
      aws_s3_bucket.logs.arn,
      "${aws_s3_bucket.logs.arn}/*",
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

resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id
  policy = data.aws_iam_policy_document.logs.json
}
