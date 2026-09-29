# Restore witness and recovery evidence outside both the database and the
# host rollback domains (bloom-relay#2). Versioned with Object Lock, so a
# restored database or a rolled-back host cannot rewind or erase it.
#
# The relay's witness today is a local file (bloom-relay-store/src/restore.rs).
# Publishing it here, and checking it at startup, is a relay code change this
# bucket is provisioned for; see README.md.

resource "aws_s3_bucket" "witness" {
  bucket_prefix       = "bloom-relay-${var.placement}-witness-"
  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "witness" {
  bucket = aws_s3_bucket.witness.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "witness" {
  bucket = aws_s3_bucket.witness.id

  rule {
    default_retention {
      mode = var.witness_retention_mode
      days = var.witness_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.witness]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "witness" {
  bucket = aws_s3_bucket.witness.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.relay.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "witness" {
  bucket                  = aws_s3_bucket.witness.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "witness" {
  bucket = aws_s3_bucket.witness.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

data "aws_iam_policy_document" "witness_bucket" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.witness.arn,
      "${aws_s3_bucket.witness.arn}/*",
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "witness" {
  bucket = aws_s3_bucket.witness.id
  policy = data.aws_iam_policy_document.witness_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.witness]
}
