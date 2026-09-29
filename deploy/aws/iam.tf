data "aws_caller_identity" "current" {}

# Encrypts the host volume, database, Performance Insights and witness
# bucket. The backup vaults and alerts have their own keys.
resource "aws_kms_key" "relay" {
  description             = "bloom-relay ${var.placement} host, database and witness"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "relay" {
  name          = "alias/bloom-relay-${var.placement}"
  target_key_id = aws_kms_key.relay.key_id
}

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# Every local user can reach instance metadata, so this role must never
# hold more than any relay service may do. The DNS workers keep their own
# narrower IAM users (packaging/iam), delivered as systemd credentials.
resource "aws_iam_role" "relay_host" {
  name               = "bloom-relay-${var.placement}-host"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy_attachment" "relay_host_ssm" {
  role       = aws_iam_role.relay_host.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Append-only witness access: new versions and reads. No delete, no
# retention bypass, no lock or lifecycle changes.
data "aws_iam_policy_document" "relay_host_witness" {
  statement {
    sid       = "ListWitness"
    actions   = ["s3:ListBucket", "s3:ListBucketVersions"]
    resources = [aws_s3_bucket.witness.arn]
  }

  statement {
    sid = "AppendWitness"
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:PutObject",
    ]
    resources = ["${aws_s3_bucket.witness.arn}/*"]
  }

  statement {
    sid       = "WitnessKey"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.relay.arn]
  }

  statement {
    sid       = "ReadDatabaseMasterSecret"
    effect    = "Deny"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "relay_host_witness" {
  name   = "witness-append"
  role   = aws_iam_role.relay_host.id
  policy = data.aws_iam_policy_document.relay_host_witness.json
}

resource "aws_iam_instance_profile" "relay_host" {
  name = "bloom-relay-${var.placement}-host"
  role = aws_iam_role.relay_host.name
}
