# Daily snapshots into a locked vault, copied to a second region. RDS
# automated backups give point-in-time restore; this vault is the copy the
# relay host, its instance role and an ordinary administrator cannot delete
# early once the lock is past its cooling-off period.
#
# Separating backup deletion authority fully means a vault in a second AWS
# account that this account can only copy into. That needs AWS Organizations;
# see README.md.

resource "aws_kms_key" "backup" {
  description             = "bloom-relay ${var.placement} backup vault"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "backup" {
  name          = "alias/bloom-relay-${var.placement}-backup"
  target_key_id = aws_kms_key.backup.key_id
}

resource "aws_backup_vault" "primary" {
  name        = "bloom-relay-${var.placement}"
  kms_key_arn = aws_kms_key.backup.arn
}

resource "aws_backup_vault_lock_configuration" "primary" {
  backup_vault_name   = aws_backup_vault.primary.name
  min_retention_days  = 7
  max_retention_days  = 400
  changeable_for_days = var.vault_lock_changeable_days
}

resource "aws_kms_key" "backup_copy" {
  provider = aws.backup_copy

  description             = "bloom-relay ${var.placement} backup vault copy"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_backup_vault" "copy" {
  provider = aws.backup_copy

  name        = "bloom-relay-${var.placement}-copy"
  kms_key_arn = aws_kms_key.backup_copy.arn
}

resource "aws_backup_vault_lock_configuration" "copy" {
  provider = aws.backup_copy

  backup_vault_name   = aws_backup_vault.copy.name
  min_retention_days  = 7
  max_retention_days  = 400
  changeable_for_days = var.vault_lock_changeable_days
}

resource "aws_backup_plan" "relay" {
  name = "bloom-relay-${var.placement}"

  rule {
    rule_name         = "daily"
    target_vault_name = aws_backup_vault.primary.name
    # After the RDS backup window, before the maintenance window.
    schedule          = "cron(0 5 * * ? *)"
    start_window      = 60
    completion_window = 180

    lifecycle {
      delete_after = var.vault_snapshot_retention_days
    }

    copy_action {
      destination_vault_arn = aws_backup_vault.copy.arn

      lifecycle {
        delete_after = var.vault_snapshot_retention_days
      }
    }
  }
}

data "aws_iam_policy_document" "backup_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["backup.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "backup" {
  name               = "bloom-relay-${var.placement}-backup"
  assume_role_policy = data.aws_iam_policy_document.backup_assume.json
}

resource "aws_iam_role_policy_attachment" "backup" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

resource "aws_iam_role_policy_attachment" "restore" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores"
}

resource "aws_backup_selection" "relay" {
  name         = "bloom-relay-${var.placement}-database"
  plan_id      = aws_backup_plan.relay.id
  iam_role_arn = aws_iam_role.backup.arn
  resources    = [aws_db_instance.relay.arn]
}

# Any failed, aborted, expired or partial backup or copy job alerts at once.
resource "aws_cloudwatch_event_rule" "backup_failures" {
  name = "bloom-relay-${var.placement}-backup-failures"
  event_pattern = jsonencode({
    source      = ["aws.backup"]
    detail-type = ["Backup Job State Change", "Copy Job State Change"]
    detail = {
      state = ["FAILED", "ABORTED", "EXPIRED", "PARTIAL"]
    }
  })
}

resource "aws_cloudwatch_event_target" "backup_failures" {
  rule = aws_cloudwatch_event_rule.backup_failures.name
  arn  = aws_sns_topic.alerts.arn
}

# Freshness: a job that silently never runs emits no failure event. Alarm
# when no backup job completed in the vault for two consecutive days.
resource "aws_cloudwatch_metric_alarm" "backup_freshness" {
  alarm_name          = "bloom-relay-${var.placement}-backup-freshness"
  namespace           = "AWS/Backup"
  metric_name         = "NumberOfBackupJobsCompleted"
  dimensions          = { BackupVaultName = aws_backup_vault.primary.name }
  statistic           = "Sum"
  period              = 86400
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}
