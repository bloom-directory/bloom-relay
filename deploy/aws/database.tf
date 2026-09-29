resource "aws_db_subnet_group" "relay" {
  name       = "bloom-relay-${var.placement}"
  subnet_ids = aws_subnet.database[*].id
}

resource "aws_db_parameter_group" "relay" {
  name   = "bloom-relay-${var.placement}-pg17"
  family = "postgres17"

  # Every connection must use TLS; services verify the RDS CA and hostname
  # (sslmode=verify-full).
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  parameter {
    name  = "password_encryption"
    value = "scram-sha-256"
  }

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }
}

resource "aws_db_instance" "relay" {
  identifier     = "bloom-relay-${var.placement}"
  engine         = "postgres"
  engine_version = "17"
  instance_class = var.db_instance_class
  multi_az       = true

  db_name                     = "relay"
  username                    = "relay_admin"
  manage_master_user_password = true

  allocated_storage     = var.db_allocated_storage_gb
  max_allocated_storage = var.db_max_allocated_storage_gb
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.relay.arn

  db_subnet_group_name   = aws_db_subnet_group.relay.name
  vpc_security_group_ids = [aws_security_group.database.id]
  parameter_group_name   = aws_db_parameter_group.relay.name
  publicly_accessible    = false
  ca_cert_identifier     = "rds-ca-ecc384-g1"

  # Point-in-time restore window. The locked vault in backup.tf holds
  # longer-lived copies outside this instance's own deletion path.
  backup_retention_period  = var.db_backup_retention_days
  backup_window            = "02:00-02:30"
  maintenance_window       = "sun:03:00-sun:04:00"
  copy_tags_to_snapshot    = true
  delete_automated_backups = false

  deletion_protection       = true
  skip_final_snapshot       = false
  final_snapshot_identifier = "bloom-relay-${var.placement}-final"

  auto_minor_version_upgrade      = true
  allow_major_version_upgrade     = false
  apply_immediately               = false
  enabled_cloudwatch_logs_exports = ["postgresql"]

  performance_insights_enabled          = true
  performance_insights_kms_key_id       = aws_kms_key.relay.arn
  performance_insights_retention_period = 7
}

resource "aws_db_event_subscription" "relay" {
  name        = "bloom-relay-${var.placement}"
  sns_topic   = aws_sns_topic.alerts.arn
  source_type = "db-instance"
  source_ids  = [aws_db_instance.relay.identifier]
  event_categories = [
    "availability",
    "backup",
    "failover",
    "failure",
    "low storage",
    "maintenance",
    "notification",
    "recovery",
    "restoration",
  ]
}

resource "aws_cloudwatch_metric_alarm" "db_free_storage" {
  alarm_name          = "bloom-relay-${var.placement}-db-free-storage"
  namespace           = "AWS/RDS"
  metric_name         = "FreeStorageSpace"
  dimensions          = { DBInstanceIdentifier = aws_db_instance.relay.identifier }
  statistic           = "Minimum"
  period              = 300
  evaluation_periods  = 2
  threshold           = 2 * 1024 * 1024 * 1024
  comparison_operator = "LessThanThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "db_cpu" {
  alarm_name          = "bloom-relay-${var.placement}-db-cpu"
  namespace           = "AWS/RDS"
  metric_name         = "CPUUtilization"
  dimensions          = { DBInstanceIdentifier = aws_db_instance.relay.identifier }
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  threshold           = 80
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

# Burstable classes throttle to baseline when credits run out, which would
# slow every tunnel renewal.
resource "aws_cloudwatch_metric_alarm" "db_cpu_credits" {
  alarm_name          = "bloom-relay-${var.placement}-db-cpu-credits"
  namespace           = "AWS/RDS"
  metric_name         = "CPUCreditBalance"
  dimensions          = { DBInstanceIdentifier = aws_db_instance.relay.identifier }
  statistic           = "Minimum"
  period              = 300
  evaluation_periods  = 3
  threshold           = 20
  comparison_operator = "LessThanThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "db_connections" {
  alarm_name          = "bloom-relay-${var.placement}-db-connections"
  namespace           = "AWS/RDS"
  metric_name         = "DatabaseConnections"
  dimensions          = { DBInstanceIdentifier = aws_db_instance.relay.identifier }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 2
  threshold           = 60
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}
