output "control_ipv4" {
  description = "Public control address: point relay-control.bloom.directory here and bind HAProxy to control_private_ipv4."
  value       = aws_eip.control.public_ip
}

output "control_private_ipv4" {
  value = local.control_private_ip
}

output "ingress_ipv4" {
  description = "Public Browser ingress address: BLOOM_RELAY_INGRESS_ADDRESSES for the DNS workers."
  value       = aws_eip.ingress.public_ip
}

output "ingress_private_ipv4" {
  description = "BLOOM_RELAY_INGRESS_BIND host for the gateway."
  value       = local.ingress_private_ip
}

output "host_ipv6" {
  value = aws_network_interface.relay.ipv6_address_list
}

output "instance_id" {
  value = aws_instance.relay.id
}

output "database_endpoint" {
  description = "Host for every service's BLOOM_RELAY_DATABASE_URL, with sslmode=verify-full."
  value       = aws_db_instance.relay.address
}

output "database_master_secret_arn" {
  description = "Secrets Manager secret holding the RDS master password. Used only to create roles; never installed on the host."
  value       = aws_db_instance.relay.master_user_secret[0].secret_arn
}

output "witness_bucket" {
  value = aws_s3_bucket.witness.id
}

output "backup_vaults" {
  value = {
    primary = aws_backup_vault.primary.arn
    copy    = aws_backup_vault.copy.arn
  }
}

output "alerts_topic_arn" {
  value = aws_sns_topic.alerts.arn
}
