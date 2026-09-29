variable "region" {
  description = "Region for the relay host, database, witness bucket and primary backup vault."
  type        = string
  default     = "eu-central-1"
}

variable "backup_copy_region" {
  description = "Second region that receives a copy of every backup snapshot."
  type        = string
  default     = "eu-north-1"
}

variable "placement" {
  description = "Relay placement name, matching BLOOM_RELAY_PLACEMENT and BLOOM_RELAY_GATEWAY_ID."
  type        = string
  default     = "relay-1"
}

variable "vpc_cidr" {
  description = "CIDR for the relay VPC."
  type        = string
  default     = "10.40.0.0/16"
}

variable "instance_type" {
  description = "Relay host instance type. Released relay packages are x86_64."
  type        = string
  default     = "t3.medium"
}

variable "root_volume_gb" {
  description = "Relay host root volume size."
  type        = number
  default     = 30
}

variable "admin_ssh_cidrs" {
  description = "CIDRs allowed to reach SSH. Empty means SSH is closed and administration uses SSM Session Manager."
  type        = list(string)
  default     = []
}

variable "db_instance_class" {
  description = "RDS instance class. The relay database is megabytes; Multi-AZ is for availability, not capacity."
  type        = string
  default     = "db.t4g.micro"
}

variable "db_allocated_storage_gb" {
  description = "Initial gp3 storage."
  type        = number
  default     = 20
}

variable "db_max_allocated_storage_gb" {
  description = "Storage autoscaling ceiling."
  type        = number
  default     = 100
}

variable "db_backup_retention_days" {
  description = "RDS automated backup retention, which bounds point-in-time restore (maximum 35)."
  type        = number
  default     = 35
}

variable "vault_snapshot_retention_days" {
  description = "Retention for daily snapshots in the locked backup vault and its cross-region copy."
  type        = number
  default     = 90
}

variable "vault_lock_changeable_days" {
  description = "Cooling-off period before the vault lock becomes immutable. Review the plan within this window; after it, retention can never be shortened."
  type        = number
  default     = 7
}

variable "witness_retention_mode" {
  description = "S3 Object Lock default mode for the restore witness and recovery evidence. GOVERNANCE while the design is rehearsed; COMPLIANCE for production."
  type        = string
  default     = "GOVERNANCE"

  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.witness_retention_mode)
    error_message = "witness_retention_mode must be GOVERNANCE or COMPLIANCE."
  }
}

variable "witness_retention_days" {
  description = "Default Object Lock retention for every witness and evidence object version."
  type        = number
  default     = 400
}

variable "alert_email" {
  description = "Address subscribed to operational alerts. The subscription must be confirmed from the email AWS sends."
  type        = string
}
