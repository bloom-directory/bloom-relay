terraform {
  required_version = ">= 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # Remote state with locking. Supply bucket/key/region with
  # `terraform init -backend-config=backend.hcl` (see backend.hcl.example).
  # State holds no database password: RDS keeps the master secret in
  # Secrets Manager and service role passwords never pass through Terraform.
  backend "s3" {}
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project   = "bloom-relay"
      Placement = var.placement
      ManagedBy = "terraform"
    }
  }
}

# Cross-region copies of the locked backup vault.
provider "aws" {
  alias  = "backup_copy"
  region = var.backup_copy_region

  default_tags {
    tags = {
      Project   = "bloom-relay"
      Placement = var.placement
      ManagedBy = "terraform"
    }
  }
}
