# Relay on AWS: host, database, backups and witness

Terraform for one relay placement in a single AWS region: the relay host on
EC2 and its PostgreSQL on RDS in the same VPC. It is the proposed answer to
the managed-database decision in
[bloom-relay#2](https://github.com/bloom-directory/bloom-relay/issues/2).
Nothing here has been applied.

## Why the host moves with the database

The gateway reads PostgreSQL when a tunnel opens and on every lease renewal,
and drops the tunnel when a renewal does not finish within 10 seconds
(`crates/bloom-relay/src/main.rs`, `renew_lifecycle`). A database across the
public internet from the host would put every tunnel at the mercy of that
path, and would need a publicly reachable PostgreSQL endpoint. In one VPC the
database has no public address and renewals stay on the AWS network.

## What it creates

| File | Resources |
|---|---|
| `network.tf` | VPC with IPv6, two public subnets (host), two private subnets with no internet route (database), security groups: 443 and ACME 80 to the host, optional SSH, PostgreSQL from the host only |
| `host.tf` | Debian 13 x86_64 EC2 instance, IMDSv2 only, encrypted gp3 root volume, termination protection; one interface with two private IPs and two Elastic IPs (control and Browser ingress) plus two IPv6 addresses; auto-recovery on host failure |
| `database.tf` | RDS PostgreSQL 17, Multi-AZ, gp3 with autoscaling, KMS encryption, forced TLS, SCRAM passwords, master password in Secrets Manager (never in Terraform state), 35-day point-in-time restore, deletion protection, final snapshot, event subscription and alarms |
| `backup.tf` | AWS Backup daily snapshots into a vault with Vault Lock, copied to a locked vault in a second region, alerts on failed/aborted/expired/partial jobs and when no job completed for two days |
| `witness.tf` | S3 bucket with versioning and Object Lock for the restore witness and recovery evidence, TLS only, no public access |
| `iam.tf` | Host role: SSM Session Manager plus append-only witness access; KMS key for host, database and witness |
| `alerts.tf` | Encrypted SNS topic with email subscription that CloudWatch, EventBridge and RDS can publish to |

The existing Route 53 zone and the DNS workers' IAM users are not managed
here. The workers keep their narrower users (`packaging/iam`) as systemd
credentials: every local user can reach instance metadata, so the host role
holds nothing a relay service should not have.

## Rough monthly cost (eu-central-1, on-demand)

Approximate list prices; confirm with the AWS pricing calculator.

| Item | ~USD/month |
|---|---|
| EC2 `t3.medium` | 35 |
| Two public IPv4 addresses | 7 |
| EBS gp3 30 GB | 3 |
| RDS `db.t4g.micro` Multi-AZ | 26 |
| RDS gp3 20 GB × 2 (Multi-AZ) | 6 |
| Backup vault snapshots and cross-region copy (database is megabytes) | 1 |
| KMS keys (4) | 4 |
| CloudWatch alarms and logs, SNS, Secrets Manager, S3 | 3 |
| **Total** | **~85** |

## Applying

1. Create a versioned, encrypted S3 bucket for Terraform state, copy
   `backend.hcl.example` to `backend.hcl` and `terraform.tfvars.example` to
   `terraform.tfvars`.
2. `terraform init -backend-config=backend.hcl`, then `terraform plan`.
   Review the vault lock in particular: after `vault_lock_changeable_days`
   the lock is permanent and retention can never be shortened.
3. `terraform apply`, then confirm the SNS email subscription.

## Host configuration differences from `docs/package.md`

Installation follows `docs/package.md`, except the database is remote:

- **Roles.** Using the master secret from Secrets Manager (from an
  administrator's machine or an SSM session, never stored on the host),
  create the schema owner and the five service roles with `LOGIN PASSWORD`,
  run `bloom-relay-migrate` as the owner, then apply
  `packaging/postgres/runtime-grants.sql.example`. Peer authentication does
  not exist on RDS.
- **Passwords.** Each service gets a one-line pgpass file as a systemd
  credential (`LoadCredential=pgpass:/etc/bloom-relay/credentials/<service>.pgpass`)
  and `Environment=PGPASSFILE=%d/pgpass`. sqlx reads `PGPASSFILE` when it
  parses the database URL, so no relay code change is needed and no password
  appears in an environment file.
- **TLS.** Install the RDS CA bundle as `/etc/bloom-relay/rds-ca.pem` and set
  every `BLOOM_RELAY_DATABASE_URL` to
  `postgresql://<role>@<database_endpoint>:5432/relay?sslmode=verify-full&sslrootcert=/etc/bloom-relay/rds-ca.pem`.
- **Addresses.** Bind HAProxy to `control_private_ipv4:443` and the gateway
  to `ingress_private_ipv4:443`; publish `ingress_ipv4` (and the ingress IPv6
  address) as `BLOOM_RELAY_INGRESS_ADDRESSES`.

## Known limits

- **Multi-AZ failover drops tunnels.** Failover takes one to two minutes,
  longer than the gateway's 10-second renewal timeout, so every tunnel
  disconnects and Brokers reconnect once the standby is promoted.
- **Restore witness.** The relay still keeps its witness as a local file.
  Publishing each revision to the witness bucket and refusing to start below
  it is a relay code change (bloom-relay#2); the bucket and the host's
  append-only access are ready for it.
- **Backup deletion authority.** Vault Lock stops early deletion within this
  account. A vault in a separate account, which this account can only copy
  into, needs AWS Organizations and is not configured here.
- **Rehearsal.** None of this is recovery evidence until the restore drills
  in bloom-relay#2 are run against it.

## Moving from the current host

1. Apply this configuration and install the relay on the new host with
   enrollment closed.
2. Stop the relay services on the old host, take a final `pg_dump`, restore it
   into RDS, copy the restore witness, and start the services on the new host.
3. Point `relay-control.bloom.directory` at `control_ipv4`, and let the DNS
   serving worker republish installation records to the new ingress address.
4. Confirm Broker reconnection and a remote passkey ceremony, then retire the
   old host. Brokers pin the control CA and receipt key, not addresses, so
   no Triad update is needed.
