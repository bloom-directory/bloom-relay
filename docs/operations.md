# Relay operations and deployment gates

This repository contains implementation work but is not deployed. No DNS,
cloud, wallet or certificate mutation runs in local tests.

Before a production rollout, record the owning AWS account, Route 53 hosted
zone ID and parent-zone NS delegation, optional DNSSEC/DS decision, ingress
IPv4 and IPv6 addresses, shard placement, PostgreSQL service and backup
owner, and separate workload identities for gateway, control administration
and DNS reconciliation. The gateway must have no Route 53 permission; the
DNS role must be restricted to the delegated zone and exact record types.
The `relay-control.bloom.directory` TLS identity and offline receipt-signing
key need separate protected provisioning and rotation procedures.

The control service takes its PostgreSQL URL, bind address, placement, TLS
certificate/key paths and raw 32-byte receipt-signing key path from
restricted service configuration. The gateway takes PostgreSQL URL,
gateway ID, control bind, public ingress bind and control TLS key paths.
Control also requires the delegated Route 53 hosted zone ID, comma-separated
ingress addresses and authoritative DNS server addresses. Its DNS worker uses
the standard AWS workload credential chain; give that role permission only
for exact A/AAAA/CAA/TXT changes in the delegated zone. Both services require
`BLOOM_RELAY_RESTORE_WITNESS_PATH`, an owner-only local high-water file on
storage independent of PostgreSQL snapshots. Preserve the shared witness
across database restore. The store takes an advisory lock and advances the
witness before acknowledging each durable identity, credential, DNS and CT
security transition. A missing witness is accepted only for an empty new
database; an established database without its witness fails closed. A
database below its witness makes the service refuse startup or stop serving.
If a committed mutation cannot advance the witness, the request fails and
the operator reconciles the durable operation before retry. Production
recovery still needs independently retained audit/backup evidence and a
documented restore rehearsal.
Do not pass bearer values on command lines or environment variables. Broker
reads its tunnel credential from an owner-only file. Control metrics and
administrative endpoints belong on a private network.

Deployment acceptance must exercise authoritative and recursive
A/AAAA/CAA/TXT resolution, unknown-name NXDOMAIN, IPv4/IPv6 ingress,
placement move with stable RP, and Route 53 change timeout/ambiguous-write
reconciliation. Register the ACME account URI before restrictive CAA
publication. Broker performs DNS-01 with its own account/key and certificate
private key, validates the exact hostname, stages a replacement certificate,
and reloads atomically. A failed renewal keeps a still-valid lineage only;
expiry disables remote access. Run staging issuance and renewal with
disposable names before enabling the production CA.

Backups must preserve `hostname_reservations` and security audit high-water
marks beyond the database snapshot. Restoring a stale snapshot must be
refused until compared against external audit and certificate inventory
markers. Never recycle a retired hostname or silently rebind an admin key.
If protected admin authority is lost, provision a new installation identity
and use the wallet credential/recovery procedure.

`bloom-relay-ct` pulls a configured authenticated HTTPS feed adapter every
30 seconds. It requires a pinned feed CA and owner-only bearer file, and the
adapter contract is `GET /v1/entries?after=N&limit=100` returning a source ID
and contiguous positions with exact hostname and SPKI SHA-256. The worker
persists checkpoints, expected inventory and unexpected issuance alerts, then
POSTs them to a separately authenticated HTTPS alert sink with a stable
idempotency key. A 15-minute feed outage creates a distinct durable lag
alert. The local HTTPS fixture exercises both deliveries. Production still
requires selection and review of a real CT source/adapter that validates log
entries, plus a monitored alert sink and on-call target. Before production,
exercise a
drill for unexpected issuance:
contain DNS/control credentials, identify affected names, notify owners,
revoke improper certificates, inspect audit and CT, and verify a legitimate
rotation does not trigger a false incident. Record audit retention and
access controls, bootstrap abuse thresholds, tested capacity, and incident
contacts. Public DNS/CA drills are opt-in operations with reviewed
credentials.

The local test gate uses disposable PostgreSQL 14 and loopback-only TLS. Run
`BLOOM_RELAY_TEST_DATABASE_URL=postgres://... cargo test --workspace --locked`
to exercise opaque Browser TLS forwarding, tunnel reconnect fencing, scoped
credential rotation, DNS challenge leases, stale restore refusal and the CT
alert fixture. CI provisions the disposable database. The remaining rollout
work is CT source/adapter and alert destination configuration, real Route 53 propagation and failure
drills, public ACME staging issuance/renewal, production service packaging,
load and incident drills, and the recorded ownership/configuration above.
A health endpoint or local fixture alone is not production readiness evidence.
