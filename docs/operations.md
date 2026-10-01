# Relay operations

No DNS, cloud, wallet or certificate mutation runs in local tests.
The reviewable Linux release templates and role grants are in
[`package.md`](package.md); their installation and live drills are still
deployment actions.

For each deployment, record the DNS provider and its owning account,
zone ID and delegation or authoritative-zone decision, optional DNSSEC/DS
decision, ingress IPv4 and IPv6 addresses, shard placement, PostgreSQL service
and backup owner, and separate workload identities for gateway, control administration
and DNS reconciliation. The gateway must have no DNS provider permission.
For Route 53, restrict DNS roles to the delegated zone and exact record types.
The `relay-control.bloom.directory` TLS identity and receipt-signing
key need separate protected provisioning and rotation procedures.

The API process takes its PostgreSQL URL, bind address, placement and TLS
certificate/key paths from restricted service configuration. It signs
allocation receipts either with a raw 32-byte Ed25519 seed
(`BLOOM_RELAY_RECEIPT_KEY_PATH`) or with an AWS KMS `ECC_NIST_EDWARDS25519` key
(`BLOOM_RELAY_RECEIPT_KMS_KEY_ARN`, instance-role credentials only), whose
private half never leaves KMS. Set `BLOOM_RELAY_RECEIPT_PUBLIC_KEY_HEX` to the
public key Signers pin so a wrong key refuses to start; every signature is also
verified locally before it is returned. The gateway takes PostgreSQL URL,
gateway ID, control bind, public ingress bind and control TLS key paths.
The gateway ID must exactly equal its shard placement. A tunnel claim at a
different placement is rejected even with a valid scoped credential. Each DNS
worker claims only jobs for its configured placement.
Separate `dns-serving` and `dns-challenge` workers take the provider zone ID,
comma-separated ingress addresses and authoritative DNS server addresses.
Set `BLOOM_RELAY_DNS_PROVIDER` explicitly in deployment configuration. Route 53
remains the default for older configurations. Give its serving role only
A/AAAA/CAA changes and its challenge role only TXT changes under
`_acme-challenge`, with distinct AWS credentials. For Cloudflare, use distinct
zone-scoped API tokens delivered as protected files via systemd `LoadCredential`
as described in [`package.md`](package.md). The API process has no DNS provider
credential. All services require
`BLOOM_RELAY_RESTORE_WITNESS_PATH`, a restricted shared-group high-water file on
storage independent of PostgreSQL snapshots. Preserve the shared witness
across database restore. The store takes an advisory lock and advances the
witness before acknowledging each durable identity, credential, DNS and CT
security transition. A missing witness is accepted only for an empty new
database; an established database without its witness fails closed. A
database below its witness makes the service refuse startup or stop serving.
If a committed mutation cannot advance the witness, the request fails and
the operator reconciles the durable operation before retry. With the S3
witness configured (see [`package.md`](package.md)), the same rules apply to
the higher of the local and S3 revisions, so a whole-host rollback or a
replacement host cannot start below the last acknowledged transition.
Keep independently retained audit/backup evidence and rehearse restores.
Do not pass bearer values on command lines or environment variables. Broker
reads its tunnel credential from an owner-only file. The signed control API
uses its fixed public TLS origin; metrics and backend management belong on a
private network.
Bootstrap challenge issuance is capped at 10 per source IP and 100 globally
per minute, and at 20 completed enrollments per source IP per day. Consumed
challenges stay counted; the API sweeper prunes challenge history after two
days and replay nonces once they expire. Pending allocations expire after 24
hours. Browser ingress
admits at most 120 new TLS connections per source IP and 5,000 globally per
fixed minute. Tune these values from capacity/NAT measurements while
retaining Broker's installation and recovery-ID quotas.
In the packaged topology HAProxy terminates public TLS, so the API's TCP peer
is always HAProxy's loopback address. HAProxy therefore sends each client's
address with PROXY protocol v2 (`send-proxy-v2`) at the start of its backend
connection, before TLS, and the API keys its quotas on it when
`BLOOM_RELAY_CONTROL_PROXY_PROTOCOL=v2`. In that mode every connection must
carry the header, the API refuses to start on a non-loopback bind, and it never
reads client addresses from HTTP headers. Without it, every public bootstrap
would share HAProxy's single source bucket. This does not affect the gateway's
direct Browser-ingress source quota.

The selected rollout uses a separately delegated Route 53 child zone. For an
alternative Cloudflare deployment, record the authoritative zone ID and
nameservers in the restricted operations inventory. The relay's assigned names remain under `relay.bloom.directory`;
use exact, DNS-only A/AAAA/CAA records and exact `_acme-challenge` TXT records.
Use the Cloudflare zone ID in both worker env files, the public ingress address
in `BLOOM_RELAY_INGRESS_ADDRESSES`, and the zone's authoritative DNS server
addresses in `BLOOM_RELAY_AUTHORITATIVE_ADDRESSES`. Keep the control service
address and the ingress address distinct in the router and gateway config.
Cloudflare tokens cannot enforce per-record-name/type restrictions within a
zone; only worker scope, provider validation and outbox ownership checks enforce
that boundary. Review zone audit activity and keep the two tokens isolated.
Before accepting allocations, a separate zone operator must add CAA
`0 issue ";"` and `0 issuewild ";"` at `relay.bloom.directory`, preserving
all unrelated records there. This denies issuance for unallocated or retired
relay names that have no exact per-installation CAA. Do not put this policy at
`bloom.directory` or `relay-control.bloom.directory`; the DNS workers have no
authority to modify the parent policy. Confirm authoritative and recursive CAA
answers before enrollment and after a retirement.

The control API defaults to Let's Encrypt production account registration.
Set `BLOOM_RELAY_ACME_ENVIRONMENT=staging` only for an explicitly reviewed
staging issuance exercise while enrollment is closed, and allocate a fresh test
installation rather than rebinding an existing hostname. The only accepted
values are `production` and `staging`; any other value fails startup. Registration
accepts only the selected Let's Encrypt account URI namespace with a numeric
account ID. DNS reconciliation accepts those two validated namespaces so it can
publish the exact account-bound CAA record during a controlled test-mode switch;
the exact-owner `issuewild ";"` denial remains present.

Deployment acceptance must exercise authoritative and recursive
A/AAAA/CAA/TXT resolution, unknown-name NXDOMAIN, IPv4/IPv6 ingress,
placement move with stable RP, and provider change timeout/ambiguous-write
reconciliation. Register the ACME account URI before restrictive CAA
publication. Broker performs DNS-01 with its own account/key and certificate
private key, validates the exact hostname, stages a replacement certificate,
and reloads atomically. A failed renewal keeps a still-valid lineage only;
expiry disables remote access. Run staging issuance and renewal with
disposable names before enabling the production CA.

Keep control servers and clients synchronized with NTP. Clients allow up to five
seconds of positive server clock offset when checking future timestamps in
authenticated bootstrap challenges, signed allocation receipts and scoped
credential receipts. This narrow allowance covers ordinary subsecond clock and
request timing differences; production bootstrap measurements were below 100 ms.
It does not extend an expired challenge, credential or authorization claim, and
it does not change the server's authorization lifetime checks. An allocation
receipt issued slightly in the client's future is accepted only after its
signature and operation, admin key, hostname and freshness bindings validate.
Offsets approaching the allowance are an operational clock fault to alert on and
correct, rather than a reason to increase the allowance.

To move a live installation, provision the new gateway and its ingress
addresses first. Run `bloom-relay-relocate INSTALLATION_UUID OPERATION_UUID
PLACEMENT` from the restricted operator environment with
`BLOOM_RELAY_DATABASE_URL` and `BLOOM_RELAY_RESTORE_WITNESS_PATH`. Reuse the
same operation UUID on an ambiguous retry. The transaction preserves the
hostname, fences the old tunnel, changes placement and queues a new exact DNS
publish. DNS writes already in progress finish under a per-installation
database advisory lock before the move commits. The new placement worker
publishes A/AAAA and observes authoritative and recursive answers; only then
should operators consider the move complete. Wait for the previous DNS TTL,
verify new ingress and reconnect, and record the observed propagation. Do not
run two public gateway processes with the same placement as an HA strategy.

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
alert. The local HTTPS fixture exercises both deliveries. A deployment
supplies a reviewed CT source/adapter that validates log entries, plus a
monitored alert sink and on-call target. Exercise a drill for unexpected
issuance:
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
alert fixture. CI provisions the disposable database. Provider propagation,
failure, load and incident drills run against a deployment, not in CI; a
health endpoint or local fixture alone is not readiness evidence.
