# bloom-relay

**Status:** proposed codebase and implementation plan, 2026-09-17. This repository
is new; the components below are work to build, not deployed capabilities.

Bloom's relay makes a self-hosted Broker reachable at
`https://<randomid>.relay.bloom.directory` without inbound ports or user DNS
configuration. It provides hostname allocation, authoritative DNS automation,
authenticated outbound tunnels, certificate challenge support and operations.
Broker serves the ceremony application and terminates Browser TLS. Signer retains
custody and ceremony authority. Relay owns neither wallet state nor approval logic.

See the sibling [remote architecture](../bloom/docs/architecture/Open-Internet%20Sealed%20Approval%20Ceremony.md)
and [cross-stack plan](../bloom/docs/plans/2026-09-17-remote-ceremonies.md).
These relative links assume the documented sibling checkout layout. The two
supported ceremony origins are assigned relay HTTPS and canonical localhost;
custom domains, LAN/VPN origins and fully hosted Triads are deferred.

## Rust and dependencies

Use **Rust edition 2024**, workspace resolver 3, and the latest stable compiler.
At this planning checkpoint that is **Rust 1.98.1**. Scaffold with an exact
`rust-toolchain.toml` pin, `rustfmt` and `clippy`, and a matching workspace
`rust-version`. Recheck stable before the first implementation commit; subsequent
updates are reviewed changes rather than a floating release build. Sources:
[Rust edition guide](https://doc.rust-lang.org/edition-guide/rust-2024/index.html),
[Rust 1.98.1 announcement](https://blog.rust-lang.org/2026/09/03/Rust-1.98.1/).

Select latest mutually compatible **stable, non-yanked** library releases at
scaffolding. Use workspace dependency declarations, explicit minimal features,
a committed Cargo.lock and `--locked` in CI/releases. Do not use wildcard versions,
nightly-only dependencies or unpinned Git heads. Document any compatibility-driven
exception. These are selected libraries, not a claim of an already tested graph:

| Concern | Libraries / baseline verified at planning time |
| --- | --- |
| Async I/O and cancellation | [tokio](https://docs.rs/tokio/latest/tokio/) 1.53.1, tokio-util; tracked tasks, bounded channels and semaphores |
| Control HTTP API | [axum](https://docs.rs/axum/latest/axum/) 0.8.9, tower, tower-http; explicit middleware and admission limits |
| Outbound tunnel transport | [h2](https://docs.rs/h2/latest/h2/), http, bytes; HTTP/2 over TLS/TCP 443 |
| Transport TLS | [rustls](https://docs.rs/rustls/latest/rustls/) 0.23.45, tokio-rustls; one explicitly selected supported crypto provider |
| Persistence | [sqlx](https://docs.rs/sqlx/latest/sqlx/) 0.9.0 with PostgreSQL, Tokio and rustls features; versioned SQL migrations |
| Diagnostics | tracing, [tracing-subscriber](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/) 0.3.23; JSON production logs, EnvFilter |
| Errors | [thiserror](https://docs.rs/thiserror/latest/thiserror/) 2.0.20 for typed library errors; anyhow only at executable boundaries |
| DNS provider | [aws-sdk-route53](https://docs.rs/aws-sdk-route53/latest/aws_sdk_route53/) and aws-config for Route 53; reqwest with rustls for Cloudflare DNS API |
| Supporting APIs | serde/serde_json, clap, validated TOML configuration, [reqwest](https://docs.rs/reqwest/latest/reqwest/) with rustls for bounded HTTP calls |
| Metrics and tests | metrics + Prometheus exporter; proptest, cargo-fuzz, testcontainers or a disposable PostgreSQL fixture |

Resolve versions for supporting libraries at implementation time, record the
resolved inventory and MSRV, and check advisories/licenses with cargo-deny and
cargo-audit. Keep the Broker-integrated client/protocol crates free of the AWS
SDK, PostgreSQL and server-only dependencies; confirm their toolchain requirements
with Broker before pinning them downstream.

## Reuse-first development

Implementation agents and subagents must inspect existing Bloom/Broker/Signer
modules and maintained libraries before proposing new code. Return a short reuse
map for each work package: requirement, existing module/API or library, and the
extension needed. Reuse owner-maintained protocol/client crates instead of copying
code or creating competing authority, ceremony or session implementations.

Prefer established protocols and libraries for TLS, cryptography, HTTP/2 framing,
ClientHello parsing, credential verification primitives, serialization, database
transactions, retries, tracing and DNS/ACME integration. Evaluate library support
for bounded input/memory, maintenance, license, MSRV and compatible features.
Extend the existing Broker ACME/certificate integration where available; this
repository does not need its own ACME implementation.

Custom code should implement Bloom-specific ownership, scope, state transitions
and orchestration on those primitives. Any proposed custom parser, transport,
authentication mechanism or other general infrastructure must identify existing
alternatives and explain the concrete unmet requirement before implementation.
Do not hand-roll TLS, cryptographic algorithms, HTTP/2 framing or ACME. For SNI
routing, first evaluate maintained bounded ClientHello parsing support that leaves
the original bytes intact without terminating Browser TLS. Keep adversarial tests
for Bloom's integration even when the underlying mechanism comes from a library.

## Components and repository shape

```text
crates/
  bloom-relay-protocol/   versioned wire types, identifiers, limits, error codes
  bloom-relay-client/     Broker-integrated outbound client, no wallet APIs
  bloom-relay/            ingress + tunnel gateway executable
  bloom-relay-control/    enrollment API + reconciliation workers executable
  bloom-relay-store/      SQL transactions, migrations, outbox and audit records
  bloom-relay-dns/        narrow DNS interface, Route 53, Cloudflare and test adapters
migrations/              forward schema changes and restore/version checks
tests/                   protocol, routing, DNS and fault-injection integration
infra/                   reviewed DNS, network, identity, DB and service definitions
docs/                    wire protocol, operations, threat model and release evidence
```

Share types, not authority. Data-plane processes have no DNS write credential or
admin signing key. Control workers use separate scoped service identities.
Broker uses the client library inside its security boundary and attaches only to
its fixed ceremony TLS listener. No relay message supplies an arbitrary local
host/port, command, filesystem path, Machine RPC or Signer destination.

## DNS and public ingress

Route 53 and Cloudflare are supported behind the narrow DNS adapter. The intended
rollout uses Cloudflare's existing authoritative `bloom.directory` zone while
assigned names remain under `relay.bloom.directory`. Route 53 remains available
for a separately delegated relay zone. Record provider ownership, zone ID,
nameservers, optional DNSSEC/DS decision and ingress addresses before production;
they are not application-controlled or assumed to be deployed. Provider choice
does not change installation identity or protocol. Cloudflare zone-level API
tokens cannot restrict individual record names or types as Route 53 IAM can;
the serving and challenge worker scope boundaries are application-enforced.

Use **explicit per-installation A/AAAA records**, not a wildcard, pointing to the
assigned relay ingress shard's stable addresses. Publish AAAA only when IPv6 is
actually served. Use a 300-second initial TTL. Do not use a CNAME at the assigned
hostname: that owner also needs its own exact CAA records. Unknown names resolve
NXDOMAIN and unknown/unassigned SNI is rejected even if DNS is stale or forged.

Each installation gets a lowercase DNS-safe random label with at least 128 bits
of OS-generated entropy, independent of user/wallet identity. A DB unique
constraint handles collisions. Keep hostname identity and ingress placement
separate: shard moves change addresses, never the credential RP. Reserve control
service names outside the random label namespace.

Use a dedicated HTTPS control/tunnel endpoint, proposed
`relay-control.bloom.directory`, with its own ordinary service certificate. This
certificate is unrelated to individual Brokers' certificates. It can terminate
outer transport TLS; the ceremony ingress cannot terminate inner Browser TLS.

Allocation and DNS are a reconciled workflow:

1. Authenticate installation admin proof and allocate hostname + immutable owner
   transactionally with an idempotency key and durable outbox entry.
2. Register the Broker-created ACME account URI, publish exact CAA and A/AAAA
   records, then observe authoritative DNS before declaring DNS ready.
3. Broker requests DNS-01 leases, obtains its own exact-host certificate, opens
   its tunnel, and proves external HTTPS readiness before ceremony activation.
4. Retry incomplete stages under the same installation/operation ID; no second
   hostname is allocated because a provider response was lost.

Tombstones are permanent and survive uninstall and restore. DNS records may be
removed during retirement, but the label and ownership history are never recycled.
TTL caches do not authorize routing; gateway ownership checks remain mandatory.
At rollout, test recursive and authoritative A/AAAA/CAA/TXT resolution, NXDOMAIN,
IPv4/IPv6 connectivity and placement changes without RP changes.

Initial serving topology is one active ingress per shard, with durable placement
in PostgreSQL and Broker reconnect on replacement. Do not put arbitrary ingress
replicas behind a random TCP load balancer: a browser must reach the gateway
holding its installation tunnel. Add authenticated inter-gateway routing or an
explicit shared-placement strategy before claiming multi-node HA. Availability
loss during initial failover is acceptable; misrouting is not.

## Enrollment and scoped authority

Signer-local elevated setup holds an installation-admin private key and supplies
proof of possession over a service nonce, operation ID and canonical request.
The control plane enrolls the public key; it receives no wallet key or passkey.
Separate credentials authorize `surface_admin`, `tunnel` and `dns_challenge`.
Admin credentials are protected separately from online tunnel/DNS credentials.
Use standard TLS and reviewed signature libraries, never custom cryptography.

Automatic first enrollment needs a defined admission policy, not a shared secret
embedded in the installer. Implement a rate-limited bootstrap challenge and admin
key proof with per-source/global allocation quotas and a bounded pending-allocation
lifetime. Proof identifies an installation, not a trusted human or unlimited
entitlement. Record anti-abuse thresholds and capacity/incident controls before
opening bootstrap publicly; if stronger admission becomes necessary, return an
explicit provisioning-pending result rather than pretending setup succeeded.

Enrollment issues scoped, renewable service credentials bound to installation,
audience, scope, expiry and generation. Prefer mutual TLS for routine gateway
connections; specify the issuance/renewal/revocation protocol and nonce signature
encoding before coding. Credential rotation must fence old sessions. Rebinding
an ACME account or admin key requires existing admin proof or a separately
established offline recovery authority; neither a tunnel credential nor a support
request suffices. If all admin recovery authority is lost, do not reassign the
old hostname: provision a new installation identity and use the wallet's existing
credential/recovery protocol to regain access.

Proposed `/v1` control API operations: bootstrap challenge/enrollment, installation
status, scoped credential renewal, ACME account registration/rebinding, challenge
lease create/delete, certificate metadata publication, tunnel claim and retirement.
Every mutation has typed input, authorization scope, nonce/expiry, generation,
idempotency key, bounded size and stable operation status. Never accept arbitrary
DNS names or record types from the client. Publish a wire schema and compatibility
vectors in `bloom-relay-protocol` before Broker integration.

## DNS-01, CAA and certificate lifecycle

Challenge API inputs are installation ID, lease/operation ID and TXT value;
server derives `_acme-challenge.<assigned-hostname>`. Use short expiring leases,
conditional updates and per-host serialization. Cleanup removes only its own
value; delayed cleanup cannot remove a newer concurrent challenge. Authenticate
scope on both creation and deletion and audit lifecycle events without TXT values.
Check propagation before reporting ready. Sweep abandoned leases idempotently.

The DNS worker alone holds a provider identity restricted to the selected zone;
further enforce exact ownership and record-type boundaries in code. Route 53
roles can additionally restrict record names, types and operations through IAM.
Cloudflare zone-level tokens cannot provide those per-record/type limits.
Admin CAA/address reconciliation and routine TXT hooks use separate identities.
No hook can mutate CAA, siblings, parent zones, wildcards, MX or arbitrary records.

Publish exact CAA authorizing Let's Encrypt, DNS-01 and the enrolled ACME account
URI, with wildcard issuance denied. Keep restrictive deny-by-default parent
policy for unallocated names. Test actual CA enforcement in staging; DNS does
not itself enforce issuance policy. ACME account/key and certificate private key
stay in Broker. This repository supplies challenge APIs/client integration and
metadata checks; Broker owns Certbot/ACME orchestration, renewal, staged deploy,
atomic reload and valid-lineage rollback.

Certificate metadata includes expected hostname, key fingerprint, lineage and
validity, authenticated by the installation, never private keys. Monitor CT with
checkpoints, deduplication and inventory reconciliation; alert within 15 minutes
of monitored unexpected issuance. Alert separately on feed lag so a silent feed
cannot count as successful monitoring. Exercise containment, notification,
revocation, and legitimate certificate rotation races. Bloom remains trusted as
authoritative DNS/control-plane operator despite CAA and CT.

## Blind tunnel protocol

Use outbound HTTP/2 over authenticated TLS/TCP 443 from Broker to gateway. Browser
TLS is an opaque inner byte stream. Maintain one control stream; gateway requests
a connection with a random, short-lived single-use ticket, and Broker opens an
outbound CONNECT stream for that ticket. The ticket binds installation, hostname,
gateway lease generation and connection ID. Broker never accepts a requested
upstream address. HTTP/2 flow control bounds each stream and total connection.
Specify control-frame encoding and CONNECT authority semantics before implementation.

Gateway reads only enough Browser TLS records to assemble a bounded ClientHello
and extract exact SNI. Preserve every buffered byte and forward unchanged after
routing. Handle fragmentation, duplicate/invalid extensions, malformed lengths,
missing SNI and unsupported routing explicitly; no TLS handshake termination or
HTTP error injected into Browser TLS. Do not advertise ECH/HTTP3 for ceremony
ingress in v1. Browser ALPN remains Broker's decision inside its TLS handshake.

One installation/hostname has one current authenticated tunnel lease/generation.
A new valid connection atomically fences an old one; stale tickets and reconnect
races cannot claim another installation. Database/control-plane loss denies new
enrollment or uncertain routing; live streams may finish within their limits,
but new streams require an unexpired ownership lease. Renewals are generation
checked; no unbounded stale authorization cache.

Starting limits, adjustable through validated server config and load tests:
ClientHello 64 KiB / 5 seconds; ticket and stream-open deadline 10 seconds;
128 streams per installation; 10,000 streams per gateway; 64 KiB buffer per
stream direction with a 256 MiB aggregate buffer budget; 120-second idle timeout;
30-minute absolute stream lifetime; control heartbeat 15 seconds and dead-peer
threshold 45 seconds; reconnect exponential backoff with jitter, 1–60 seconds.
Reject at capacity before allocating buffers. Browser application retries reconcile
through Broker ceremony IDs; relay never replays a partially forwarded stream.

## Persistence, errors and observability

PostgreSQL is authoritative for installations/admin keys, scoped credential
generations, hostname/tombstone ownership, ingress placement and leases, ACME
bindings, DNS jobs/challenge leases, certificate inventory, audit and idempotency
records. Use transactions, uniqueness constraints and compare-and-swap revisions;
external DNS changes use a transactional outbox with reconciliation, not a pretend
cross-system transaction. Audit security mutations in the same DB transaction.
Backups need tested restoration plus external audit/inventory high-water marks so
a stale snapshot cannot resurrect revoked identities or reassign retired names.

Use typed `thiserror` domain errors: invalid request, unauthorized, conflict,
expired/replayed, quota exceeded, dependency unavailable and internal failure.
Map control HTTP responses to a stable `{code, request_id, retryable}` envelope;
keep provider/DB details internal and sanitized. Use 400/401/403/409/410/429/503/500
consistently and Retry-After for retryable throttling/unavailability. Do not expose
whether a foreign installation exists. Never log opaque request bodies via Debug.

Retry only transient reads and idempotent reconciled mutations with bounded
backoff/jitter. After ambiguous writes, query operation state before retrying.
Do not retry authorization failures, replay, ownership conflicts or blind streams.
Use Result in request/tasks, no unwrap/expect on external input; supervise spawned
tasks, propagate cancellation and drain on SIGTERM. Fail startup for invalid
configuration, incompatible DB schema or missing required credentials. Libraries
return typed errors; executable boundaries add safe context and log once.

Use tracing spans for API request, DNS job, tunnel lifecycle and certificate
reconciliation, with structured JSON via tracing-subscriber in production and
readable development logs. Include service/version, random request/operation ID,
state transition, duration and error code. Use `#[instrument(skip_all)]` plus
explicit safe fields; bridge legacy log events once. No secrets, auth headers,
cert/key files, TXT tokens, Browser bytes, full URLs or wallet identifiers.
Routine telemetry excludes installation IDs/hostnames/IPs; restricted security
audit may retain the identifiers necessary for attribution with documented
retention/access controls. Rate-limit/summarize repeated rejection logs.

Expose private Prometheus metrics and liveness/readiness endpoints. Measure live
streams, bytes, buffer budget, rejected admissions, reconnects, DNS job lag/errors,
lease expiry, certificate expiry and CT feed/alert lag. Labels are bounded enums,
not hostnames, IDs, IPs or error messages. Optional OTLP export may be added behind
a feature/config switch; its failure must not stall traffic. Keep audit durability
separate from best-effort sampled diagnostic logs; fail privileged mutations when
their transactional audit cannot persist.

## Build, delivery and acceptance

Start with Linux production services and macOS/Linux development support. Provide
reproducible release builds, non-root runtime users, graceful draining, separate
DNS/data-plane credentials, private admin/metrics networking, and reviewed infra
for zone delegation, ingress placement, PostgreSQL backups, service identities
and alerts. Credentials come from restricted files or workload identities, never
CLI arguments, checked-in config or logs. Supply safe example configuration and
no-secret local fixtures. No cloud/DNS changes run as a side effect of tests.

Implementation slices:

1. Workspace/toolchain/dependency lock, config validation, tracing/errors, protocol
   types and CI; architecture/wire-format decisions and resource-limit fixtures.
2. PostgreSQL schema, idempotent allocation/tombstones and outbox; test DNS adapter.
3. Admin enrollment/scoped credential issuance and DNS reconciliation;
   authoritative/recursive A/AAAA/CAA/TXT tests and staging issuance.
4. Gateway ClientHello parser, leases, HTTP/2 control/CONNECT streams and Broker
   client; adversarial routing and resource tests before public ingress.
5. Certificate/CT inventory workers, operational dashboards, incident/restore
   drills and deployment packaging; Broker cert lifecycle integration.
6. Real triad acceptance: provision a random origin, enroll remote/local passkeys,
   complete remote approval separately from execution, disable/re-enable without
   hostname loss, and prove outage/failure behavior at exact repository commits.

CI: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked
-- -D warnings`, `cargo test --workspace --locked`, dependency policy/advisories,
protocol compatibility tests and release builds. Add deterministic fault injection
for DB/provider timeouts, ambiguous writes, concurrent TXT cleanup, admin rotation,
lease replacement, restore and shutdown. Fuzz ClientHello/control framing and
property-test ownership/capacity invariants. Test that relay cannot read/modify
Browser plaintext or reach authority endpoints. Run a load/soak test proving
bounded memory and fair admission before release. Keep public DNS/CA drills
explicitly opt-in with disposable installations and reviewed credentials.

Before production, record the DNS provider/zone/delegation and deployment account,
bootstrap admission limits, wire/authentication format, exact dependency inventory,
CT ingestion source, audit retention, lease TTL and tested capacity. These are
assigned engineering/operations deliverables, not grounds to expand v1 product
scope. No service is ready merely because its HTTP health endpoint responds.
