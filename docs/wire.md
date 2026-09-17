# Relay wire contract, version 1

All control requests use HTTPS to the fixed `relay-control.bloom.directory`
audience. The control endpoint has its own certificate. The Signer pins its
trust anchor and the Ed25519 relay receipt verification key separately.
Version mismatches fail closed. Broker's browser certificate is distinct and
never leaves Broker.

Allocation begins with a 60-second bootstrap nonce. Signer signs
`bloom-relay/control/v1\0 || JCS(AuthClaims)`, where JCS is RFC 8785 JSON
canonicalization. Claims contain version, installation ID (nil during
bootstrap), scope, generation, audience, operation ID, nonce, absolute
millisecond expiry, and SHA-256 of the JCS body. Signatures are unpadded
base64url Ed25519. The control service verifies scope, audience, body digest,
signature, deadline, and one-time nonce before mutation.

An allocation response is `AllocationReceipt`: allocation, operation ID,
admin-public-key SHA-256, issued time, and relay signature. The signature
covers `bloom-relay/allocation-receipt/v1\0 || JCS((allocation, operation_id,
admin_key_sha256, issued_at_ms))`. The Signer verifies the relay key, original
operation and admin key, exact hostname syntax, and five-minute age before it
uses the assigned surface. The assigned label has 128 bits of OS randomness,
base32 encoded as 26 lowercase characters. Hostnames are permanent even after
retirement.

The routine tunnel uses outbound TLS with HTTP/2 and a separately scoped
random bearer credential in an owner-only file. A successful
`POST /v1/tunnel` establishes the active installation lease. Each browser
connection gets an `Open` event on that stream, newline-delimited JSON
regardless of HTTP/2 DATA boundaries. The event carries the exact hostname,
installation lease generation, random single-use ticket, connection ID, and
ten-second absolute expiry. Broker opens one outbound CONNECT for the ticket.
The gateway accepts CONNECT only on the same authenticated HTTP/2 connection,
with matching authority, current generation and unexpired ticket. The
connected DATA streams carry opaque Browser TLS bytes.

The privileged administrator issues a 24-hour random bearer by sending only
its SHA-256 digest in a signed request. The receipt gives the exact database
generation and expiry. Broker renews with its current scoped bearer, a new
digest and a caller-persisted operation ID; retries with identical values are
idempotent for five minutes. The response includes the authoritative expiry.
Renewal revokes the old scoped bearer and immediately fences an old tunnel
lease. Broker writes the next token to an owner-only staging file before the
request, then atomically replaces the active file after the receipt. No admin
key is needed for routine renewal.

The gateway uses rustls's ClientHello acceptor only to extract exact SNI.
Every byte it reads is then forwarded unchanged. Browser TLS terminates at
Broker. No tunnel frame can choose a local destination; the Broker client
accepts only `127.0.0.1:18735`. A second tunnel for an installation advances
the generation and fences old routing.

Current coded limits: 16 KiB control messages, 64 KiB ClientHello in five
seconds, ten-second ticket/CONNECT setup, 128 streams per installation,
10,000 per gateway (further capped at 2,048 by the 256 MiB buffer budget),
16 KiB relay DATA chunks, 120-second idle and 30-minute
absolute stream lifetime, 15-second heartbeats and a 45-second lease/dead
peer threshold. Admission occurs before stream buffers are allocated.

The DNS adapter accepts only an assigned exact hostname in the delegated
`relay.bloom.directory` zone. It publishes explicit A/AAAA and exact CAA
records, with 300-second address TTL. A TXT lease derives the
`_acme-challenge.` name on the server. The control plane never accepts an
arbitrary DNS owner/type from Broker.
The scoped DNS-01 client has create, readiness and delete operations; only
the control service derives the record owner. Readiness requires exact TXT
observation through configured authoritative and recursive resolvers. Broker
reports public certificate metadata through the same scoped channel. A
privileged admin separately binds Broker's ACME account URI so CAA can name
the exact account before issuance.

CT consumption uses a reviewed authenticated HTTPS adapter that returns at
most 100 contiguous positions from a requested checkpoint. The relay records
the assigned hostname and SPKI SHA-256, compares it with Broker-reported
expected inventory, and persists unknown issuances for an independent HTTPS
alert sink. A successful empty batch refreshes feed health; 15 minutes
without a successful batch queues a separate lag alert. The sink accepts
idempotent `202` alerts keyed by stable source/alert ID. The adapter's trust
in CT log inclusion and its concrete provider remain deployment decisions.

Every durable identity/credential/DNS/CT security transition advances a
PostgreSQL revision and an external owner-only restore witness before an API
success response. `fs4` locks the witness path across processes and atomic
replacement prevents older writers from lowering it. Startup fails closed
if an established database lost its witness or is below its witness.

The protocol, admin client, and tunnel client packages declare Rust 1.85
compatibility for Signer and Broker. The server workspace uses 1.98.1. The
admin client is a separate package, so Signer does not pull tunnel code. Both
clients use ureq 3.4.2 with rustls for bounded HTTPS control/probing, avoiding
the downstream WebAssembly/JS dependency conflict from reqwest.
The gateway and tunnel client use maintained rustls, h2 and tokio primitives;
rustls's Acceptor reads ClientHello without terminating Browser TLS. Hickory
performs DNS observations, sqlx owns PostgreSQL transactions, and the AWS SDK
owns Route 53 signing/transport. Custom code is limited to Bloom's authority
policy, exact-owner DNS changes, ticket/generation fencing, bounded byte
bridging, idempotent state transitions and restore/CT evidence that these
libraries do not define for this protocol.
