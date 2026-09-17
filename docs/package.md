# Relay Linux service package

`scripts/package-release.sh` builds locked release binaries and a sorted,
timestamped archive containing five executables, systemd units, example
environment files, a control-plane HAProxy route, and role policy examples.
CI builds this package; publishing and installing it are separate operations.
The unit files are templates, not an automatic installer. Validate the archive
checksum, substitute the assigned network addresses and hosted zone, then
review every permission before installation.

The CI fuzz smoke job exercises the gateway's maintained rustls ClientHello
parser and the relay's bounded control-frame decoder with seeded and mutated
inputs. For a longer local run, install `cargo-fuzz` 0.13.2 and run
`cargo +nightly fuzz run client_hello` and
`cargo +nightly fuzz run control_frames`. The nightly toolchain is test-only;
production crates build on the pinned stable toolchain. Gateway proptests
check random per-source/global admission sequences and ticket owner tuple
mutations. The included corpus seeds are fixed protocol fixtures, not secrets.

Use a dedicated, non-root Unix user and matching PostgreSQL peer role for each
of `bloom-relay-gateway`, `bloom-relay-api`, `bloom-relay-dns-serving`,
`bloom-relay-dns-challenge`, and `bloom-relay-ct`. Run
`bloom-relay-migrate` once as the schema owner before any service; runtime
processes only validate the exact migration set and need no DDL privileges.
Apply `packaging/postgres/runtime-grants.sql.example` as the schema owner
after selecting the production database name. Test each role's allowed and
denied operations under `SET ROLE` during staging acceptance. PostgreSQL peer
authentication and its Unix socket must map each service UID to its DB role;
the example URLs contain no DB password. The API has no AWS credential. Only
the serving and challenge workers receive distinct AWS credentials through
systemd `LoadCredential`; neither worker receives the receipt-signing key.

Create `/var/lib/bloom-relay/witness` on storage outside PostgreSQL snapshot
restores, owned by root and group `bloom-relay-witness`, mode `2770`.
Add the five service users to that group. Run migration with `umask 007` so
the revision and lock files are group-writable and world-inaccessible. Preserve
the directory and files on rollback and restore. Any service detecting a
missing or stale witness fails closed; a failed witness write is an incident,
not a reason to reset the marker. The shared witness group is trusted for
integrity, so grant membership only to these processes and the operator.

The first topology uses a dedicated public IP for Browser ingress and a
different control IP for `relay-control.bloom.directory`. Gateway ingress
binds its dedicated IP on port 443, preserving Browser source IP for the
gateway's admission quota. HAProxy terminates the unrelated outer control
TLS on the control IP and forwards `/v1/tunnel` and CONNECT to the gateway's
loopback HTTP/2 listener; other control requests go to the API's loopback TLS
listener. `packaging/haproxy/relay-control.cfg.example` shows the route.
Validate the HAProxy configuration and real HTTP/2 CONNECT behavior with the
chosen version in staging. Do not proxy Browser ingress without preserving a
trusted source-IP signal. Control certificate/key copies are accessible only
to gateway, API and HAProxy through their service credentials. Browser
certificate keys remain only in Broker.

The Route 53 serving role may list the delegated zone and change only
A/AAAA/CAA; the DNS-01 role may list the zone and change only TXT at
`_acme-challenge.*.relay.bloom.directory`. The reviewed policy examples use
Route 53's record-name, type, action and hosted-zone conditions. Replace the
zone ID and validate both allowed and denied calls with the real identity.
The worker's typed outbox scope and provider methods add an exact assigned
hostname check. The API and gateway must have no Route 53 permission.

Each service has separate loopback HTTP health (`/health/live`,
`/health/ready`) and Prometheus listeners. Public control routes expose
neither. Scrape through a restricted local collector. Metrics contain only
bounded service labels and aggregate counters/gauges for ingress admission,
live tunnel/stream counts, byte volume, DNS jobs, CT feed lag, and certificate
expiry. Configure alert thresholds and dashboards before production.

Start the API, both DNS workers, CT monitor, gateway and control router only
after schema/witness validation and protected credentials are in place.
Readiness is an initial process check; live external HTTPS, public DNS,
certificate validity, and CT alert delivery still need independent rollout
checks. On SIGTERM, the gateway stops admission and drains existing connections
for up to 30 seconds, API asks axum-server for a 30-second graceful stop,
and workers stop between jobs/ticks. The DNS outbox is replay-safe after an
interrupted job. To roll back a binary, stop services, keep the witness and
database schema intact, and use only a binary compatible with the current
wire/schema version. Database restore requires external audit and certificate
inventory comparison before services restart.
