# Deployed relay smoke probe

This is an opt-in, destructive probe for disposable production infrastructure. It
uses the maintained admin and Broker tunnel clients to enroll a fresh installation,
verify its signed receipt, issue scoped credentials, register a supplied real ACME
account URI, exercise a DNS-01 lease, route concurrent pinned synthetic TLS streams
through the public ingress, reconnect the tunnel, and retire the installation.

It creates no public certificate and proves no browser, passkey, wallet, Signer, or
public CA issuance behavior. The synthetic certificate is generated in memory for
the allocated hostname and trusted only by this process. The assigned hostname is
permanently tombstoned by retirement.

The public bootstrap operator allowlist must admit the machine running the probe.
Set every variable below; the two addresses are checked against the fixed deployed
topology before any network operation:

```sh
BLOOM_RELAY_DEPLOYED_SMOKE=1 \
BLOOM_RELAY_SMOKE_CONTROL_CA_FILE=/restricted/control-ca.pem \
BLOOM_RELAY_SMOKE_RECEIPT_PUBLIC_KEY_FILE=/restricted/receipt-public-key.hex \
BLOOM_RELAY_SMOKE_ACME_ACCOUNT_URI_FILE=/restricted/acme-account-uri \
BLOOM_RELAY_SMOKE_GATEWAY_ADDR=84.32.151.158:443 \
BLOOM_RELAY_SMOKE_INGRESS_ADDR=84.32.25.82:443 \
cargo run --manifest-path tools/deployed-smoke/Cargo.toml --locked
```

The tool fails if `127.0.0.1:18735` is occupied and never stops the occupying
service. Temporary bearer files are mode `0600` in a mode `0700` directory and are
removed on exit. Output contains only PASS steps, the public installation UUID, and
the assigned hostname. Run from this repository so the path dependencies select the
same reviewed client code as the deployed release.

The public receipt key and ACME account URI may instead be supplied directly as
`BLOOM_RELAY_SMOKE_RECEIPT_PUBLIC_KEY_HEX` and
`BLOOM_RELAY_SMOKE_ACME_ACCOUNT_URI`. Set exactly one source for each value.

After enrollment, SIGINT or SIGTERM cancels the probe and attempts signed
retirement before exit, preserving the normal DNS-cleanup outbox and permanent
tombstone. Check the retirement result and worker cleanup afterward. A forced
kill, process crash or ambiguous enrollment response cannot guarantee cleanup;
the ephemeral administrator key is intentionally not persisted.
