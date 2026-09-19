#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT
# The HAProxy image runs as a non-root user and must traverse the temporary
# bind mount during syntax validation.
chmod 0755 "$fixture"

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$fixture/key.pem" -out "$fixture/ca.pem" -days 1 \
  -subj /CN=relay-control.bloom.directory >/dev/null 2>&1
cat "$fixture/ca.pem" "$fixture/key.pem" > "$fixture/control.pem"
chmod 0644 "$fixture/control.pem" "$fixture/ca.pem"
sed -e 's/CONTROL_IP/127.0.0.2/' \
  -e 's@/etc/bloom-relay/control-haproxy.pem@/fixture/control.pem@' \
  -e 's@/etc/ssl/certs/ca-certificates.crt@/fixture/ca.pem@g' \
  "$repo_dir/packaging/haproxy/relay-control.cfg.example" > "$fixture/relay.cfg"
docker run --rm -v "$fixture:/fixture:ro" haproxy:3.2-alpine \
  haproxy -c -f /fixture/relay.cfg

for policy in "$repo_dir"/packaging/iam/*.json.example; do
  python3 -m json.tool "$policy" >/dev/null
done
printf '%s\n' 'Package template syntax passed.'
