#!/bin/sh
# Certbot deploy hook. Control transport only; Broker owns ceremony TLS.
set -eu
[ "$(id -u)" = 0 ] || exit 1
lineage=/etc/letsencrypt/live/relay-control.bloom.directory
[ "${RENEWED_LINEAGE:-$lineage}" = "$lineage" ] || exit 0
root=/etc/bloom-relay
umask 077
install -d -m 0700 "$root/tls"
exec 9> "$root/tls/renew.lock"
flock -x 9
stage=$(mktemp -d "$root/tls/release.XXXXXXXX")
cleanup() {
  rm -f "$root/tls/current.new.$$"
  if [ "$(readlink "$root/tls/current" || true)" != "$stage" ]; then rm -rf "$stage"; fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
install -m 0600 "$lineage/fullchain.pem" "$stage/fullchain.pem"
install -m 0600 "$lineage/privkey.pem" "$stage/privkey.pem"
openssl x509 -in "$stage/fullchain.pem" -noout -checkhost relay-control.bloom.directory
openssl x509 -in "$stage/fullchain.pem" -noout -checkend 86400
openssl verify -purpose sslserver -verify_hostname relay-control.bloom.directory \
  -CAfile /etc/ssl/certs/ca-certificates.crt -untrusted "$stage/fullchain.pem" "$stage/fullchain.pem"
openssl x509 -in "$stage/fullchain.pem" -pubkey -noout > "$stage/cert-public.pem"
openssl pkey -in "$stage/privkey.pem" -pubout > "$stage/key-public.pem"
cmp "$stage/cert-public.pem" "$stage/key-public.pem"
rm "$stage/cert-public.pem" "$stage/key-public.pem"
cat "$stage/fullchain.pem" "$stage/privkey.pem" > "$stage/haproxy.pem"
# Publish the complete certificate/key generation through one atomic symlink.
ln -s "$stage" "$root/tls/current.new.$$"
mv -Tf "$root/tls/current.new.$$" "$root/tls/current"
# systemd credentials are refreshed only when the processes restart.
status=0
systemctl try-restart bloom-relay-api.service bloom-relay-gateway.service || status=1
if systemctl is-active --quiet haproxy.service; then
  if haproxy -c -f /etc/haproxy/haproxy.cfg; then
    systemctl reload haproxy.service || status=1
  else
    status=1
  fi
fi
exit "$status"
