#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"
if [[ "$(uname -s)" != Linux ]]; then
  printf '%s\n' 'Release packages are built on Linux.' >&2
  exit 1
fi

commit="$(git rev-parse HEAD)"
epoch="$(git show -s --format=%ct HEAD)"
arch="$(uname -m)"
name="bloom-relay-${commit:0:12}-linux-${arch}"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
target="${CARGO_TARGET_DIR:-$repo_dir/target}"

cargo build --release --locked --bins
mkdir -p "$stage/$name/bin" "$stage/$name/packaging" "$repo_dir/dist"
for binary in bloom-relay bloom-relay-control bloom-relay-ct bloom-relay-migrate bloom-relay-relocate; do
  install -m 0755 "$target/release/$binary" "$stage/$name/bin/$binary"
done
cp -R packaging/. "$stage/$name/packaging/"
cp docs/operations.md docs/package.md docs/wire.md "$stage/$name/"
printf '%s\n' "$commit" > "$stage/$name/COMMIT"
tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
  -C "$stage" -czf "dist/$name.tar.gz" "$name"
sha256sum "dist/$name.tar.gz" > "dist/$name.tar.gz.sha256"
printf 'Created %s\n' "dist/$name.tar.gz"
