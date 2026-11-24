#!/bin/sh
# Runs the whole Go suite on Linux as root in a private cgroup namespace,
# inside the boot image's build stage. That stage also builds sash, so it
# needs the sash repository as the named build context "sash": SASH_SRC, or
# ../sash-initp1 by default (read-only; nothing there is changed).
set -eu
cd "$(dirname "$0")/.."
src=${SASH_SRC:-../sash-initp1}
if [ ! -f "$src/go.mod" ]; then
  echo "test-linux.sh: no sash repository at $src; set SASH_SRC" >&2
  exit 2
fi
src=$(cd "$src" && pwd)
docker build --target build --build-context sash="$src" -f tests/boot/Dockerfile -t sahinit-linux-test .
# The cgroup tests refuse the real host hierarchy; Docker supplies a private
# cgroup namespace. Privilege is needed for writable nested cgroups/Landlock.
docker run --rm --init --privileged --cgroupns=private --network none sahinit-linux-test go test -race -timeout 180s ./...
