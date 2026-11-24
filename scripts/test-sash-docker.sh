#!/bin/sh
# Runs the sash service end-to-end tests: builds a Linux sash binary from the
# sash repository (branch feat/init-phase1; SASH_SRC, default ../sash-initp1,
# mounted read-only) and runs the supervise tests that drive it, as root with
# a private writable cgroup2. Extra arguments go to go test.
set -eu
cd "$(dirname "$0")/.."
src=$(cd "${SASH_SRC:-../sash-initp1}" && pwd)
docker run --rm --init --privileged --cgroupns=private \
  -v "$PWD":/src -v "$src":/sash:ro -w /src \
  -v sahinit-gomod:/go/pkg/mod -e GOFLAGS=-buildvcs=false \
  golang:1.26-bookworm sh -c '
    set -eu
    (cd /sash && go build -o /usr/local/bin/sash-e2e ./cmd/sash)
    SAHINIT_SASH_BIN=/usr/local/bin/sash-e2e go test -race -count=1 -run Sash "$@" ./internal/supervise/
  ' sh "$@"
