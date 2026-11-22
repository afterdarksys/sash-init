#!/bin/sh
set -eu
cd "$(dirname "$0")"
out=$(gofmt -l .)
if [ -n "$out" ]; then echo "$out" >&2; exit 1; fi
go test -race ./...
go vet ./...
for pkg in ./internal/sandbox ./internal/supervise ./internal/bootpolicy; do
  bin=$(mktemp /tmp/sahinit-test.XXXXXX)
  GOOS=linux go test -c -o "$bin" "$pkg"
  rm -f "$bin"
done
