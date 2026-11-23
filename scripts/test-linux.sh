#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
docker build --target build -f tests/boot/Dockerfile -t sahinit-linux-test .
# The cgroup tests refuse the real host hierarchy; Docker supplies a private
# cgroup namespace. Privilege is needed for writable nested cgroups/Landlock.
docker run --rm --init --privileged --cgroupns=private --network none sahinit-linux-test go test -race -timeout 180s ./...
