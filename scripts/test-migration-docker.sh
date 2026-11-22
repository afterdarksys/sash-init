#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
docker build -f tests/migration/Dockerfile -t sahinit-migration-test .
docker run --rm --init --network none sahinit-migration-test
