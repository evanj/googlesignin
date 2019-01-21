#!/bin/bash
# Runs checks on CircleCI

set -euf -o pipefail

go test ./...

# go test only checks some vet warnings; check all
go vet ./...
golint ./...

diff -u <(echo -n) <(gofmt -d .)
