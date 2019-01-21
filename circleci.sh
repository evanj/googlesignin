#!/bin/bash
# Runs checks on CircleCI

set -euf -o pipefail

# Get dependencies: TODO: Use dep or modules
go get ./...

go test ./...

# go test only checks some vet warnings; check all
go vet ./...

go get -u golang.org/x/lint/golint
golint ./...

diff -u <(echo -n) <(gofmt -d .)
