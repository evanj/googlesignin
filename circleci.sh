#!/bin/bash
# Runs checks on CircleCI

set -euf -o pipefail

# Get dependencies: TODO: Use dep or modules
go test -mod=readonly -race ./...

# go test only checks some vet warnings; check all
go vet -mod=readonly ./...

go get -mod=readonly golang.org/x/lint/golint
golint --set_exit_status ./...

diff -u <(echo -n) <(gofmt -d .)

# require that we use go mod tidy. TODO: there must be as easier way
go mod tidy
CHANGED=$(git status --porcelain --untracked-files=no)
if [ -n "${CHANGED}" ]; then
    echo "ERROR files were changed:" > /dev/stderr
    echo "$CHANGED" > /dev/stderr
    exit 10
fi
