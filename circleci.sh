#!/bin/bash
# Continuous integration checks

set -x -euf -o pipefail

go test -mod=readonly -race -count=10 ./...

# go test only checks some vet warnings; check all
go vet -mod=readonly ./...

# TODO: Use tools.go
(cd /tmp && go get golang.org/x/lint/golint)
golint --set_exit_status ./...

diff -u <(echo -n) <(gofmt -d .)

# only check in "go mod tidy" go.mod/go.sum
# TODO there must be an easier way?
cp go.sum go.sum.orig
cp go.mod go.mod.orig
go mod tidy
CHANGED=$(diff -u go.sum.orig go.sum && diff -u go.mod.orig go.mod)
if [ -n "${CHANGED}" ]; then
    echo "ERROR go mod tidy changed go.mod or go.sum:" > /dev/stderr
    echo "$CHANGED" > /dev/stderr
    exit 10
fi
