#!/bin/bash
# Continuous integration checks

set -x -euf -o pipefail

go test -race -count=10 ./...

# go test only checks some vet warnings; check all
go vet ./...

# cd /tmp to not change go.mod/go.sum ; TODO: Use tools.go:
# https://github.com/golang/go/wiki/Modules#how-can-i-track-tool-dependencies-for-a-module
(cd /tmp && go get golang.org/x/tools/cmd/goimports golang.org/x/lint/golint honnef.co/go/tools/cmd/staticcheck)
golint --set_exit_status ./...
staticcheck --checks=all ./...

# require that we use goimports and go mod tidy. TODO: there must be an easier way?
go list ./... | sed 's|github.com/evanj/googlesignin|.|' | xargs goimports -w
go mod tidy
CHANGED=$(git status --porcelain --untracked-files=no)
if [ -n "${CHANGED}" ]; then
    echo "ERROR files were changed:" > /dev/stderr
    echo "$CHANGED" > /dev/stderr
    exit 10
fi
