#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

HERE="$(dirname "$(readlink --canonicalize "$BASH_SOURCE")")"
ROOT="$(readlink --canonicalize "$HERE/..")"
# Update e2e test annotations that indicate openshift compatibility
pushd "$ROOT"
trap popd EXIT
go generate -mod=vendor "$ROOT/e2e_test.go"
