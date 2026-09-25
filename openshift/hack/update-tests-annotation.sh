#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

HERE="$(dirname "$(readlink --canonicalize "$BASH_SOURCE")")"
ROOT="$(readlink --canonicalize "$HERE/..")"

${HERE}/check-go-mod-consistency.sh

# Update e2e test annotations that indicate openshift compatibility
pushd "$ROOT"
trap popd EXIT
go generate -mod=vendor "$ROOT/test/e2e_test.go"
