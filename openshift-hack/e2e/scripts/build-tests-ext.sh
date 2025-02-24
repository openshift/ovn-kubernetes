#!/bin/bash
set -e

HERE=$(dirname "$(readlink --canonicalize "$BASH_SOURCE")")
ROOT=$(readlink --canonicalize "$HERE/..")
OUTPUT="${ROOT}/bin"
mkdir -vp "$OUTPUT"
if [[ -z "$(command -v go)" ]]; then
    cat <<EOF
Can't find 'go' in PATH, please fix and retry.
See http://golang.org/doc/install for installation instructions.
EOF
    exit 2
fi
pushd "$ROOT"
trap popd EXIT
echo "Building OVN-Kubernetes tests extension binary"
go build -v \
    -o "${OUTPUT}" \
    -mod=vendor \
    "$ROOT/cmd/ovnk-tests-ext/"
