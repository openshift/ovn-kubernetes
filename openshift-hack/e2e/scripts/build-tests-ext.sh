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

${HERE}/check-go-mod-consistency.sh

echo "Adding vendor files to tests extension"
# issue: we do not have a go mod in a subdirectory, therefore openshift-hack
# must have its own go mod and therefore vendor folder. This isn't ideal as now
# we must maintain a go mod in go-controller and within the openshift-hack.
# FIXME: move go mod from go-controller to repo root and share the go mod.
# Load the vendor directory at test time for now to limit repo size at the cost
# of no offline or isolated builds.
go mod vendor
echo "Building OVN-Kubernetes tests extension binary"
go build -v \
    -o "${OUTPUT}" \
    -mod=vendor \
    "$ROOT/cmd/ovnk-tests-ext/"
