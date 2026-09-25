#!/bin/bash
set -e

HERE=$(dirname "$(readlink --canonicalize "${BASH_SOURCE[0]}")")
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

"${HERE}"/check-go-mod-consistency.sh

echo "Adding vendor files to tests extension"
# FIXME: find a possibility to share go mod for openshift and test/e2e.
# Load the vendor directory at test time for now to limit repo size at the cost
# of no offline or isolated builds.
go mod vendor
echo "Building OVN-Kubernetes tests extension binary"
go build -v \
    -o "${OUTPUT}" \
    -mod=vendor \
    "$ROOT/cmd/ovn-kubernetes-tests-ext/"
