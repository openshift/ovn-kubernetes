#!/bin/bash
set -e
# because we must manage the openshift go mod and also the go-controller go mod, we must ensure they are
# kept in sync to prevent version drift. Focus on the go version and k8 api only however all k8 deps must be kept in sync.
HERE=$(dirname "$(readlink --canonicalize "${BASH_SOURCE[0]}")")
REPO_ROOT=$(readlink --canonicalize "$HERE/../..")
GO_MOD_OVNK="$REPO_ROOT/go-controller/go.mod"
GO_MOD_OCP_HACK="$REPO_ROOT/openshift/go.mod"
echo "Checking go mods consistency.."
GO_VER_OVNK=$(grep "^go " "$GO_MOD_OVNK" | awk '{print $2}')
GO_VER_GO_MOD_OCP_HACK=$(grep "^go " "$GO_MOD_OCP_HACK" | awk '{print $2}')

K8_API_OVNK=$(grep "k8s.io/api " "$GO_MOD_OVNK" | head -1 | awk '{print $2}')
K8_API_OCP_HACK=$(grep "k8s.io/api " "$GO_MOD_OCP_HACK" | head -1 | awk '{print $2}')

if [ "$GO_VER_OVNK" != "$GO_VER_GO_MOD_OCP_HACK" ]; then
    echo "Go versions differ between OVN Kubernetes & OCP hack e2e: $GO_MOD_OVNK=$GO_VER_OVNK, $GO_MOD_OCP_HACK=$GO_VER_GO_MOD_OCP_HACK"
    exit 1
fi

if [ "$K8_API_OVNK" != "$K8_API_OCP_HACK" ]; then
    echo "k8s.io/api versions between OVN Kubernetes & OCP hack e2e: $GO_MOD_OVNK=$K8_API_OVNK, $GO_MOD_OCP_HACK=$K8_API_OCP_HACK"
    exit 1
fi
echo "Finished checking go mods consistency.."
exit 0
