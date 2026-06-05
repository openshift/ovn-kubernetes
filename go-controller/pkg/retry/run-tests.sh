#!/bin/bash
# OVN-Kubernetes retry package requires linux (OVS metrics have //go:build linux).
# On macOS, run tests in a container via podman.
#
# Usage:
#   ./run-tests.sh                          # run all retry tests
#   ./run-tests.sh TestFailedAttempts       # run matching tests only

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
RUN_FLAG=""
if [ -n "$1" ]; then
    RUN_FLAG="-run $1"
fi

podman run --rm \
    -v "$REPO_ROOT:/workspace:Z" \
    -w /workspace/go-controller \
    golang:1.25 \
    go test ./pkg/retry/ $RUN_FLAG -v -count=1
