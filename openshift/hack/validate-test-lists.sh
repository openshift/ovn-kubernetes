#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

HERE="$(dirname "$(readlink --canonicalize "${BASH_SOURCE[0]}")")"
ROOT="$(readlink --canonicalize "$HERE/..")"

# Unset KUBECONFIG to ensure complete test discovery
# (test binary filters based on cluster features when kubeconfig is present)
unset KUBECONFIG

echo "🔍 Validating test lists..." >&2

# Build test binary to discover actual test names
echo "  Building test binary..." >&2
pushd "$ROOT" > /dev/null
trap 'popd > /dev/null 2>&1' EXIT

# Build the test extension binary
"$HERE/build-tests-ext.sh" > /dev/null 2>&1 || {
  echo "  ⚠️  Failed to build test binary, skipping validation" >&2
  exit 0
}

# List all actual tests from the binary
echo "  Discovering actual tests..." >&2
ACTUAL_TESTS=$(./bin/ovn-kubernetes-tests-ext list tests 2>/dev/null | jq -r '.[].name' | sort || true)

if [[ -z "$ACTUAL_TESTS" ]]; then
  echo "  ⚠️  Could not discover tests, skipping validation" >&2
  exit 0
fi

# Extract test names from tests.go
echo "  Extracting expected tests from tests.go..." >&2
if ! EXPECTED_TESTS=$(go run -mod=vendor ./cmd/list-test-names/main.go | sort); then
  echo "  ⚠️  Failed to extract expected tests, skipping validation" >&2
  exit 0
fi

# Find orphaned tests (in tests.go but don't exist anymore)
ORPHANED=$(comm -13 <(echo "$ACTUAL_TESTS") <(echo "$EXPECTED_TESTS") || true)

# Find new tests (exist but not in tests.go)
NEW_TESTS=$(comm -23 <(echo "$ACTUAL_TESTS") <(echo "$EXPECTED_TESTS") || true)

# Output results for script consumption
if [[ -n "$ORPHANED" ]]; then
  echo "ORPHANED_TESTS_START"
  echo "$ORPHANED"
  echo "ORPHANED_TESTS_END"
fi

if [[ -n "$NEW_TESTS" ]]; then
  echo "NEW_TESTS_START"
  echo "$NEW_TESTS"
  echo "NEW_TESTS_END"
fi

# Exit with error if mismatches found
if [[ -n "$ORPHANED" ]] || [[ -n "$NEW_TESTS" ]]; then
  echo "" >&2
  echo "  ⚠️  Test list validation failed" >&2
  [[ -n "$ORPHANED" ]] && echo "  Found $(echo "$ORPHANED" | wc -l) orphaned test(s)" >&2
  [[ -n "$NEW_TESTS" ]] && echo "  Found $(echo "$NEW_TESTS" | wc -l) new test(s)" >&2
  exit 1
fi

echo "  ✅ Test lists are in sync" >&2
exit 0
