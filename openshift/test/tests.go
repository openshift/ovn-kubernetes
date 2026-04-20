package test

// This list contains separate lists of informing and blocking tests. Tests not
// on either of these lists do not run. To graduate a test from informing to
// blocking:
//  1. Remove the tests from InformingTests list and add it to the BlockingTests list
//  2. Rebuild: ./hack/build-tests-ext.sh
//  3. Verify: ./bin/ovn-kubernetes-tests-ext list tests | jq -r '.[] | select(.name == "test name here") | .lifecycle'
//
// Used by: openshift/cmd/ovn-kubernetes-tests-ext/main.go

// InformingTests lists tests that generally pass but are not considered stable
// and should not block CI jobs if they fail.
var InformingTests = []string{}

// BlockingTests lists tests that are considered stable and should block CI jobs
// if they fail.
var BlockingTests = []string{}
