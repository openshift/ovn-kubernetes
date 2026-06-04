package test

import (
	// import OVN-Kubernetes E2Es
	_ "github.com/ovn-kubernetes/ovn-kubernetes/test/e2e"

	// import OTP (OpenShift Tests Private) migration tests
	_ "github.com/ovn-kubernetes/ovn-kubernetes/openshift/test/otp"

	// Ensure that logging flags are part of the command line.
	_ "k8s.io/component-base/logs/testinit"
)

//go:generate go run -mod vendor ../cmd/annotate ./generated/zz_generated.annotations.go
