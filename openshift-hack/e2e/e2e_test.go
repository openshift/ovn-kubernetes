package e2e

import (
	// import OVN-Kubernetes E2Es
	_ "github.com/ovn-org/ovn-kubernetes/test/e2e"

	// Ensure that logging flags are part of the command line.
	_ "k8s.io/component-base/logs/testinit"
)

//go:generate go run -mod vendor ./cmd/annotate -- ./pkg/generated/zz_generated.annotations.go
