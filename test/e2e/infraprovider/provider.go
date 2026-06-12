// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package infraprovider

import (
	"errors"
	"os/exec"
	"strings"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	"k8s.io/kubernetes/test/e2e/framework"
)

// ErrExternalInfraUnavailable is returned when external container infrastructure is not available.
// This typically indicates the cluster is running on a cloud platform without bare-metal
// external container/network infrastructure support.
var ErrExternalInfraUnavailable = errors.New("external container infrastructure not available")

var infraProvider api.Provider

// Set infrastructure provider.
func Set(provider api.Provider) {
	infraProvider = provider
}

// Get infrastructure provider.
func Get() api.Provider {
	if infraProvider == nil {
		panic("infra provider not set")
	}
	return infraProvider
}

// IsKind returns true if cluster provider is KinD
func IsKind() bool {
	_, err := exec.LookPath("kubectl")
	if err != nil {
		framework.Logf("kubectl is not installed: %v", err)
		return false
	}
	currentCtx, err := exec.Command("kubectl", "config", "current-context").CombinedOutput()
	if err != nil {
		framework.Logf("unable to get current cluster context: %v", err)
		return false
	}
	if strings.Contains(string(currentCtx), "kind-ovn") {
		return true
	}
	return false
}
