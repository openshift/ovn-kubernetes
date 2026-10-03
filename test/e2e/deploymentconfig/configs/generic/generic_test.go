// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package generic

import (
	"testing"

	deploymentconfigapi "github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig/api"
)

func TestNewDoesNotPanic(t *testing.T) {
	cfg := New()
	if cfg.OVNKubernetesNamespace() != "ovn-kubernetes" {
		t.Fatalf("unexpected namespace %q", cfg.OVNKubernetesNamespace())
	}
	if cfg.ExternalBridgeName() != "breth0" {
		t.Fatalf("unexpected bridge %q", cfg.ExternalBridgeName())
	}
}

func TestL3UDNMultiSubnetDisabled(t *testing.T) {
	cfg := New()
	if cfg.IsConfigurationEnabled(deploymentconfigapi.L3UDNMultiSubnetConfig) {
		t.Fatal("generic deployment config should not enable L3UDNMultiSubnet")
	}
}
