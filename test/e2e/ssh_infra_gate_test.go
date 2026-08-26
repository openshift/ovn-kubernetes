// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"os"
	"testing"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider"
)

// TestSSHInfraProviderGate is an opt-in guardrail that exercises test/e2e's
// TestMain provider selection (OVN_TEST_INFRA_PROVIDER=ssh), deployment-config
// selection, and the active provider's external-container surface after KinD is
// up. It is narrower than a conformance shard but broader than the package-level
// TestSSHProviderSmoke, which bypasses TestMain.
func TestSSHInfraProviderGate(t *testing.T) {
	if os.Getenv("OVN_TEST_SSH_GATE") != "1" {
		t.Skip("set OVN_TEST_SSH_GATE=1 with OVN_TEST_INFRA_PROVIDER=ssh and SSH env vars to run")
	}
	if infraprovider.Get().Name() != "ssh" {
		t.Fatalf("infra provider name = %q, want ssh", infraprovider.Get().Name())
	}
	nets, err := infraprovider.Get().ListNetworks()
	if err != nil {
		t.Fatalf("ListNetworks: %v", err)
	}
	if len(nets) == 0 {
		t.Fatalf("expected at least one container network, got %v", nets)
	}
	primary, err := infraprovider.Get().PrimaryNetwork()
	if err != nil {
		t.Fatalf("PrimaryNetwork: %v", err)
	}
	t.Logf("ssh infra gate ok: networks=%v primary=%q", nets, primary.Name())
}
