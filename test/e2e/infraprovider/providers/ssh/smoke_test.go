// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package ssh

import (
	"os"
	"strings"
	"testing"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/testcontext"
)

// TestSSHProviderSmoke exercises the real provider against a live container
// daemon over SSH. It is OPT-IN: it runs only when OVN_TEST_SSH_SMOKE=1 and the
// OVN_TEST_SSH_* connection env vars are set (see ConfigFromEnv). It is skipped
// during ordinary `go test` so the package's unit tests stay hermetic.
//
// It requires: a reachable SSH host running the container runtime, a cluster
// whose primary network and a node are reachable via that daemon (e.g. a local
// kind cluster reached via ssh-to-localhost hitting the same docker daemon), and
// the agnhost image available on that daemon.
//
// Env knobs:
//
//	OVN_TEST_SSH_SMOKE=1                 enable the test
//	OVN_TEST_SSH_SMOKE_NODE=<name>       node/container to exec on (required)
//	OVN_TEST_SSH_SMOKE_IMAGE=<image>     external-container image
//	                                     (default registry.k8s.io/e2e-test-images/agnhost:2.45)
func TestSSHProviderSmoke(t *testing.T) {
	if os.Getenv("OVN_TEST_SSH_SMOKE") != "1" {
		t.Skip("set OVN_TEST_SSH_SMOKE=1 (plus OVN_TEST_SSH_* and OVN_TEST_SSH_SMOKE_NODE) to run the live smoke test")
	}
	nodeName := os.Getenv("OVN_TEST_SSH_SMOKE_NODE")
	if nodeName == "" {
		t.Fatal("OVN_TEST_SSH_SMOKE_NODE (a node/container name to exec on) is required")
	}
	image := os.Getenv("OVN_TEST_SSH_SMOKE_IMAGE")
	if image == "" {
		image = "registry.k8s.io/e2e-test-images/agnhost:2.45"
	}

	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Register Close first so it runs LAST: t.Cleanup is LIFO, and the external
	// container cleanup registered later must run first (deleting the container
	// over SSH while the client is still open) before Close tears the SSH client
	// down. Using a defer here would instead close the client before the t.Cleanup
	// container delete, forcing a reconnect that then leaks.
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	// 1) ListNetworks over SSH must see the cluster's primary network.
	nets, err := p.ListNetworks()
	if err != nil {
		t.Fatalf("ListNetworks: %v", err)
	}
	t.Logf("ListNetworks -> %v", nets)
	found := false
	for _, n := range nets {
		if n == cfg.PrimaryNetwork {
			found = true
		}
	}
	if !found {
		t.Fatalf("primary network %q not found in %v", cfg.PrimaryNetwork, nets)
	}

	// 2) GetNetwork/PrimaryNetwork parse `network inspect` over SSH.
	primary, err := p.PrimaryNetwork()
	if err != nil {
		t.Fatalf("PrimaryNetwork: %v", err)
	}
	v4, v6, err := primary.IPv4IPv6Subnets()
	if err != nil {
		t.Fatalf("PrimaryNetwork subnets: %v", err)
	}
	t.Logf("PrimaryNetwork %q subnets v4=%q v6=%q", primary.Name(), v4, v6)

	// 3) Node exec over SSH (docker exec <node> on the same daemon). The node's
	// hostname is not guaranteed to equal its runtime name, so assert only that
	// the command ran and produced output.
	out, err := p.ExecK8NodeCommand(nodeName, []string{"hostname"})
	if err != nil {
		t.Fatalf("ExecK8NodeCommand(%s): %v", nodeName, err)
	}
	if strings.TrimSpace(out) == "" {
		t.Fatalf("ExecK8NodeCommand(%s, hostname) returned no output", nodeName)
	}
	t.Logf("ExecK8NodeCommand(%s, hostname) -> %q", nodeName, strings.TrimSpace(out))

	// 4) Full external-container lifecycle over SSH: create on the primary
	// network, exec inside it, then cleanup deletes it.
	tc := &testcontext.TestContext{}
	// Register cleanup immediately so the external container is removed on every
	// exit path, including a t.Fatalf after a successful create (e.g. if the exec
	// below fails). Otherwise a leaked container makes the next run fail on the
	// duplicate name. CleanUp is a no-op until CreateExternalContainer registers
	// the container delete on tc.
	t.Cleanup(func() {
		if err := tc.CleanUp(); err != nil {
			t.Errorf("CleanUp (external container delete): %v", err)
		}
	})
	cctx := p.remote.NewExternalContainerContext(tc)
	ec := api.ExternalContainer{
		Name:    "ovn-ssh-smoke-ext",
		Image:   image,
		Network: primary,
		CmdArgs: []string{"pause"}, // agnhost stays up; avoids the images.AgnHost() default path
	}
	created, err := cctx.CreateExternalContainer(ec)
	if err != nil {
		t.Fatalf("CreateExternalContainer: %v", err)
	}
	t.Logf("CreateExternalContainer -> name=%s ipv4=%s ipv6=%s", created.Name, created.IPv4, created.IPv6)
	// Validate each configured address family so a dual-stack primary network is
	// actually exercised for both v4 and v6 (not just one).
	if v4 != "" && created.IPv4 == "" {
		t.Fatalf("external container got no IPv4 address on dual/v4 network")
	}
	if v6 != "" && created.IPv6 == "" {
		t.Fatalf("external container got no IPv6 address on dual/v6 network")
	}
	if v4 == "" && v6 == "" && created.IPv4 == "" && created.IPv6 == "" {
		t.Fatalf("external container got no IP")
	}
	exOut, err := p.ExecExternalContainerCommand(created, []string{"hostname"})
	if err != nil {
		t.Fatalf("ExecExternalContainerCommand: %v", err)
	}
	t.Logf("ExecExternalContainerCommand(hostname) -> %q", strings.TrimSpace(exOut))

	t.Log("smoke lifecycle ok; external container is deleted during cleanup")
}
