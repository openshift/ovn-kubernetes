// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package infraprovider

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	ocpdeploymentconfig "github.com/ovn-kubernetes/ovn-kubernetes/openshift/test/deploymentconfig"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/images"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/container"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/container/network"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/testcontext"
)

// TestMain sets the OpenShift deployment config as main() does, without
// cluster access: images.AgnHost() reads it.
func TestMain(m *testing.M) {
	deploymentconfig.Set(ocpdeploymentconfig.New(nil))
	os.Exit(m.Run())
}

// TestNofloodUpstreamSpecContract fails when the upstream spec no longer
// creates its external containers with the name format the matcher expects
// on PrimaryNetwork(): update its entry in isolatedContainerNames in that case.
// Without it, a rename would put the containers back on host networking and
// the specs would fail on a lane with unexplained MAC mismatches.
func TestNofloodUpstreamSpecContract(t *testing.T) {
	src, err := os.ReadFile("../../../test/e2e/network_segmentation_noflood.go")
	if err != nil {
		t.Fatalf("cannot read the upstream spec: %v", err)
	}
	format := nofloodContainerPrefix + "%d-%s"
	for _, want := range []string{`"` + format + `"`, "PrimaryNetwork()"} {
		if !strings.Contains(string(src), want) {
			t.Fatalf("the upstream spec changed: %q not found in network_segmentation_noflood.go, update the no-flood entry in isolatedContainerNames", want)
		}
	}
	for _, name := range []string{fmt.Sprintf(format, 0, "abcde"), fmt.Sprintf(format, 1, "abcde")} {
		if !needsIsolation(name) {
			t.Fatalf("matcher does not accept %q", name)
		}
	}
	for _, name := range []string{"noflood-ext-12", "x-noflood-ext-0-b"} {
		if needsIsolation(name) {
			t.Fatalf("matcher accepts %q", name)
		}
	}
}

// failingRunner fails every hypervisor command, so each operation shows
// whether it reached the base provider (an error) or was short-cut.
type failingRunner struct{}

func (failingRunner) Run(string, ...string) (string, error) { return "", errors.New("no hypervisor") }

// TestBaremetalProviderMatchesBaseWithoutFixture checks that the baremetal
// context provider, now used even without a secondary network, behaves like
// the base provider there for the operations it can short-cut and for
// non-isolated primary containers. (DeleteNetwork is left out: the engine
// retries a failing delete for 10s, and without the network both return nil.)
func TestBaremetalProviderMatchesBaseWithoutFixture(t *testing.T) {
	secondary := &network.ContainerEngineNetwork{NetName: bmSecondaryNetworkName}
	ops := map[string]func(p api.ExternalContainerContextProvider) (interface{}, error){
		"CreateNetwork secondarynetwork": func(p api.ExternalContainerContextProvider) (interface{}, error) {
			return p.CreateNetwork(bmSecondaryNetworkName, bmSecondaryIPv4Subnet)
		},
		"AttachNetwork secondarynetwork": func(p api.ExternalContainerContextProvider) (interface{}, error) {
			return p.AttachNetwork(secondary, "worker-0")
		},
		"DetachNetwork secondarynetwork": func(p api.ExternalContainerContextProvider) (interface{}, error) {
			return nil, p.DetachNetwork(secondary, "worker-0")
		},
		"CreateExternalContainer secondarynetwork": func(p api.ExternalContainerContextProvider) (interface{}, error) {
			return p.CreateExternalContainer(api.ExternalContainer{Name: "eip-sec", Image: images.AgnHost(), Network: secondary})
		},
		"CreateExternalContainer primary": func(p api.ExternalContainerContextProvider) (interface{}, error) {
			return p.CreateExternalContainer(api.ExternalContainer{Name: "eip-host", Image: images.AgnHost(),
				Network: &network.ContainerEngineNetwork{NetName: bmPrimaryNetworkName}})
		},
	}
	base := &baseInfra{runner: failingRunner{}, engine: container.NewEngine("podman", failingRunner{}),
		primaryNetworkName: bmPrimaryNetworkName, hostNetworkInfo: &api.NetworkInterface{IPv4: "192.168.111.1"},
		externalContainers: map[string]api.ExternalContainer{}}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			ctx := &testcontext.TestContext{}
			gotV, gotErr := op((&baremetalInfra{base: base}).GetExternalContainerContextProvider(ctx))
			wantV, wantErr := op(&baseContextProvider{parent: base, engine: base.engine.WithTestContext(ctx)})
			if got, want := fmt.Sprintf("%v, %v", gotV, gotErr), fmt.Sprintf("%v, %v", wantV, wantErr); got != want {
				t.Fatalf("baremetal provider differs from the base provider:\n got %s\nwant %s", got, want)
			}
		})
	}
}
