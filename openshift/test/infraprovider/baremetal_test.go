package infraprovider

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/container"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/container/network"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/testcontext"
)

type recordingRunner struct {
	calls   [][]string
	failRun bool
}

func (r *recordingRunner) Run(command string, args ...string) (string, error) {
	r.calls = append(r.calls, append([]string{command}, args...))
	if len(args) > 0 && args[0] == "run" && r.failRun {
		return "", fmt.Errorf("container already exists")
	}
	if len(args) > 0 && args[0] == "ps" {
		// First query during cleanup finds the container; the query after rm does not.
		for _, call := range r.calls {
			if len(call) > 1 && call[1] == "rm" {
				return "", nil
			}
		}
		return "test-container", nil
	}
	return "", nil
}

func TestHostNetworkedContainerLifecycle(t *testing.T) {
	for _, failRun := range []bool{false, true} {
		t.Run(fmt.Sprintf("creationFails=%t", failRun), func(t *testing.T) {
			r := &recordingRunner{failRun: failRun}
			ctx := &testcontext.TestContext{}
			ci := &baremetalInfra{
				runner:               r,
				engine:               container.NewEngine("podman", r),
				machineNetwork:       &network.ContainerEngineNetwork{NetName: primaryNetworkName},
				machineNetworkGwInfo: &api.NetworkInterface{IPv4: "192.168.122.1", IPv6: "fd00::1"},
			}
			provider := ci.GetExternalContainerContextProvider(ctx)
			ec, err := provider.CreateExternalContainer(api.ExternalContainer{
				Name: "test-container", Image: "example.com/netshoot:test", Network: ci.machineNetwork,
				CmdArgs: []string{"sleep", "infinity"},
			})
			if failRun {
				if err == nil {
					t.Fatal("expected creation error")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if ec.Network.Name() != "host" || ec.IPv4 != "192.168.122.1" || ec.IPv6 != "fd00::1" {
					t.Fatalf("incorrect host network metadata: %+v", ec)
				}
			}
			wantRun := []string{"podman", "run", "-d", "--privileged", "--network", "host", "--name", "test-container", "example.com/netshoot:test", "sleep", "infinity"}
			if !reflect.DeepEqual(r.calls[0], wantRun) {
				t.Fatalf("unexpected invocation: %v", r.calls[0])
			}
			if err := ctx.CleanUp(); err != nil {
				t.Fatal(err)
			}
			removed := false
			for _, call := range r.calls {
				if reflect.DeepEqual(call, []string{"podman", "rm", "-f", "test-container"}) {
					removed = true
				}
			}
			if removed == failRun {
				t.Fatalf("cleanup removed=%t, creation failed=%t", removed, failRun)
			}
		})
	}
}
