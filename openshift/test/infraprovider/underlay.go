package infraprovider

import (
	"context"
	"fmt"

	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/utils/ptr"

	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/test/infraprovider/internal/nmstate"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
)

// SetupUnderlay wires a localnet logical network to an OVS bridge on every node
// by configuring the OVN bridge-mappings. On OpenShift the localnet is mapped to
// the shared external bridge (br-ex): no dedicated bridge or physical NIC is
// created, so only the bridge-mapping is added alongside the default mapping.
// A cleanup function restores the default mapping when the test context ends.
func (o *contextOpenshift) SetupUnderlay(f *framework.Framework, underlay api.Underlay) error {
	if underlay.LogicalNetworkName == "" {
		return fmt.Errorf("underlay logical network name must be set")
	}
	if underlay.BridgeName == "" {
		underlay.BridgeName = deploymentconfig.Get().ExternalBridgeName()
	}
	if underlay.BridgeName != deploymentconfig.Get().ExternalBridgeName() {
		return fmt.Errorf("openshift underlay only supports the external bridge %q, got %q",
			deploymentconfig.Get().ExternalBridgeName(), underlay.BridgeName)
	}

	desiredState := nmstate.Configuration{
		OVN: &nmstate.OVN{
			BridgeMapping: []nmstate.OVNBridgeMapping{{
				Localnet: new(underlay.LogicalNetworkName),
				Bridge:   new(underlay.BridgeName),
				State:    new(nmstate.OVNBridgeMappingStatePresent),
			}},
		},
	}

	nncpName := f.UniqueName

	cli, err := nmstate.Client(f.ClientConfig())
	if err != nil {
		return fmt.Errorf("failed to initialize nmstate client for openshift underlay setup: %w", err)
	}

	o.AddCleanUpFn(func() error {
		framework.Logf("Deleting nncp %q", nncpName)
		return nmstate.DeleteNNCP(context.Background(), cli, nncpName)
	})

	o.AddCleanUpFn(func() error {
		desiredState.OVN.BridgeMapping[0].State = new(nmstate.OVNBridgeMappingStateAbsent)
		framework.Logf("Deleting ovn bridge mapping %q at ovs-bridge %q with nncp %q",
			ptr.Deref(desiredState.OVN.BridgeMapping[0].Localnet, ""),
			ptr.Deref(desiredState.OVN.BridgeMapping[0].Bridge, ""),
			nncpName)
		if err := nmstate.UpdateNNCP(context.Background(), cli, nncpName, desiredState); err != nil {
			return fmt.Errorf("failed to remove bridge mapping for logical network %q to bridge %q during cleanup: %w",
				underlay.LogicalNetworkName, underlay.BridgeName, err)
		}
		return nil
	})
	framework.Logf("Deploying kubernetes-nmstate")
	if err := nmstate.Deploy(context.Background(), cli); err != nil {
		return err
	}

	framework.Logf("Adding ovn bridge mapping %q at ovs-bridge %q with nncp %q",
		ptr.Deref(desiredState.OVN.BridgeMapping[0].Localnet, ""),
		ptr.Deref(desiredState.OVN.BridgeMapping[0].Bridge, ""),
		nncpName)
	if err := nmstate.UpdateNNCP(context.Background(), cli, nncpName, desiredState); err != nil {
		return fmt.Errorf("failed to configure bridge mapping for logical network %q to bridge %q: %w",
			underlay.LogicalNetworkName, underlay.BridgeName, err)
	}
	return nil
}
