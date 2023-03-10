package kubevirt

import (
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
)

const (
	OriginalSwitchNameLabel = types.OvnK8sPrefix + "/original-switch-name"
	OvnZoneExternalIDKey    = types.OvnK8sPrefix + "/zone"
	OvnRemoteZone           = "remote"
	OvnLocalZone            = "local"
)

// NetworkInfo is the network information common to all the pods belonging
// to the same vm
type NetworkInfo struct {
	// OriginalSwitchName is the switch name where the vm was created
	OriginalSwitchName string

	// Status is the ovn pod annotation related to the VM.
	Status string
}
