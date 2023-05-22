package kubevirt

import (
	kvv1 "kubevirt.io/api/core/v1"
)

const (
	AllowPodBridgeNetworkLiveMigrationAnnotation = kvv1.AllowPodBridgeNetworkLiveMigrationAnnotation
	OriginalSwitchNameLabel                      = "k8s.ovn.org/original-switch-name"
	VMLabel                                      = kvv1.VirtualMachineNameLabel
	MigrationTargetStartTimestampAnnotation      = kvv1.MigrationTargetReadyTimestamp
	NodeNameLabel                                = kvv1.NodeNameLabel
)

// NetworkInfo is the network information common to all the pods involve
// on the same vm
type NetworkInfo struct {
	// OriginalSwitchName is the switch name where the vm was created
	OriginalSwitchName string

	// Status is the OVN network annotations
	Status string
}
