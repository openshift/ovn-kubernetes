package kubevirt

const (
	AllowPodBridgeNetworkLiveMigrationAnnotation = "kubevirt.io/allow-pod-bridge-network-live-migration"
	OriginalSwitchNameLabel                      = "k8s.ovn.org/original-switch-name"
	VMLabel                                      = "kubevirt.io/vm"
	MigrationTargetStartTimestampAnnotation      = "kubevirt.io/migration-target-start-timestamp"
	NodeNameLabel                                = "kubevirt.io/nodeName"
)

// NetworkInfo is the network information common to all the pods involve
// on the same vm
type NetworkInfo struct {
	// OriginalSwitchName is the switch name where the vm was created
	OriginalSwitchName string

	// Status is the OVN network annotations
	Status string
}
