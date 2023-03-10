package kubevirt

import (
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	ktypes "k8s.io/apimachinery/pkg/types"
)

func ExtractVMFromExternalIDs(externalIDs map[string]string) *ktypes.NamespacedName {
	namespace, ok := externalIDs[string(libovsdbops.NamespaceIndex)]
	if !ok {
		return nil
	}
	vmName, ok := externalIDs[string(libovsdbops.VirtualMachineIndex)]
	if !ok {
		return nil
	}
	return &ktypes.NamespacedName{Namespace: namespace, Name: vmName}
}

// OwnsItAndIsOrphanOrWrongZone return true if kubevirt owns this this OVN NB
// resource by check if it has the VM name external id and also check if the
// expected ovn zone correspond with the one it was created on by checking
// OvnZoneExternalIDKey
func OwnsItAndIsOrphanOrWrongZone(externalIDs map[string]string, vms map[ktypes.NamespacedName]bool) bool {
	vm := ExtractVMFromExternalIDs(externalIDs)
	if vm == nil {
		return false // Not related to kubevirt
	}
	if vm.Name == AllVMs {
		return false // This is resource needed for all the VMs keep it
	}
	vmIsLocal, vmFound := vms[*vm]
	resourceOvnZone := externalIDs[OvnZoneExternalIDKey]
	// There is no VM that owns it or is at the wrong zone
	return !vmFound || (vmIsLocal && resourceOvnZone != OvnLocalZone)
}
