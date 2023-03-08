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
