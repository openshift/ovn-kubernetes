package pod

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	kubevirtv1 "kubevirt.io/api/core/v1"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

// GetPoolAddressOwner constructs the owner identifier for IP/MAC pool tracking.
// Returns "<ns>/<pod-name>" for regular pods and "<ns>/<vm-name>" for VMs with persistent IPs enabled.
func GetPoolAddressOwner(pod *corev1.Pod, netInfo util.NetInfo) string {
	// Check if this is a VM pod and persistent IPs are enabled
	if netInfo.AllowsPersistentIPs() {
		if vmName, ok := pod.Labels[kubevirtv1.VirtualMachineNameLabel]; ok {
			return fmt.Sprintf("%s/%s", pod.Namespace, vmName)
		}
	}

	// Default to pod-based identifier
	return fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
}
