package pod

import (
	"fmt"
	"net"

	kubevirtv1 "kubevirt.io/api/core/v1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"
	utilnet "k8s.io/utils/net"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
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

// InitializeAddressPool initializes the address pool for the network with allocated MAC addresses.
// In case an error occur during the process, error is recorded and the process continues to next pod/namespace.
func (allocator *PodAnnotationAllocator) InitializeAddressPool(eventRec record.EventRecorder) error {
	networkName := allocator.netInfo.GetNetworkName()
	infaMACs := calculateSubnetsInfraMACAddresses(allocator.netInfo.Subnets())
	for owner, mac := range infaMACs {
		allocator.addressPool.AddMACToPool(networkName, mac, owner)
	}

	return nil
}

// calculateSubnetsInfraMACAddresses return map of the network infrastructure mac addresses and owner name.
// It calculates the gateway (.2) and management (.1) ports MAC addresses from their IP address.
func calculateSubnetsInfraMACAddresses(subnets []config.CIDRNetworkEntry) map[string]net.HardwareAddr {
	reservedMACs := map[string]net.HardwareAddr{}
	for _, subnet := range subnets {
		if subnet.CIDR != nil && utilnet.IsIPv4CIDR(subnet.CIDR) {
			gwIP := util.GetNodeGatewayIfAddr(subnet.CIDR)
			gwMAC := util.IPAddrToHWAddr(gwIP.IP)
			reservedMACs["gw"] = gwMAC

			mgmtIP := util.GetNodeManagementIfAddr(subnet.CIDR)
			mgmtMAC := util.IPAddrToHWAddr(mgmtIP.IP)
			reservedMACs["mgmt"] = mgmtMAC
		}
	}
	return reservedMACs
}
