package pod

import (
	"fmt"
	"net"

	kubevirtv1 "kubevirt.io/api/core/v1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util/pool"
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

	pods, err := allocator.fetchNetworkPods()
	if err != nil {
		return err
	}
	if aerr := allocator.allocatePodMACs(pods, eventRec); aerr != nil {
		return aerr
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

// fetchNetworkPods fetch pods in to the network NAD namespaces.
func (allocator *PodAnnotationAllocator) fetchNetworkPods() ([]*corev1.Pod, error) {
	var netPods []*corev1.Pod
	for _, ns := range allocator.netInfo.GetNADNamespaces() {
		pods, err := allocator.podLister.Pods(ns).List(labels.Everything())
		if err != nil {
			return nil, fmt.Errorf("failed to list pods for namespace %q: %v", ns, err)
		}
		for _, pod := range pods {
			if pod == nil {
				continue
			}
			if pod.Status.Phase != corev1.PodRunning || !pod.DeletionTimestamp.IsZero() && len(pod.Finalizers) == 0 {
				// skip pods who are non-running or about to dispose
				continue
			}
			netPods = append(netPods, pod)
		}
	}
	return netPods, nil
}

// allocatePodMACs for each given pod it record the given pods MAC addresses in the network pool.
// In case of a conflict it emits pod event reflecting MAC conflict occurred.
func (allocator *PodAnnotationAllocator) allocatePodMACs(pods []*corev1.Pod, eventRecorder record.EventRecorder) error {
	networkName := allocator.netInfo.GetNetworkName()
	macConflictPods := map[string]string{}

	for _, pod := range pods {
		podNetworks, err := util.UnmarshalPodAnnotationAllNetworks(pod.Annotations)
		if err != nil {
			return fmt.Errorf("failed to unmarshal pod annotation %s/%s: %v", pod.Namespace, pod.Name, err)
		}
		for nadName, network := range podNetworks {
			if network.Role != types.NetworkRoleInfrastructure {
				// primary UDN network role is infrastructure-lock on primary UDNs only.
				continue
			}
			mac, perr := net.ParseMAC(network.MAC)
			if perr != nil {
				return fmt.Errorf("failed to parse pod %s/%s mac address %q: %v", pod.Namespace, pod.Name, network.MAC, perr)
			}

			ownerID := GetPoolAddressOwner(pod, allocator.netInfo)
			if allocator.addressPool.IsMACConflict(networkName, mac, ownerID) {
				macConflictPods[network.MAC] = pod.Namespace + "/" + pod.Name

				msg := fmt.Sprintf("%s: %s already allocated in network %s", pool.ErrMACConflict, mac, nadName)
				eventRecorder.Event(pod, corev1.EventTypeWarning, "ErrorInitAddressPool", msg)
				klog.Warningf("%v; network-name: %s", msg, allocator.netInfo.GetNetworkName())
			} else {
				allocator.addressPool.AddMACToPool(allocator.netInfo.GetNetworkName(), mac, ownerID)
			}
		}
	}
	if len(macConflictPods) > 0 {
		return fmt.Errorf("MAC address conflicts detected: %v", macConflictPods)
	}
	return nil
}
