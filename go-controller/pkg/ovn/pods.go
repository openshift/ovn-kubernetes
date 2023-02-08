package ovn

import (
	"fmt"
	"net"
	"sync/atomic"
	"time"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/libovsdb/ovsdb"
	hotypes "github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/dhcp"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kubevirt"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/metrics"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	ovntypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/pkg/errors"
	kapi "k8s.io/api/core/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
)

func (oc *DefaultNetworkController) syncPods(pods []interface{}) error {
	// get the list of logical switch ports (equivalent to pods). Reserve all existing Pod IPs to
	// avoid subsequent new Pods getting the same duplicate Pod IP.
	//
	// TBD: Before this succeeds, add Pod handler should not continue to allocate IPs for the new Pods.
	expectedLogicalPorts := make(map[string]bool)
	for _, podInterface := range pods {
		pod, ok := podInterface.(*kapi.Pod)
		if !ok {
			return fmt.Errorf("spurious object in syncPods: %v", podInterface)
		}
		annotations, err := util.UnmarshalPodAnnotation(pod.Annotations, ovntypes.DefaultNetworkName)
		if err != nil {
			continue
		}
		expectedLogicalPortName, err := oc.allocatePodIPs(pod, annotations, ovntypes.DefaultNetworkName)
		if err != nil {
			return err
		}
		if expectedLogicalPortName != "" {
			expectedLogicalPorts[expectedLogicalPortName] = true
		}

		// OCP HACK
		// Do not try to remove hybrid overlay subnet route on pods using ICNIv1
		// delete the outdated hybrid overlay subnet route if it exists
		if annotations != nil && !hasHybridAnnotation(pod.ObjectMeta) {
			// END OCP HACK
			newRoutes := []util.PodRoute{}
			switchName := pod.Spec.NodeName
			for _, subnet := range oc.lsManager.GetSwitchSubnets(switchName) {
				hybridOverlayIFAddr := util.GetNodeHybridOverlayIfAddr(subnet).IP
				for _, route := range annotations.Routes {
					if !route.NextHop.Equal(hybridOverlayIFAddr) {
						newRoutes = append(newRoutes, route)
					}
				}
			}
			// checking the length because cannot compare the slices directly and if routes are removed
			// the length will be different
			if len(annotations.Routes) != len(newRoutes) {
				annotations.Routes = newRoutes
				err = oc.updatePodAnnotationWithRetry(pod, annotations, ovntypes.DefaultNetworkName)
				if err != nil {
					return fmt.Errorf("failed to set annotation on pod %s: %v", pod.Name, err)
				}
			}
		}
	}
	// all pods present before ovn-kube startup have been processed
	atomic.StoreUint32(&oc.allInitialPodsProcessed, 1)

	if config.HybridOverlay.Enabled {
		// allocate all previously annoted hybridOverlay Distributed Router IP addresses. Allocation needs to happen here
		// before a Pod Add event can be processed and be allocated a previously assigned hybridOverlay Distributed Router IP address.
		// we do not support manually setting the hybrid overlay DRIP address
		nodes, err := oc.watchFactory.GetNodes()
		if err != nil {
			return fmt.Errorf("failed to get nodes: %v", err)
		}
		for _, node := range nodes {
			// allocation also happens during Add/Update Node events we only want to allocate any addresses allocated as hybrid overlay
			// distributed router ips during a previous run of ovn-k master to ensure that incoming pod events will not take the address that
			// the node is expecting as the hybrid overlay DRIP
			if _, ok := node.Annotations[hotypes.HybridOverlayDRIP]; ok {
				if err := oc.allocateHybridOverlayDRIP(node); err != nil {
					return fmt.Errorf("cannot allocate hybridOverlay DRIP on node %s (%v)", node.Name, err)
				}
			}
		}
	}

	return oc.deleteStaleLogicalSwitchPorts(expectedLogicalPorts)
}

func (oc *DefaultNetworkController) deleteLogicalPort(pod *kapi.Pod, portInfo *lpInfo) (err error) {
	podDesc := pod.Namespace + "/" + pod.Name
	klog.Infof("Deleting pod: %s", podDesc)

	if err = oc.deletePodExternalGW(pod); err != nil {
		return fmt.Errorf("unable to delete external gateway routes for pod %s: %w", podDesc, err)
	}
	if pod.Spec.HostNetwork {
		return nil
	}
	if !util.PodScheduled(pod) {
		return nil
	}

	isLiveMigrationLefover, err := kubevirt.PodIsLiveMigrationLeftOver(oc.client, pod)
	if err != nil {
		return err
	}

	// For live migrated leftover pods keep the LSP, the LSP should be removed
	// when the VM is removed
	if isLiveMigrationLefover {
		return nil
	}

	pInfo, err := oc.deletePodLogicalPort(pod, portInfo, ovntypes.DefaultNetworkName)
	if err != nil {
		return err
	}

	if kubevirt.OwnsPod(pod) {
		if err := oc.deleteDHCPOptions(pod); err != nil {
			return err
		}
		if err := oc.deletePodEnrouting(pod); err != nil {
			return err
		}
	}

	// do not remove SNATs/GW routes/IPAM for an IP address unless we have validated no other pod is using it
	if pInfo == nil {
		return nil
	}

	if config.Gateway.DisableSNATMultipleGWs {
		if err := deletePodSNAT(oc.nbClient, pInfo.logicalSwitch, []*net.IPNet{}, pInfo.ips); err != nil {
			return fmt.Errorf("cannot delete GR SNAT for pod %s: %w", podDesc, err)
		}
	}
	podNsName := ktypes.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}
	if err := oc.deleteGWRoutesForPod(podNsName, pInfo.ips); err != nil {
		return fmt.Errorf("cannot delete GW Routes for pod %s: %w", podDesc, err)
	}

	// Releasing IPs needs to happen last so that we can deterministically know that if delete failed that
	// the IP of the pod needs to be released. Otherwise we could have a completed pod failed to be removed
	// and we dont know if the IP was released or not, and subsequently could accidentally release the IP
	// while it is now on another pod. Releasing IPs may fail at this point if cache knows nothing about it,
	// which is okay since node may have been deleted.
	klog.Infof("Attempting to release IPs for pod: %s/%s, ips: %s", pod.Namespace, pod.Name,
		util.JoinIPNetIPs(pInfo.ips, " "))
	return oc.releasePodIPs(pInfo)
}

func (oc *DefaultNetworkController) addLogicalPort(pod *kapi.Pod) (err error) {
	// If a node does node have an assigned hostsubnet don't wait for the logical switch to appear
	switchName := pod.Spec.NodeName
	if oc.lsManager.IsNonHostSubnetSwitch(switchName) {
		return nil
	}

	_, network, err := util.PodWantsMultiNetwork(pod, oc.NetInfo)
	if err != nil {
		// multus won't add this Pod if this fails, should never happen
		return fmt.Errorf("error getting default-network's network-attachment for pod %s/%s: %v", pod.Namespace, pod.Name, err)
	}

	var libovsdbExecuteTime time.Duration
	var lsp *nbdb.LogicalSwitchPort
	var ops []ovsdb.Operation
	var podAnnotation *util.PodAnnotation
	var newlyCreatedPort bool
	// Keep track of how long syncs take.
	start := time.Now()
	defer func() {
		klog.Infof("[%s/%s] addLogicalPort took %v, libovsdb time %v",
			pod.Namespace, pod.Name, time.Since(start), libovsdbExecuteTime)
	}()

	nadName := ovntypes.DefaultNetworkName
	// OCP HACK
	var routingExternalGWs *gatewayInfo
	var routingPodGWs map[string]gatewayInfo
	ops, lsp, podAnnotation, newlyCreatedPort, routingExternalGWs, routingPodGWs, err = oc.addLogicalPortToNetwork(oc, pod, nadName, network)
	if err != nil {
		return err
	}
	// END OCP HACK

	// if we have any external or pod Gateways, add routes
	gateways := make([]*gatewayInfo, 0, len(routingExternalGWs.gws)+len(routingPodGWs))

	if len(routingExternalGWs.gws) > 0 {
		gateways = append(gateways, routingExternalGWs)
	}
	for key := range routingPodGWs {
		gw := routingPodGWs[key]
		if len(gw.gws) > 0 {
			if err = validateRoutingPodGWs(routingPodGWs); err != nil {
				klog.Error(err)
			}
			gateways = append(gateways, &gw)
		} else {
			klog.Warningf("Found routingPodGW with no gateways ip set for namespace %s", pod.Namespace)
		}
	}

	if len(gateways) > 0 {
		podNsName := ktypes.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}
		err = oc.addGWRoutesForPod(gateways, podAnnotation.IPs, podNsName, pod.Spec.NodeName)
		if err != nil {
			return err
		}
	} else if config.Gateway.DisableSNATMultipleGWs {
		// Add NAT rules to pods if disable SNAT is set and does not have
		// namespace annotations to go through external egress router
		if extIPs, err := getExternalIPsGR(oc.watchFactory, pod.Spec.NodeName); err != nil {
			return err
		} else if ops, err = oc.addOrUpdatePodSNATReturnOps(pod.Spec.NodeName, extIPs, podAnnotation.IPs, ops); err != nil {
			return err
		}
	}

	recordOps, txOkCallBack, _, err := oc.AddConfigDurationRecord("pod", pod.Namespace, pod.Name)
	if err != nil {
		klog.Errorf("Config duration recorder: %v", err)
	}
	ops = append(ops, recordOps...)

	transactStart := time.Now()
	_, err = libovsdbops.TransactAndCheckAndSetUUIDs(oc.nbClient, lsp, ops)
	libovsdbExecuteTime = time.Since(transactStart)
	if err != nil {
		return fmt.Errorf("error transacting operations %+v: %v", ops, err)
	}
	txOkCallBack()
	oc.podRecorder.AddLSP(pod.UID, oc.NetInfo)

	// check if this pod is serving as an external GW
	err = oc.addPodExternalGW(pod)
	if err != nil {
		return fmt.Errorf("failed to handle external GW check: %v", err)
	}

	// if somehow lspUUID is empty, there is a bug here with interpreting OVSDB results
	if len(lsp.UUID) == 0 {
		return fmt.Errorf("UUID is empty from LSP: %+v", *lsp)
	}

	// Add the pod's logical switch port to the port cache
	portInfo := oc.logicalPortCache.add(pod, switchName, ovntypes.DefaultNetworkName, lsp.UUID, podAnnotation.MAC, podAnnotation.IPs)

	// If multicast is allowed and enabled for the namespace, add the port to the allow policy.
	// FIXME: there's a race here with the Namespace multicastUpdateNamespace() handler, but
	// it's rare and easily worked around for now.
	ns, err := oc.watchFactory.GetNamespace(pod.Namespace)
	if err != nil {
		return err
	}
	if oc.multicastSupport && isNamespaceMulticastEnabled(ns.Annotations) {
		if err := podAddAllowMulticastPolicy(oc.nbClient, pod.Namespace, portInfo); err != nil {
			return err
		}
	}
	if kubevirt.OwnsPod(pod) {
		if err := oc.addDHCPOptions(pod, lsp); err != nil {
			return err
		}
	}
	//observe the pod creation latency metric for newly created pods only
	if newlyCreatedPort {
		metrics.RecordPodCreated(pod, oc.NetInfo)
	}
	return nil
}

func (oc *DefaultNetworkController) addDHCPOptions(pod *kapi.Pod, lsp *nbdb.LogicalSwitchPort) error {
	ipPoolName, err := oc.getIPPoolName(pod)
	if err != nil {
		return err
	}
	var switchSubnets []*net.IPNet
	if switchSubnets = oc.lsManager.GetSwitchSubnets(ipPoolName); switchSubnets == nil {
		return fmt.Errorf("cannot retrieve subnet for assigning gateway routes switch: %s", ipPoolName)
	}
	// Fake router to delegate on proxy arp mechanism
	router := "169.254.1.1"
	cidr := switchSubnets[0].String()
	dhcpOptions, err := dhcp.ComposeOptionsWithKubeDNS(oc.client, cidr, router)
	if err != nil {
		return fmt.Errorf("failed composing DHCP options: %v", err)
	}
	dhcpOptions.ExternalIDs = map[string]string{
		"namespace":      pod.Namespace,
		kubevirt.VMLabel: pod.Labels[kubevirt.VMLabel],
	}
	err = libovsdbops.CreateOrUpdateDhcpv4Options(oc.nbClient, lsp, dhcpOptions)
	if err != nil {
		return fmt.Errorf("failed adding ovn operations to add DHCP v4 options: %v", err)
	}
	return nil
}

func matchesKubevirtPod(pod *kapi.Pod, externalIDs map[string]string) bool {
	return len(externalIDs) > 1 && externalIDs["namespace"] == pod.Namespace && externalIDs[kubevirt.VMLabel] == pod.Labels[kubevirt.VMLabel]
}

func (oc *DefaultNetworkController) deleteDHCPOptions(pod *kapi.Pod) error {
	predicate := func(item *nbdb.DHCPOptions) bool {
		return matchesKubevirtPod(pod, item.ExternalIDs)
	}
	return libovsdbops.DeleteDHCPOptionsWithPredicate(oc.nbClient, predicate)
}

func (oc *DefaultNetworkController) deletePodEnrouting(pod *kapi.Pod) error {
	routePredicate := func(item *nbdb.LogicalRouterStaticRoute) bool {
		return matchesKubevirtPod(pod, item.ExternalIDs)
	}
	if err := libovsdbops.DeleteLogicalRouterStaticRoutesWithPredicate(oc.nbClient, types.OVNClusterRouter, routePredicate); err != nil {
		return err
	}
	policyPredicate := func(item *nbdb.LogicalRouterPolicy) bool {
		return matchesKubevirtPod(pod, item.ExternalIDs)
	}
	if err := libovsdbops.DeleteLogicalRouterPoliciesWithPredicate(oc.nbClient, types.OVNClusterRouter, policyPredicate); err != nil {
		return err
	}
	return nil
}

func (oc *DefaultNetworkController) deleteLiveMigrationLeftOverLSPs(pod *kapi.Pod) error {
	// Delete LSP from source virt-launcher pod
	vmPods, err := kubevirt.FindPodsByVMLabel(oc.client, pod)
	if err != nil {
		return fmt.Errorf("failed finding VM's pods: %v", err)
	}
	for _, vmPod := range vmPods {
		if vmPod.Name == pod.Name {
			continue
		}
		switchName, err := oc.getExpectedSwitchName(&vmPod)
		if err != nil {
			return fmt.Errorf("failed composing switch name: %v", err)
		}
		lsp, err := libovsdbops.GetLogicalSwitchPort(oc.nbClient, &nbdb.LogicalSwitchPort{Name: util.GetLogicalPortName(&vmPod)})
		if err != nil {
			if !errors.Is(err, libovsdbclient.ErrNotFound) {
				return fmt.Errorf("failed getting logical switch port to delete: %v", err)
			} else {
				continue
			}
		}
		if err := libovsdbops.DeleteLogicalSwitchPorts(oc.nbClient, &nbdb.LogicalSwitch{Name: switchName}, lsp); err != nil {
			return fmt.Errorf("failed deleting live migration left over LSP: %v", err)
		}
	}
	return nil
}

func (oc *DefaultNetworkController) enroutePodAddressesToNode(pod *kapi.Pod) error {
	podAnnotation, err := util.UnmarshalPodAnnotation(pod.Annotations, "default")
	if err != nil {
		return err
	}

	nodeGwAddress, err := oc.lrpAddress(types.GWRouterToJoinSwitchPrefix + types.GWRouterPrefix + pod.Spec.NodeName)
	if err != nil {
		return err
	}
	for _, podIP := range podAnnotation.IPs {
		podAddress := podIP.IP.String()
		// Add a reroute policy to route VM n/s traffic to the node where the VM
		// is running
		egressPolicy := nbdb.LogicalRouterPolicy{
			Match:    fmt.Sprintf("ip4.src == %s", podAddress),
			Action:   nbdb.LogicalRouterPolicyActionReroute,
			Nexthops: []string{nodeGwAddress},
			Priority: 1,
			ExternalIDs: map[string]string{
				"namespace":      pod.Namespace,
				kubevirt.VMLabel: pod.Labels[kubevirt.VMLabel],
			},
		}
		if err := libovsdbops.CreateOrUpdateLogicalRouterPolicyWithPredicate(oc.nbClient, types.OVNClusterRouter, &egressPolicy, func(item *nbdb.LogicalRouterPolicy) bool {
			return item.Priority == egressPolicy.Priority && item.Match == egressPolicy.Match && item.Action == egressPolicy.Action
		}); err != nil {
			return err
		}

		// Add a policy to force send an ARP to discover VMs MAC and send
		// directly to it since there is no more routers in the middle
		outputPort := types.RouterToSwitchPrefix + pod.Spec.NodeName
		ingressRoute := nbdb.LogicalRouterStaticRoute{
			IPPrefix:   podAddress,
			Nexthop:    podAddress,
			Policy:     &nbdb.LogicalRouterStaticRoutePolicyDstIP,
			OutputPort: &outputPort,
			ExternalIDs: map[string]string{
				"namespace":      pod.Namespace,
				kubevirt.VMLabel: pod.Labels[kubevirt.VMLabel],
			},
		}
		if err := libovsdbops.CreateOrReplaceLogicalRouterStaticRouteWithPredicate(oc.nbClient, types.OVNClusterRouter, &ingressRoute, func(item *nbdb.LogicalRouterStaticRoute) bool {
			matches := item.IPPrefix == ingressRoute.IPPrefix && item.Nexthop == ingressRoute.Nexthop && item.Policy != nil && *item.Policy == *ingressRoute.Policy
			return matches
		}); err != nil {
			return err
		}
	}
	return nil
}

func (oc *DefaultNetworkController) enrouteVirtualMachine(pod *kapi.Pod) error {
	targetNode := pod.Labels[kubevirt.NodeNameLabel]
	// There is no live migration or live migration has finished
	if targetNode == "" || targetNode == pod.Spec.NodeName {
		if err := oc.enroutePodAddressesToNode(pod); err != nil {
			return fmt.Errorf("failed enroutePodAddressesToNode for  %s/%s: %w", pod.Namespace, pod.Name, err)
		}
		if err := oc.deleteLiveMigrationLeftOverLSPs(pod); err != nil {
			return fmt.Errorf("failed deleteLiveMigrationLeftOverLSPs for %s/%s: %w", pod.Namespace, pod.Name, err)
		}
	}
	return nil
}

func (oc *DefaultNetworkController) lrpAddress(lrpName string) (string, error) {
	lrp := &nbdb.LogicalRouterPort{
		Name: lrpName,
	}

	lrp, err := libovsdbops.GetLogicalRouterPort(oc.nbClient, lrp)
	if err != nil {
		return "", err
	}
	lrpIP, _, err := net.ParseCIDR(lrp.Networks[0])
	if err != nil {
		return "", err
	}
	address := lrpIP.String()
	if address == "" {
		return "", fmt.Errorf("missing logical router port address")
	}
	return address, nil
}
