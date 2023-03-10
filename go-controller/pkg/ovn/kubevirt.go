package ovn

import (
	"fmt"
	"net"

	corev1 "k8s.io/api/core/v1"
	kapi "k8s.io/api/core/v1"
	utilnet "k8s.io/utils/net"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kubevirt"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

func (oc *DefaultNetworkController) ensureDHCPOptionsForVM(pod *corev1.Pod, lsp *nbdb.LogicalSwitchPort) error {
	if !kubevirt.AllowPodBridgeNetworkLiveMigration(pod.Annotations) {
		return nil
	}

	switchNames, err := oc.getSwitchNames(pod)
	if err != nil {
		return fmt.Errorf("failed configuring dhcp when getting switch current and original name: %v", err)
	}
	var switchSubnets []*net.IPNet
	if switchSubnets = oc.lsManager.GetSwitchSubnets(switchNames.Original); switchSubnets == nil {
		return fmt.Errorf("subnet not found for switch %s to configuare DHCP at lsp %s", switchNames.Original, lsp.Name)
	}
	// Fake router to delegate on proxy arp mechanism
	vmName, ok := pod.Labels[kubevirt.VMLabel]
	if !ok {
		return fmt.Errorf("missing %s label at pod %s/%s when configuaring DHCP", kubevirt.VMLabel, pod.Namespace, pod.Name)
	}
	dhcpConfig, err := kubevirt.ComposeDHCPConfig(oc.watchFactory, vmName, switchSubnets)
	if err != nil {
		return fmt.Errorf("failed composing DHCP options: %v", err)
	}

	if dhcpConfig.V4Options != nil {
		dhcpConfig.V4Options.ExternalIDs = map[string]string{
			"namespace":      pod.Namespace,
			kubevirt.VMLabel: vmName,
		}
	}
	if dhcpConfig.V6Options != nil {
		dhcpConfig.V6Options.ExternalIDs = map[string]string{
			"namespace":      pod.Namespace,
			kubevirt.VMLabel: vmName,
		}
	}
	err = libovsdbops.CreateOrUpdateDhcpOptions(oc.nbClient, lsp, dhcpConfig.V4Options, dhcpConfig.V6Options)
	if err != nil {
		return fmt.Errorf("failed creation or updating OVN operations to add DHCP options: %v", err)
	}
	return nil
}

func (oc *DefaultNetworkController) deleteDHCPOptions(pod *kapi.Pod) error {
	predicate := func(item *nbdb.DHCPOptions) bool {
		return kubevirt.PodMatchesExternalIDs(pod, item.ExternalIDs)
	}
	return libovsdbops.DeleteDHCPOptionsWithPredicate(oc.nbClient, predicate)
}

func (oc *DefaultNetworkController) deletePodRouting(pod *kapi.Pod) error {
	routePredicate := func(item *nbdb.LogicalRouterStaticRoute) bool {
		return kubevirt.PodMatchesExternalIDs(pod, item.ExternalIDs)
	}
	if err := libovsdbops.DeleteLogicalRouterStaticRoutesWithPredicate(oc.nbClient, types.OVNClusterRouter, routePredicate); err != nil {
		return fmt.Errorf("failed deleting pod routing when deleting the LR static routes: %v", err)
	}
	policyPredicate := func(item *nbdb.LogicalRouterPolicy) bool {
		return kubevirt.PodMatchesExternalIDs(pod, item.ExternalIDs)
	}
	if err := libovsdbops.DeleteLogicalRouterPoliciesWithPredicate(oc.nbClient, types.OVNClusterRouter, policyPredicate); err != nil {
		return fmt.Errorf("failed deleting pod routing when deleting the LR policies: %v", err)
	}
	return nil
}

func (oc *DefaultNetworkController) cleanupForVM(pod *corev1.Pod) error {
	isLiveMigrationLefover, err := kubevirt.PodIsLiveMigrationLeftOver(oc.watchFactory, pod)
	if err != nil {
		return fmt.Errorf("failed cleaning up VM when checking if pod is leftover: %v", err)
	}
	// Everything has already being cleand up since this is and old migration
	// pod
	if isLiveMigrationLefover {
		return nil
	}
	// This pod is not part of ip migration so we don't need to clean up
	if !kubevirt.AllowPodBridgeNetworkLiveMigration(pod.Annotations) {
		return nil
	}
	if err := oc.deleteDHCPOptions(pod); err != nil {
		return err
	}
	if err := oc.deletePodRouting(pod); err != nil {
		return err
	}
	return nil
}

func (oc *DefaultNetworkController) ensurePodAddressesToNodeRoute(pod *kapi.Pod) error {
	podAnnotation, err := util.UnmarshalPodAnnotation(pod.Annotations, "default")
	if err != nil {
		return fmt.Errorf("failed reading ovn annotation: %v", err)
	}
	switchNames, err := oc.getSwitchNames(pod)
	if err != nil {
		return fmt.Errorf("failed configuring pod routing when getting switch current and original name: %v", err)
	}

	// VM is running at the node that owns the subnet the point to point
	// routing is not needed
	if switchNames.Current == switchNames.Original {
		// Delete not needed policies or static routes
		if err := libovsdbops.DeleteLogicalRouterPoliciesWithPredicate(oc.nbClient, types.OVNClusterRouter, func(policy *nbdb.LogicalRouterPolicy) bool {
			policyVMLabel, ok := policy.ExternalIDs[kubevirt.VMLabel]
			return ok && policyVMLabel == pod.Labels[kubevirt.VMLabel]
		}); err != nil {
			return fmt.Errorf("failed configuring pod routing when deleting stale policies for pod %s/%s: %v", pod.Namespace, pod.Name, err)
		}
		if err := libovsdbops.DeleteLogicalRouterStaticRoutesWithPredicate(oc.nbClient, types.OVNClusterRouter, func(route *nbdb.LogicalRouterStaticRoute) bool {
			routeVMLabel, ok := route.ExternalIDs[kubevirt.VMLabel]
			return ok && routeVMLabel == pod.Labels[kubevirt.VMLabel]
		}); err != nil {
			return fmt.Errorf("failed configuring pod routing when deleting stale static routes for pod %s/%s: %v", pod.Namespace, pod.Name, err)
		}
		return nil
	}

	lrpAddresses, err := util.GetLRPAddrs(oc.nbClient, types.GWRouterToJoinSwitchPrefix+types.GWRouterPrefix+pod.Spec.NodeName)
	if err != nil {
		return fmt.Errorf("failed configuring pod routing when reading LRP addresses: %v", err)
	}

	nodeGwAddressIPv4, err := util.MatchFirstIPNetFamily(false, lrpAddresses)
	if err != nil {
		return fmt.Errorf("failed configuring pod routing when looking for lrp IPv4 address: %v", err)
	}
	var nodeGwAddressIPv6 *net.IPNet
	// This is dual stack, lets find the ipv6 gateway
	if len(lrpAddresses) > 1 {
		nodeGwAddressIPv6, err = util.MatchFirstIPNetFamily(true, lrpAddresses)
		if err != nil {
			return fmt.Errorf("failed configuring pod routing when looking for lrp IPv6 address: %v", err)
		}
	}

	for _, podIP := range podAnnotation.IPs {
		// Add a reroute policy to route VM n/s traffic to the node where the VM
		// is running
		ipVersion := "4"
		nexthop := nodeGwAddressIPv4.IP.String()
		if utilnet.IsIPv6CIDR(podIP) {
			ipVersion = "6"
			nexthop = nodeGwAddressIPv6.IP.String()
		}
		podAddress := podIP.IP.String()
		match := fmt.Sprintf("ip%s.src == %s", ipVersion, podAddress)
		egressPolicy := nbdb.LogicalRouterPolicy{
			Match:    match,
			Action:   nbdb.LogicalRouterPolicyActionReroute,
			Nexthops: []string{nexthop},
			Priority: 1,
			ExternalIDs: map[string]string{
				"namespace":      pod.Namespace,
				kubevirt.VMLabel: pod.Labels[kubevirt.VMLabel],
			},
		}
		if err := libovsdbops.CreateOrUpdateLogicalRouterPolicyWithPredicate(oc.nbClient, types.OVNClusterRouter, &egressPolicy, func(item *nbdb.LogicalRouterPolicy) bool {
			return item.Priority == egressPolicy.Priority && item.Match == egressPolicy.Match && item.Action == egressPolicy.Action
		}); err != nil {
			return fmt.Errorf("failed adding point to point policy for pod %s/%s : %v", pod.Namespace, pod.Name, err)
		}

		// Add a static route that will always match so policies get evaluated
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
			return fmt.Errorf("failed adding static route: %v", err)
		}
	}
	return nil
}

func (oc *DefaultNetworkController) ensureRoutingForVM(pod *kapi.Pod) error {
	isLiveMigrationLefover, err := kubevirt.PodIsLiveMigrationLeftOver(oc.watchFactory, pod)
	if err != nil {
		return err
	}
	if util.PodWantsHostNetwork(pod) || !kubevirt.AllowPodBridgeNetworkLiveMigration(pod.Annotations) || isLiveMigrationLefover {
		return nil
	}

	targetNode := pod.Labels[kubevirt.NodeNameLabel]
	targetStartTimestamp := pod.Annotations[kubevirt.MigrationTargetStartTimestampAnnotation]
	// No live migration or target node was reached || qemu is already ready
	if targetNode == pod.Spec.NodeName || targetStartTimestamp != "" {
		if err := oc.ensurePodAddressesToNodeRoute(pod); err != nil {
			return fmt.Errorf("failed ensurePodAddressesToNodeRoute for %s/%s: %w", pod.Namespace, pod.Name, err)
		}
	}
	return nil
}
