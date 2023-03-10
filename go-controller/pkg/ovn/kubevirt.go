package ovn

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	kapi "k8s.io/api/core/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	utilnet "k8s.io/utils/net"

	kubevirtv1 "kubevirt.io/api/core/v1"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kubevirt"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	ovntypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

func (oc *DefaultNetworkController) ensureDHCPOptionsForVM(pod *corev1.Pod, lsp *nbdb.LogicalSwitchPort) error {
	if !kubevirt.PodIsLiveMigratable(pod) {
		return nil
	}

	ovnPodAnnotation, err := util.UnmarshalPodAnnotation(pod.Annotations, ovntypes.DefaultNetworkName)
	if err != nil {
		return fmt.Errorf("failed retrieving subnets to configure DHCP at lsp %s: %v", lsp.Name, err)
	}
	// Fake router to delegate on proxy arp mechanism
	vmName, ok := pod.Labels[kubevirtv1.VirtualMachineNameLabel]
	if !ok {
		return fmt.Errorf("missing %s label at pod %s/%s when configuaring DHCP", kubevirtv1.VirtualMachineNameLabel, pod.Namespace, pod.Name)
	}
	dhcpConfigs, err := kubevirt.ComposeDHCPConfigs(oc.watchFactory, oc.controllerName, pod.Namespace, vmName, ovnPodAnnotation.IPs)
	if err != nil {
		return fmt.Errorf("failed composing DHCP options: %v", err)
	}
	err = libovsdbops.CreateOrUpdateDhcpOptions(oc.nbClient, lsp, dhcpConfigs)
	if err != nil {
		return fmt.Errorf("failed creation or updating OVN operations to add DHCP options: %v", err)
	}
	return nil
}

func (oc *DefaultNetworkController) deleteDHCPOptions(pod *kapi.Pod) error {
	predicate := func(item *nbdb.DHCPOptions) bool {
		return kubevirt.ExternalIDsContainsVM(item.ExternalIDs, kubevirt.ExtractVMFromPod(pod))
	}
	return libovsdbops.DeleteDHCPOptionsWithPredicate(oc.nbClient, predicate)
}

func (oc *DefaultNetworkController) deleteStaticRoutesForMigratedPod(pod *kapi.Pod) error {
	vm := kubevirt.ExtractVMFromPod(pod)
	routePredicate := func(item *nbdb.LogicalRouterStaticRoute) bool {
		return kubevirt.ExternalIDsContainsVM(item.ExternalIDs, vm)
	}
	if err := libovsdbops.DeleteLogicalRouterStaticRoutesWithPredicate(oc.nbClient, types.OVNClusterRouter, routePredicate); err != nil {
		return fmt.Errorf("failed deleting pod routing when deleting the LR static routes: %v", err)
	}
	policyPredicate := func(item *nbdb.LogicalRouterPolicy) bool {
		return kubevirt.ExternalIDsContainsVM(item.ExternalIDs, vm)
	}
	if err := libovsdbops.DeleteLogicalRouterPoliciesWithPredicate(oc.nbClient, types.OVNClusterRouter, policyPredicate); err != nil {
		return fmt.Errorf("failed deleting pod routing when deleting the LR policies: %v", err)
	}
	return nil
}

func (oc *DefaultNetworkController) cleanUpForVM(pod *corev1.Pod) error {
	isMigratedSourcePodState, err := kubevirt.IsMigratedSourcePodStale(oc.watchFactory, pod)
	if err != nil {
		return fmt.Errorf("failed cleaning up VM when checking if pod is leftover: %v", err)
	}
	// Everything has already being cleand up since this is and old migration
	// pod
	if isMigratedSourcePodState {
		return nil
	}
	// This pod is not part of ip migration so we don't need to clean up
	if !kubevirt.PodIsLiveMigratable(pod) {
		return nil
	}
	if err := oc.deleteDHCPOptions(pod); err != nil {
		return err
	}
	if err := oc.deleteStaticRoutesForMigratedPod(pod); err != nil {
		return err
	}
	return nil
}

func (oc *DefaultNetworkController) ensureLocalZonePodAddressesToNodeRoute(pod *kapi.Pod) error {
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
			policyVMLabel, ok := policy.ExternalIDs[string(libovsdbops.VirtualMachineIndex)]
			return ok && policyVMLabel == pod.Labels[kubevirtv1.VirtualMachineNameLabel]
		}); err != nil {
			return fmt.Errorf("failed configuring pod routing when deleting stale policies for pod %s/%s: %v", pod.Namespace, pod.Name, err)
		}
		if err := libovsdbops.DeleteLogicalRouterStaticRoutesWithPredicate(oc.nbClient, types.OVNClusterRouter, func(route *nbdb.LogicalRouterStaticRoute) bool {
			routeVMLabel, ok := route.ExternalIDs[string(libovsdbops.VirtualMachineIndex)]
			return ok && routeVMLabel == pod.Labels[kubevirtv1.VirtualMachineNameLabel]
		}); err != nil {
			return fmt.Errorf("failed configuring pod routing when deleting stale static routes for pod %s/%s: %v", pod.Namespace, pod.Name, err)
		}
		return nil
	}
	lrpName := types.GWRouterToJoinSwitchPrefix + types.GWRouterPrefix + pod.Spec.NodeName
	lrpAddresses, err := util.GetLRPAddrs(oc.nbClient, lrpName)
	if err != nil {
		return fmt.Errorf("failed configuring pod routing when reading LRP %s addresses: %v", lrpName, err)
	}

	// For IC this route will match the cluster CIDR and route traffic to
	// the gw, the VM's live migrated IP will match there when they
	// are migrated at a node not owning the VM subnet
	if config.OVNKubernetesFeature.EnableInterconnect {
		for _, clusterSubnet := range config.Default.ClusterSubnets {
			nodeGRAddress, err := util.MatchFirstIPNetFamily(utilnet.IPFamilyOfCIDR(clusterSubnet.CIDR) == utilnet.IPv6, lrpAddresses)
			if err != nil {
				return err
			}
			clusterSubnetRoute := nbdb.LogicalRouterStaticRoute{
				IPPrefix: clusterSubnet.CIDR.String(),
				Nexthop:  nodeGRAddress.IP.String(),
				Policy:   &nbdb.LogicalRouterStaticRoutePolicySrcIP,
				ExternalIDs: map[string]string{
					kubevirt.OvnZoneExternalIDKey:           kubevirt.OvnLocalZone,
					string(libovsdbops.VirtualMachineIndex): kubevirt.AllVMs,
				},
			}
			if err := libovsdbops.CreateOrReplaceLogicalRouterStaticRouteWithPredicate(oc.nbClient, types.OVNClusterRouter, &clusterSubnetRoute, func(item *nbdb.LogicalRouterStaticRoute) bool {
				matches := item.IPPrefix == clusterSubnetRoute.IPPrefix && item.Nexthop == clusterSubnetRoute.Nexthop && item.Policy != nil && *item.Policy == *clusterSubnetRoute.Policy
				return matches
			}); err != nil {
				return fmt.Errorf("failed adding static route: %v", err)
			}
		}
	}

	for _, podIP := range podAnnotation.IPs {
		podAddress := podIP.IP.String()
		// In case of one global zone a policy is needed to route traffic
		// to the gateway
		if !config.OVNKubernetesFeature.EnableInterconnect {
			ipFamily := utilnet.IPFamilyOfCIDR(podIP)
			nodeGRAddress, err := util.MatchFirstIPNetFamily(ipFamily == utilnet.IPv6, lrpAddresses)
			if err != nil {
				return err
			}
			match := fmt.Sprintf("ip%s.src == %s", ipFamily, podAddress)
			egressPolicy := nbdb.LogicalRouterPolicy{
				Match:    match,
				Action:   nbdb.LogicalRouterPolicyActionReroute,
				Nexthops: []string{nodeGRAddress.IP.String()},
				Priority: 1,
				ExternalIDs: map[string]string{
					kubevirt.OvnZoneExternalIDKey:           kubevirt.OvnLocalZone,
					string(libovsdbops.VirtualMachineIndex): pod.Labels[kubevirtv1.VirtualMachineNameLabel],
					string(libovsdbops.NamespaceIndex):      pod.Namespace,
				},
			}
			if err := libovsdbops.CreateOrUpdateLogicalRouterPolicyWithPredicate(oc.nbClient, types.OVNClusterRouter, &egressPolicy, func(item *nbdb.LogicalRouterPolicy) bool {
				return item.Priority == egressPolicy.Priority && item.Match == egressPolicy.Match && item.Action == egressPolicy.Action
			}); err != nil {
				return fmt.Errorf("failed adding point to point policy for pod %s/%s : %v", pod.Namespace, pod.Name, err)
			}
		}

		// Add a route for reroute ingress traffic to the VM port since
		// the subnet is alien to ovn_cluster_router
		outputPort := types.RouterToSwitchPrefix + pod.Spec.NodeName
		ingressRoute := nbdb.LogicalRouterStaticRoute{
			IPPrefix:   podAddress,
			Nexthop:    podAddress,
			Policy:     &nbdb.LogicalRouterStaticRoutePolicyDstIP,
			OutputPort: &outputPort,
			ExternalIDs: map[string]string{
				kubevirt.OvnZoneExternalIDKey:           kubevirt.OvnLocalZone,
				string(libovsdbops.VirtualMachineIndex): pod.Labels[kubevirtv1.VirtualMachineNameLabel],
				string(libovsdbops.NamespaceIndex):      pod.Namespace,
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

func (oc *DefaultNetworkController) ensureRemoteZonePodAddressesToNodeRoute(pod *kapi.Pod) error {
	// Cleanup from VM running at remote zone
	if err := oc.deleteDHCPOptions(pod); err != nil {
		return err
	}
	if err := oc.deleteStaticRoutesForMigratedPod(pod); err != nil {
		return err
	}

	switchNames, err := oc.getSwitchNames(pod)
	if err != nil {
		return fmt.Errorf("failed configuring remote pod routing when getting switch current and original name: %v", err)
	}

	if switchNames.Current == switchNames.Original {
		return nil
	}

	podAnnotation, err := util.UnmarshalPodAnnotation(pod.Annotations, "default")
	if err != nil {
		return fmt.Errorf("failed reading ovn annotation: %v", err)
	}

	node, err := oc.watchFactory.GetNode(pod.Spec.NodeName)
	if err != nil {
		return err
	}
	transitSwitchPortAddrs, err := util.ParseNodeTransitSwitchPortAddrs(node)
	if err != nil {
		return err
	}
	for _, podIP := range podAnnotation.IPs {
		ipFamily := utilnet.IPFamilyOfCIDR(podIP)
		transitSwitchPortAddr, err := util.MatchFirstIPNetFamily(ipFamily == utilnet.IPv6, transitSwitchPortAddrs)
		if err != nil {
			return err
		}
		route := nbdb.LogicalRouterStaticRoute{
			IPPrefix: podIP.IP.String(),
			Nexthop:  transitSwitchPortAddr.IP.String(),
			Policy:   &nbdb.LogicalRouterStaticRoutePolicyDstIP,
			ExternalIDs: map[string]string{
				kubevirt.OvnZoneExternalIDKey:           kubevirt.OvnRemoteZone,
				string(libovsdbops.VirtualMachineIndex): pod.Labels[kubevirtv1.VirtualMachineNameLabel],
				string(libovsdbops.NamespaceIndex):      pod.Namespace,
			},
		}
		if err := libovsdbops.CreateOrReplaceLogicalRouterStaticRouteWithPredicate(oc.nbClient, types.OVNClusterRouter, &route, func(item *nbdb.LogicalRouterStaticRoute) bool {
			matches := item.IPPrefix == route.IPPrefix && item.Nexthop == route.Nexthop && item.Policy != nil && *item.Policy == *route.Policy
			return matches
		}); err != nil {
			return fmt.Errorf("failed adding static route at remote zone: %v", err)
		}
	}
	return nil
}

func (oc *DefaultNetworkController) ensureRoutingForVM(pod *kapi.Pod) error {
	isMigratedSourcePodState, err := kubevirt.IsMigratedSourcePodStale(oc.watchFactory, pod)
	if err != nil {
		return err
	}
	if util.PodWantsHostNetwork(pod) || !kubevirt.PodIsLiveMigratable(pod) || isMigratedSourcePodState {
		return nil
	}

	targetNode := pod.Labels[kubevirtv1.NodeNameLabel]
	targetReadyTimestamp := pod.Annotations[kubevirtv1.MigrationTargetReadyTimestamp]
	// No live migration or target node was reached || qemu is already ready
	if targetNode == pod.Spec.NodeName || targetReadyTimestamp != "" {
		if oc.isPodScheduledinLocalZone(pod) {
			if err := oc.ensureLocalZonePodAddressesToNodeRoute(pod); err != nil {
				return fmt.Errorf("failed ensureLocalZonePodAddressesToNodeRoute for %s/%s: %w", pod.Namespace, pod.Name, err)
			}
		} else {
			if err := oc.ensureRemoteZonePodAddressesToNodeRoute(pod); err != nil {
				return fmt.Errorf("failed ensureRemoteZonePodAddressesToNodeRoute for %s/%s: %w", pod.Namespace, pod.Name, err)
			}
		}
	}
	return nil
}

func (oc *DefaultNetworkController) syncVirtualMachines(vms map[ktypes.NamespacedName]bool) error {
	// If there is no ovn_cluster_router OVN garbage collector will do the job
	_, err := libovsdbops.GetLogicalRouter(oc.nbClient, &nbdb.LogicalRouter{Name: ovntypes.OVNClusterRouter})
	if err == libovsdbclient.ErrNotFound {
		return nil
	}

	if err := libovsdbops.DeleteLogicalRouterStaticRoutesWithPredicate(oc.nbClient, ovntypes.OVNClusterRouter, func(item *nbdb.LogicalRouterStaticRoute) bool {
		return kubevirt.OwnsItAndIsOrphanOrWrongZone(item.ExternalIDs, vms)
	}); err != nil {
		return fmt.Errorf("failed deleting stale vm static routes: %v", err)
	}
	if err := libovsdbops.DeleteLogicalRouterPoliciesWithPredicate(oc.nbClient, ovntypes.OVNClusterRouter, func(item *nbdb.LogicalRouterPolicy) bool {
		return kubevirt.OwnsItAndIsOrphanOrWrongZone(item.ExternalIDs, vms)
	}); err != nil {
		return fmt.Errorf("failed deleting stale vm policies: %v", err)
	}
	//TODO: If there is no running VMs remove the IC cluster wide cidr route
	return nil
}
