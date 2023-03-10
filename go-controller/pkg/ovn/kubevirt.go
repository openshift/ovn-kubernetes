package ovn

import (
	"fmt"
	"net"

	corev1 "k8s.io/api/core/v1"
	kapi "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
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

// ensureNetworkInfoForVM will at live migration extract the ovn pod
// annotations and original switch name from the source vm pod and copy it
// to the target vm pod so ip address follow vm during migration. This has to
// done before creating the LSP to be sure that Address field get configured
// correctly at the target VM pod LSP.
func ensureNetworkInfoForVM(watchFactory *factory.WatchFactory, kube *kube.KubeOVN, pod *corev1.Pod) error {
	if !kubevirt.IsPodLiveMigratable(pod) {
		return nil
	}
	vmNetworkInfo, err := kubevirt.FindNetworkInfo(watchFactory, pod)
	if err != nil {
		return err
	}
	resultErr := retry.RetryOnConflict(util.OvnConflictBackoff, func() error {
		// Informer cache should not be mutated, so get a copy of the object
		pod, err := watchFactory.GetPod(pod.Namespace, pod.Name)
		if err != nil {
			return err
		}
		// Informer cache should not be mutated, so get a copy of the object
		cpod := pod.DeepCopy()
		_, ok := cpod.Labels[kubevirt.OriginalSwitchNameLabel]
		if !ok {
			cpod.Labels[kubevirt.OriginalSwitchNameLabel] = vmNetworkInfo.OriginalSwitchName
		}
		if vmNetworkInfo.Status != "" {
			cpod.Annotations[util.OvnPodAnnotationName] = vmNetworkInfo.Status
		}
		return kube.UpdatePod(cpod)
	})
	if resultErr != nil {
		return fmt.Errorf("failed to update labels and annotations on pod %s/%s: %v", pod.Namespace, pod.Name, resultErr)
	}

	// There is nothing to check
	if vmNetworkInfo.Status == "" {
		return nil
	}
	// Wait until informers cache get updated so we don't depend on conflict
	// mechanism at next pod annotations update
	return wait.ExponentialBackoff(util.OvnConflictBackoff, func() (bool, error) {
		pod, err := watchFactory.GetPod(pod.Namespace, pod.Name)
		if err != nil {
			return false, err
		}
		currentNetworkInfoStatus, ok := pod.Annotations[util.OvnPodAnnotationName]
		if !ok || currentNetworkInfoStatus != vmNetworkInfo.Status {
			return false, err
		}
		originalSwitchName, ok := pod.Labels[kubevirt.OriginalSwitchNameLabel]
		if !ok || originalSwitchName != vmNetworkInfo.OriginalSwitchName {
			return false, err
		}
		return true, nil
	})
}

func (oc *DefaultNetworkController) ensureDHCPOptionsForVM(pod *corev1.Pod, lsp *nbdb.LogicalSwitchPort) error {
	if !kubevirt.IsPodLiveMigratable(pod) {
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
	err = libovsdbops.CreateOrUpdateDhcpOptions(oc.nbClient, lsp, dhcpConfigs.V4, dhcpConfigs.V6)
	if err != nil {
		return fmt.Errorf("failed creation or updating OVN operations to add DHCP options: %v", err)
	}
	return nil
}

func (oc *DefaultNetworkController) deleteDHCPOptions(pod *kapi.Pod) error {
	vmKey := kubevirt.ExtractVMNameFromPod(pod)
	if vmKey == nil {
		return nil
	}
	predicateIDs := libovsdbops.NewDbObjectIDs(libovsdbops.VirtualMachineDHCPOptions, oc.controllerName,
		map[libovsdbops.ExternalIDKey]string{
			libovsdbops.NamespaceIndex:      vmKey.Namespace,
			libovsdbops.VirtualMachineIndex: vmKey.Name,
		})
	predicate := libovsdbops.GetPredicate[*nbdb.DHCPOptions](predicateIDs, nil)
	return libovsdbops.DeleteDHCPOptionsWithPredicate(oc.nbClient, predicate)
}

func (oc *DefaultNetworkController) deleteRoutingForMigratedPod(pod *kapi.Pod) error {
	vm := kubevirt.ExtractVMNameFromPod(pod)
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
	isMigratedSourcePodStale, err := kubevirt.IsMigratedSourcePodStale(oc.watchFactory, pod)
	if err != nil {
		return fmt.Errorf("failed cleaning up VM when checking if pod is leftover: %v", err)
	}
	// Everything has already being cleand up since this is an old migration
	// pod
	if isMigratedSourcePodStale {
		return nil
	}
	// This pod is not part of ip migration so we don't need to clean up
	if !kubevirt.IsPodLiveMigratable(pod) {
		return nil
	}
	if err := oc.deleteDHCPOptions(pod); err != nil {
		return err
	}
	if err := oc.deleteRoutingForMigratedPod(pod); err != nil {
		return err
	}
	return nil
}

// ensureLocalZonePodAddressesToNodeRoute will add static routes and policies to ovn_cluster_route logical router
// to ensure VM traffic work as expected after live migration if the pod is running at the local/global zone
// following is the list of NB logical resources created depending if it's interconnected or not:
// IC:
//   - static route with VM ip as dst-ip prefix and output port as node switch LRP
//   - static route with cluster wide CIDR as src-ip prefix and nexthop GR, it has less
//     priority than route to use overlay in case of pod to pod communication
//
// NO IC:
//   - static route with VM ip as dst-ip prefix and output port as node switch LRP
//   - low priority policy with src VM ip and reroute GR, since it has low priority
//     it will not override the policy to enroute pod to pod traffic using overlay
func (oc *DefaultNetworkController) ensureLocalZonePodAddressesToNodeRoute(pod *kapi.Pod) error {
	podAnnotation, err := util.UnmarshalPodAnnotation(pod.Annotations, types.DefaultNetworkName)
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

	//TODO: Should we use a transaction so all the routing elements appear
	//      at once at ovn db ?
	for _, podIP := range podAnnotation.IPs {
		podAddress := podIP.IP.String()
		podCIDR := (&net.IPNet{IP: podIP.IP.Mask(podIP.Mask), Mask: podIP.Mask}).String()
		// For interconnect a static route that matches the VM src ip is needed
		// to ensure the egress policy is evaluated, the nexthop/output port is
		// overriden by the policy but we need them to have one per VM
		if config.OVNKubernetesFeature.EnableInterconnect {
			originalNode, err := oc.watchFactory.GetNode(switchNames.Original)
			if err != nil {
				return err
			}
			transitSwitchPortAddrs, err := util.ParseNodeTransitSwitchPortAddrs(originalNode)
			if err != nil {
				return err
			}
			ipFamily := utilnet.IPFamilyOfCIDR(podIP)
			transitSwitchPortAddr, err := util.MatchFirstIPNetFamily(ipFamily == utilnet.IPv6, transitSwitchPortAddrs)
			if err != nil {
				return err
			}

			enablePoliciesRoute := nbdb.LogicalRouterStaticRoute{
				IPPrefix: podCIDR,
				Nexthop:  transitSwitchPortAddr.IP.String(),
				Policy:   &nbdb.LogicalRouterStaticRoutePolicySrcIP,
				ExternalIDs: map[string]string{
					kubevirt.OvnZoneExternalIDKey: kubevirt.OvnLocalZone,
				},
			}
			if err := libovsdbops.CreateOrReplaceLogicalRouterStaticRouteWithPredicate(oc.nbClient, types.OVNClusterRouter, &enablePoliciesRoute, func(item *nbdb.LogicalRouterStaticRoute) bool {
				return item.IPPrefix == enablePoliciesRoute.IPPrefix && item.Nexthop == enablePoliciesRoute.Nexthop && item.Policy != nil && *item.Policy == *enablePoliciesRoute.Policy
			}); err != nil {
				return fmt.Errorf("failed adding static route to enable policy at interconnect: %v", err)
			}

		}

		// Policy to with low priority to route traffic to the gateway
		ipFamily := utilnet.IPFamilyOfCIDR(podIP)
		nodeGRAddress, err := util.MatchFirstIPNetFamily(ipFamily == utilnet.IPv6, lrpAddresses)
		if err != nil {
			return err
		}

		// adds a policy so that a migrated pods egress traffic
		// will be routed to the local GR where it now resides
		match := fmt.Sprintf("ip%s.src == %s", ipFamily, podAddress)
		egressPolicy := nbdb.LogicalRouterPolicy{
			Match:    match,
			Action:   nbdb.LogicalRouterPolicyActionReroute,
			Nexthops: []string{nodeGRAddress.IP.String()},
			Priority: types.EgressLiveMigrationReroutePiority,
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

// ensureRemoteZonePodAddressesToNodeRoute will add static routes when live
// migrated pod belongs to remote zone to send traffic over transwitch switch
// port of the node where the pod is running:
//   - A dst-ip with live migrated pod ip as prefix and nexthop the pod's
//     current node transit switch port.
func (oc *DefaultNetworkController) ensureRemoteZonePodAddressesToNodeRoute(pod *kapi.Pod) error {
	// DHCPOptions are only needed at the node is running the VM
	// at that's the local zone node not the remote zone
	if err := oc.deleteDHCPOptions(pod); err != nil {
		return err
	}
	if err := oc.deleteRoutingForMigratedPod(pod); err != nil {
		return err
	}

	switchNames, err := oc.getSwitchNames(pod)
	if err != nil {
		return fmt.Errorf("failed configuring remote pod routing when getting switch current and original name: %v", err)
	}

	if switchNames.Current == switchNames.Original {
		return nil
	}

	podAnnotation, err := util.UnmarshalPodAnnotation(pod.Annotations, types.DefaultNetworkName)
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
	isMigratedSourcePodStale, err := kubevirt.IsMigratedSourcePodStale(oc.watchFactory, pod)
	if err != nil {
		return err
	}
	if util.PodWantsHostNetwork(pod) || !kubevirt.IsPodLiveMigratable(pod) || isMigratedSourcePodStale {
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
