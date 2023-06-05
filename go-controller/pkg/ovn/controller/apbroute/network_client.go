package apbroute

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	ktypes "k8s.io/apimachinery/pkg/types"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/libovsdb/ovsdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	adminpolicybasedroutelisters "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/adminpolicybasedroute/v1/apis/listers/adminpolicybasedroute/v1"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	addressset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/address_set"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

type networkClient interface {
	deleteGatewayIPs(namespaceName string, toBeDeletedGWIPs, toBeKept sets.Set[string]) error
	addGatewayIPs(pod *v1.Pod, egress gatewayInfoList) error
}

type northBoundClient struct {
	routeLister adminpolicybasedroutelisters.AdminPolicyBasedExternalRouteLister
	nodeLister  corev1listers.NodeLister
	// NorthBound client interface
	nbClient libovsdbclient.Client

	// An address set factory that creates address sets
	addressSetFactory addressset.AddressSetFactory
	externalGWCache   map[ktypes.NamespacedName]*ExternalRouteInfo
	exGWCacheMutex    *sync.RWMutex
}

type conntrackClient struct {
	podLister corev1listers.PodLister
}

func (nb *northBoundClient) findLogicalRouterStaticRoutesWithPredicate(p func(item *nbdb.LogicalRouterStaticRoute) bool) ([]*nbdb.LogicalRouterStaticRoute, error) {
	return libovsdbops.FindLogicalRouterStaticRoutesWithPredicate(nb.nbClient, p)
}
func (nb *northBoundClient) deleteLogicalRouterStaticRoutes(routerName string, lrsrs ...*nbdb.LogicalRouterStaticRoute) error {
	return libovsdbops.DeleteLogicalRouterStaticRoutes(nb.nbClient, routerName, lrsrs...)
}

func (nb *northBoundClient) findLogicalRoutersWithPredicate(p func(item *nbdb.LogicalRouter) bool) ([]*nbdb.LogicalRouter, error) {
	return libovsdbops.FindLogicalRoutersWithPredicate(nb.nbClient, p)
}

// delAllHybridRoutePolicies deletes all the 501 hybrid-route-policies that
// force pod egress traffic to be rerouted to a gateway router for local gateway mode.
// Called when migrating to SGW from LGW.
func (nb *northBoundClient) delAllHybridRoutePolicies() error {
	// nuke all the policies
	policyPred := func(item *nbdb.LogicalRouterPolicy) bool {
		return item.Priority == types.HybridOverlayReroutePriority
	}
	err := libovsdbops.DeleteLogicalRouterPoliciesWithPredicate(nb.nbClient, types.OVNClusterRouter, policyPred)
	if err != nil {
		return fmt.Errorf("error deleting hybrid route policies on %s: %v", types.OVNClusterRouter, err)
	}

	// nuke all the address-sets.
	// if we fail to remove LRP's above, we don't attempt to remove ASes due to dependency constraints.
	predicateIDs := libovsdbops.NewDbObjectIDs(libovsdbops.AddressSetHybridNodeRoute, controllerName, nil)
	asPred := libovsdbops.GetPredicate[*nbdb.AddressSet](predicateIDs, nil)
	err = libovsdbops.DeleteAddressSetsWithPredicate(nb.nbClient, asPred)
	if err != nil {
		return fmt.Errorf("failed to remove hybrid route address sets: %v", err)
	}

	return nil
}

// delAllLegacyHybridRoutePolicies deletes all the 501 hybrid-route-policies that
// force pod egress traffic to be rerouted to a gateway router for local gateway mode.
// New hybrid route matches on address set, while legacy matches just on pod IP
func (nb *northBoundClient) delAllLegacyHybridRoutePolicies() error {
	// nuke all the policies
	p := func(item *nbdb.LogicalRouterPolicy) bool {
		if item.Priority != types.HybridOverlayReroutePriority {
			return false
		}
		if isNewVer, err := regexp.MatchString(`src\s*==\s*\$`, item.Match); err == nil && isNewVer {
			return false
		}
		return true
	}
	err := libovsdbops.DeleteLogicalRouterPoliciesWithPredicate(nb.nbClient, types.OVNClusterRouter, p)
	if err != nil {
		return fmt.Errorf("error deleting legacy hybrid route policies on %s: %v", types.OVNClusterRouter, err)
	}
	return nil
}

// deleteGatewayIPs handles deleting static routes for pods on a specific GR.
// If a set of gateways is given, only routes for that gateway are deleted. If no gateways
// are given, all routes for the namespace are deleted.
func (nb *northBoundClient) deleteGatewayIPs(namespace string, toBeDeletedGWIPs, _ sets.Set[string]) error {
	for _, routeInfo := range nb.getRouteInfosForNamespace(namespace) {
		routeInfo.Lock()
		if routeInfo.Deleted {
			routeInfo.Unlock()
			continue
		}
		for podIP, routes := range routeInfo.PodExternalRoutes {
			for gw, gr := range routes {
				if toBeDeletedGWIPs.Has(gw) {
					// we cannot delete an external gateway IP from the north bound if it's also being provided by an external gateway annotation or if it is also
					// defined by a coexisting policy in the same namespace
					if err := nb.deletePodGWRoute(routeInfo, podIP, gw, gr); err != nil {
						// if we encounter error while deleting routes for one pod; we return and don't try subsequent pods
						routeInfo.Unlock()
						return fmt.Errorf("delete pod GW route failed: %w", err)
					}
					delete(routes, gw)
				}
			}
		}
		routeInfo.Unlock()
	}
	return nil
}

// getRouteInfosForNamespace returns all routeInfos for a specific namespace
func (nb *northBoundClient) getRouteInfosForNamespace(namespace string) []*ExternalRouteInfo {
	nb.exGWCacheMutex.RLock()
	defer nb.exGWCacheMutex.RUnlock()

	routes := make([]*ExternalRouteInfo, 0)
	for namespacedName, routeInfo := range nb.externalGWCache {
		if namespacedName.Namespace == namespace {
			routes = append(routes, routeInfo)
		}
	}

	return routes
}

func (nb *northBoundClient) addGatewayIPs(pod *v1.Pod, egress gatewayInfoList) error {
	if util.PodCompleted(pod) || util.PodWantsHostNetwork(pod) {
		return nil
	}
	podIPs := make([]*net.IPNet, 0)
	for _, podIP := range pod.Status.PodIPs {
		podIPStr := utilnet.ParseIPSloppy(podIP.IP).String()
		cidr := podIPStr + util.GetIPFullMask(podIPStr)
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("failed to parse CIDR: %s, error: %v", cidr, err)
		}
		podIPs = append(podIPs, ipNet)
	}
	if len(podIPs) == 0 {
		klog.Warningf("Will not add gateway routes pod %s/%s. IPs not found!", pod.Namespace, pod.Name)
		return nil
	}
	if config.Gateway.DisableSNATMultipleGWs {
		// delete all perPodSNATs (if this pod was controlled by egressIP controller, it will stop working since
		// a pod cannot be used for multiple-external-gateways and egressIPs at the same time)
		if err := nb.deletePodSNAT(pod.Spec.NodeName, []*net.IPNet{}, podIPs); err != nil {
			klog.Error(err.Error())
		}
	}
	podNsName := ktypes.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}
	return nb.addGWRoutesForPod(egress, podIPs, podNsName, pod.Spec.NodeName)
}

// deletePodSNAT removes per pod SNAT rules towards the nodeIP that are applied to the GR where the pod resides
// if allSNATs flag is set, then all the SNATs (including against egressIPs if any) for that pod will be deleted
// used when disableSNATMultipleGWs=true
func (nb *northBoundClient) deletePodSNAT(nodeName string, extIPs, podIPNets []*net.IPNet) error {
	nats, err := buildPodSNAT(extIPs, podIPNets)
	if err != nil {
		return err
	}
	logicalRouter := nbdb.LogicalRouter{
		Name: types.GWRouterPrefix + nodeName,
	}
	err = libovsdbops.DeleteNATs(nb.nbClient, &logicalRouter, nats...)
	if err != nil {
		return fmt.Errorf("failed to delete SNAT rule for pod on gateway router %s: %v", logicalRouter.Name, err)
	}
	return nil
}

// addEgressGwRoutesForPod handles adding all routes to gateways for a pod on a specific GR
func (nb *northBoundClient) addGWRoutesForPod(gateways []*gatewayInfo, podIfAddrs []*net.IPNet, podNsName ktypes.NamespacedName, node string) error {
	gr := util.GetGatewayRouterFromNode(node)

	routesAdded := 0
	portPrefix, err := nb.extSwitchPrefix(node)
	if err != nil {
		klog.Infof("Failed to find ext switch prefix for %s %v", node, err)
		return err
	}

	port := portPrefix + types.GWRouterToExtSwitchPrefix + gr
	routeInfo, err := nb.ensureRouteInfoLocked(podNsName)
	if err != nil {
		return fmt.Errorf("failed to ensure routeInfo for %s, error: %v", podNsName, err)
	}
	defer routeInfo.Unlock()
	for _, podIPNet := range podIfAddrs {
		for _, gateway := range gateways {
			// TODO (trozet): use the go bindings here and batch commands
			// validate the ip and gateway belong to the same address family
			gws, err := util.MatchAllIPStringFamily(utilnet.IsIPv6(podIPNet.IP), gateway.gws.UnsortedList())
			if err != nil {
				klog.Warningf("Address families for the pod address %s and gateway %s did not match", podIPNet.IP.String(), gateway.gws)
				continue
			}
			podIP := podIPNet.IP.String()
			for _, gw := range gws {
				// if route was already programmed, skip it
				if foundGR, ok := routeInfo.PodExternalRoutes[podIP][gw]; ok && foundGR == gr {
					routesAdded++
					continue
				}
				mask := util.GetIPFullMask(podIP)
				if err := nb.createOrUpdateBFDStaticRoute(gateway.bfdEnabled, gw, podIP, gr, port, mask); err != nil {
					return err
				}
				if routeInfo.PodExternalRoutes[podIP] == nil {
					routeInfo.PodExternalRoutes[podIP] = make(map[string]string)
				}
				routeInfo.PodExternalRoutes[podIP][gw] = gr
				routesAdded++
				if len(routeInfo.PodExternalRoutes[podIP]) == 1 {
					if err := nb.addHybridRoutePolicyForPod(podIPNet.IP, node); err != nil {
						return err
					}
				}
			}
		}
	}
	// if no routes are added return an error
	if routesAdded < 1 {
		return fmt.Errorf("gateway specified for namespace %s with gateway addresses %v but no valid routes exist for pod: %s",
			podNsName.Namespace, podIfAddrs, podNsName.Name)
	}
	return nil
}

// AddHybridRoutePolicyForPod handles adding a higher priority allow policy to allow traffic to be routed normally
// by ecmp routes
func (nb *northBoundClient) addHybridRoutePolicyForPod(podIP net.IP, node string) error {
	if config.Gateway.Mode == config.GatewayModeLocal {
		// Add podIP to the node's address_set.
		asIndex := getHybridRouteAddrSetDbIDs(node, controllerName)
		as, err := nb.addressSetFactory.EnsureAddressSet(asIndex)
		if err != nil {
			return fmt.Errorf("cannot ensure that addressSet for node %s exists %v", node, err)
		}
		err = as.AddIPs([]net.IP{(podIP)})
		if err != nil {
			return fmt.Errorf("unable to add PodIP %s: to the address set %s, err: %v", podIP.String(), node, err)
		}

		// add allow policy to bypass lr-policy in GR
		ipv4HashedAS, ipv6HashedAS := as.GetASHashNames()
		var l3Prefix string
		var matchSrcAS string
		isIPv6 := utilnet.IsIPv6(podIP)
		if isIPv6 {
			l3Prefix = "ip6"
			matchSrcAS = ipv6HashedAS
		} else {
			l3Prefix = "ip4"
			matchSrcAS = ipv4HashedAS
		}

		// get the GR to join switch ip address
		grJoinIfAddrs, err := util.GetLRPAddrs(nb.nbClient, types.GWRouterToJoinSwitchPrefix+types.GWRouterPrefix+node)
		if err != nil {
			return fmt.Errorf("unable to find IP address for node: %s, %s port, err: %v", node, types.GWRouterToJoinSwitchPrefix, err)
		}
		grJoinIfAddr, err := util.MatchFirstIPNetFamily(utilnet.IsIPv6(podIP), grJoinIfAddrs)
		if err != nil {
			return fmt.Errorf("failed to match gateway router join interface IPs: %v, err: %v", grJoinIfAddr, err)
		}

		var matchDst string
		var clusterL3Prefix string
		for _, clusterSubnet := range config.Default.ClusterSubnets {
			if utilnet.IsIPv6CIDR(clusterSubnet.CIDR) {
				clusterL3Prefix = "ip6"
			} else {
				clusterL3Prefix = "ip4"
			}
			if l3Prefix != clusterL3Prefix {
				continue
			}
			matchDst += fmt.Sprintf(" && %s.dst != %s", clusterL3Prefix, clusterSubnet.CIDR)
		}

		// traffic destined outside of cluster subnet go to GR
		matchStr := fmt.Sprintf(`inport == "%s%s" && %s.src == $%s`, types.RouterToSwitchPrefix, node, l3Prefix, matchSrcAS)
		matchStr += matchDst

		logicalRouterPolicy := nbdb.LogicalRouterPolicy{
			Priority: types.HybridOverlayReroutePriority,
			Action:   nbdb.LogicalRouterPolicyActionReroute,
			Nexthops: []string{grJoinIfAddr.IP.String()},
			Match:    matchStr,
		}
		p := func(item *nbdb.LogicalRouterPolicy) bool {
			return item.Priority == logicalRouterPolicy.Priority && strings.Contains(item.Match, matchSrcAS)
		}
		err = libovsdbops.CreateOrUpdateLogicalRouterPolicyWithPredicate(nb.nbClient, types.OVNClusterRouter,
			&logicalRouterPolicy, p, &logicalRouterPolicy.Nexthops, &logicalRouterPolicy.Match, &logicalRouterPolicy.Action)
		if err != nil {
			return fmt.Errorf("failed to add policy route %+v to %s: %v", logicalRouterPolicy, types.OVNClusterRouter, err)
		}
	}
	return nil
}

func (nb *northBoundClient) createOrUpdateBFDStaticRoute(bfdEnabled bool, gw string, podIP, gr, port, mask string) error {
	lrsr := nbdb.LogicalRouterStaticRoute{
		Policy: &nbdb.LogicalRouterStaticRoutePolicySrcIP,
		Options: map[string]string{
			"ecmp_symmetric_reply": "true",
		},
		Nexthop:    gw,
		IPPrefix:   podIP + mask,
		OutputPort: &port,
	}

	ops := []ovsdb.Operation{}
	var err error
	if bfdEnabled {
		bfd := nbdb.BFD{
			DstIP:       gw,
			LogicalPort: port,
		}
		ops, err = libovsdbops.CreateOrUpdateBFDOps(nb.nbClient, ops, &bfd)
		if err != nil {
			return fmt.Errorf("error creating or updating BFD %+v: %v", bfd, err)
		}
		lrsr.BFD = &bfd.UUID
	}

	p := func(item *nbdb.LogicalRouterStaticRoute) bool {
		return item.IPPrefix == lrsr.IPPrefix &&
			item.Nexthop == lrsr.Nexthop &&
			item.OutputPort != nil &&
			*item.OutputPort == *lrsr.OutputPort &&
			item.Policy == lrsr.Policy
	}
	ops, err = libovsdbops.CreateOrUpdateLogicalRouterStaticRoutesWithPredicateOps(nb.nbClient, ops, gr, &lrsr, p,
		&lrsr.Options)
	if err != nil {
		return fmt.Errorf("error creating or updating static route %+v on router %s: %v", lrsr, gr, err)
	}

	_, err = libovsdbops.TransactAndCheck(nb.nbClient, ops)
	if err != nil {
		return fmt.Errorf("error transacting static route: %v", err)
	}

	return nil
}

func (nb *northBoundClient) updateExternalGWInfoCacheForPodIPWithGatewayIP(podIP, gwIP, nodeName string, bfdEnabled bool, namespacedName ktypes.NamespacedName) error {
	gr := util.GetGatewayRouterFromNode(nodeName)
	routeInfo, err := nb.ensureRouteInfoLocked(namespacedName)
	if err != nil {
		return fmt.Errorf("failed to ensure routeInfo for %s, error: %v", namespacedName.Name, err)
	}
	defer routeInfo.Unlock()
	// if route was already programmed, skip it
	if foundGR, ok := routeInfo.PodExternalRoutes[podIP][gwIP]; ok && foundGR == gr {
		return nil
	}
	mask := util.GetIPFullMask(podIP)

	portPrefix, err := nb.extSwitchPrefix(nodeName)
	if err != nil {
		klog.Infof("Failed to find ext switch prefix for %s %v", nodeName, err)
		return err
	}
	if bfdEnabled {
		port := portPrefix + types.GWRouterToExtSwitchPrefix + gr
		// update the BFD static route just in case it has changed
		if err := nb.createOrUpdateBFDStaticRoute(bfdEnabled, gwIP, podIP, gr, port, mask); err != nil {
			return err
		}
	} else {
		_, err := nb.lookupBFDEntry(gwIP, gr, portPrefix)
		if err != nil {
			err = nb.cleanUpBFDEntry(gwIP, gr, portPrefix)
			if err != nil {
				return err
			}
		}
	}

	if routeInfo.PodExternalRoutes[podIP] == nil {
		routeInfo.PodExternalRoutes[podIP] = make(map[string]string)
	}
	routeInfo.PodExternalRoutes[podIP][gwIP] = gr

	return nil
}

// ensureRouteInfoLocked either gets the current routeInfo in the cache with a lock, or creates+locks a new one if missing
func (nb *northBoundClient) ensureRouteInfoLocked(podName ktypes.NamespacedName) (*ExternalRouteInfo, error) {
	// We don't want to hold the cache lock while we try to lock the routeInfo (unless we are creating it, then we know
	// no one else is using it). This could lead to dead lock. Therefore the steps here are:
	// 1. Get the cache lock, try to find the routeInfo
	// 2. If routeInfo existed, release the cache lock
	// 3. If routeInfo did not exist, safe to hold the cache lock while we create the new routeInfo
	nb.exGWCacheMutex.Lock()
	routeInfo, ok := nb.externalGWCache[podName]
	if !ok {
		routeInfo = &ExternalRouteInfo{
			PodExternalRoutes: make(map[string]map[string]string),
			PodName:           podName,
		}
		// we are creating routeInfo and going to set it in podExternalRoutes map
		// so safe to hold the lock while we create and add it
		defer nb.exGWCacheMutex.Unlock()
		nb.externalGWCache[podName] = routeInfo
	} else {
		// if we found an existing routeInfo, do not hold the cache lock
		// while waiting for routeInfo to Lock
		nb.exGWCacheMutex.Unlock()
	}

	// 4. Now lock the routeInfo
	routeInfo.Lock()

	// 5. If routeInfo was deleted between releasing the cache lock and grabbing
	// the routeInfo lock, return an error so the caller doesn't use it and
	// retries the operation later
	if routeInfo.Deleted {
		routeInfo.Unlock()
		return nil, fmt.Errorf("routeInfo for pod %s, was altered during ensure route info", podName)
	}

	return routeInfo, nil
}

func (nb *northBoundClient) deletePodGWRoute(routeInfo *ExternalRouteInfo, podIP, gw, gr string) error {
	if utilnet.IsIPv6String(gw) != utilnet.IsIPv6String(podIP) {
		return nil
	}

	mask := util.GetIPFullMask(podIP)
	if err := nb.deleteLogicalRouterStaticRoute(podIP, mask, gw, gr); err != nil {
		return fmt.Errorf("unable to delete pod %s ECMP route to GR %s, GW: %s: %w",
			routeInfo.PodName, gr, gw, err)
	}

	node := util.GetWorkerFromGatewayRouter(gr)
	// The gw is deleted from the routes cache after this func is called, length 1
	// means it is the last gw for the pod and the hybrid route policy should be deleted.
	if entry := routeInfo.PodExternalRoutes[podIP]; len(entry) == 1 {
		if err := nb.delHybridRoutePolicyForPod(net.ParseIP(podIP), node); err != nil {
			return fmt.Errorf("unable to delete hybrid route policy for pod %s: err: %v", routeInfo.PodName, err)
		}
	}

	portPrefix, err := nb.extSwitchPrefix(node)
	if err != nil {
		return err
	}
	return nb.cleanUpBFDEntry(gw, gr, portPrefix)
}

// cleanUpBFDEntry checks if the BFD table entry related to the associated
// gw router / port / gateway ip is referenced by other routing rules, and if
// not removes the entry to avoid having dangling BFD entries.
func (nb *northBoundClient) cleanUpBFDEntry(gatewayIP, gatewayRouter, prefix string) error {
	portName := prefix + types.GWRouterToExtSwitchPrefix + gatewayRouter
	p := func(item *nbdb.LogicalRouterStaticRoute) bool {
		if item.OutputPort != nil && *item.OutputPort == portName && item.Nexthop == gatewayIP && item.BFD != nil && *item.BFD != "" {
			return true
		}
		return false
	}
	logicalRouterStaticRoutes, err := libovsdbops.FindLogicalRouterStaticRoutesWithPredicate(nb.nbClient, p)
	if err != nil {
		return fmt.Errorf("cleanUpBFDEntry failed to list routes for %s: %w", portName, err)
	}
	if len(logicalRouterStaticRoutes) > 0 {
		return nil
	}

	bfd := nbdb.BFD{
		LogicalPort: portName,
		DstIP:       gatewayIP,
	}
	err = libovsdbops.DeleteBFDs(nb.nbClient, &bfd)
	if err != nil {
		return fmt.Errorf("error deleting BFD %+v: %v", bfd, err)
	}

	return nil
}

func (nb *northBoundClient) deleteLogicalRouterStaticRoute(podIP, mask, gw, gr string) error {
	p := func(item *nbdb.LogicalRouterStaticRoute) bool {
		return item.Policy != nil &&
			*item.Policy == nbdb.LogicalRouterStaticRoutePolicySrcIP &&
			item.IPPrefix == podIP+mask &&
			item.Nexthop == gw
	}
	err := libovsdbops.DeleteLogicalRouterStaticRoutesWithPredicate(nb.nbClient, gr, p)
	if err != nil {
		return fmt.Errorf("error deleting static route from router %s: %v", gr, err)
	}

	return nil
}

// DelHybridRoutePolicyForPod handles deleting a logical route policy that
// forces pod egress traffic to be rerouted to a gateway router for local gateway mode.
func (nb *northBoundClient) delHybridRoutePolicyForPod(podIP net.IP, node string) error {
	if config.Gateway.Mode == config.GatewayModeLocal {
		// Delete podIP from the node's address_set.
		asIndex := getHybridRouteAddrSetDbIDs(node, controllerName)
		as, err := nb.addressSetFactory.EnsureAddressSet(asIndex)
		if err != nil {
			return fmt.Errorf("cannot Ensure that addressSet for node %s exists %v", node, err)
		}
		err = as.DeleteIPs([]net.IP{(podIP)})
		if err != nil {
			return fmt.Errorf("unable to remove PodIP %s: to the address set %s, err: %v", podIP.String(), node, err)
		}

		// delete hybrid policy to bypass lr-policy in GR, only if there are zero pods on this node.
		ipv4HashedAS, ipv6HashedAS := as.GetASHashNames()
		ipv4PodIPs, ipv6PodIPs := as.GetIPs()
		deletePolicy := false
		var l3Prefix string
		var matchSrcAS string
		if utilnet.IsIPv6(podIP) {
			l3Prefix = "ip6"
			if len(ipv6PodIPs) == 0 {
				deletePolicy = true
			}
			matchSrcAS = ipv6HashedAS
		} else {
			l3Prefix = "ip4"
			if len(ipv4PodIPs) == 0 {
				deletePolicy = true
			}
			matchSrcAS = ipv4HashedAS
		}
		if deletePolicy {
			var matchDst string
			var clusterL3Prefix string
			for _, clusterSubnet := range config.Default.ClusterSubnets {
				if utilnet.IsIPv6CIDR(clusterSubnet.CIDR) {
					clusterL3Prefix = "ip6"
				} else {
					clusterL3Prefix = "ip4"
				}
				if l3Prefix != clusterL3Prefix {
					continue
				}
				matchDst += fmt.Sprintf(" && %s.dst != %s", l3Prefix, clusterSubnet.CIDR)
			}
			matchStr := fmt.Sprintf(`inport == "%s%s" && %s.src == $%s`, types.RouterToSwitchPrefix, node, l3Prefix, matchSrcAS)
			matchStr += matchDst

			p := func(item *nbdb.LogicalRouterPolicy) bool {
				return item.Priority == types.HybridOverlayReroutePriority && item.Match == matchStr
			}
			err := libovsdbops.DeleteLogicalRouterPoliciesWithPredicate(nb.nbClient, types.OVNClusterRouter, p)
			if err != nil {
				return fmt.Errorf("error deleting policy %s on router %s: %v", matchStr, types.OVNClusterRouter, err)
			}
		}
		if len(ipv4PodIPs) == 0 && len(ipv6PodIPs) == 0 {
			// delete address set.
			err := as.Destroy()
			if err != nil {
				return fmt.Errorf("failed to remove address set: %s, on: %s, err: %v",
					as.GetName(), node, err)
			}
		}
	}
	return nil
}

// extSwitchPrefix returns the prefix of the external switch to use for
// external gateway routes. In case no second bridge is configured, we
// use the default one and the prefix is empty.
func (nb *northBoundClient) extSwitchPrefix(nodeName string) (string, error) {
	node, err := nb.nodeLister.Get(nodeName)
	if err != nil {
		return "", errors.Wrapf(err, "extSwitchPrefix: failed to find node %s", nodeName)
	}
	l3GatewayConfig, err := util.ParseNodeL3GatewayAnnotation(node)
	if err != nil {
		return "", errors.Wrapf(err, "extSwitchPrefix: failed to parse l3 gateway annotation for node %s", nodeName)
	}

	if l3GatewayConfig.EgressGWInterfaceID != "" {
		return types.EgressGWSwitchPrefix, nil
	}
	return "", nil
}

func (nb *northBoundClient) lookupBFDEntry(gatewayIP, gatewayRouter, prefix string) (*nbdb.BFD, error) {
	portName := prefix + types.GWRouterToExtSwitchPrefix + gatewayRouter
	bfd := nbdb.BFD{
		LogicalPort: portName,
		DstIP:       gatewayIP,
	}
	found, err := libovsdbops.LookupBFD(nb.nbClient, &bfd)
	if err != nil {
		klog.Warningf("Failed to lookup BFD for gateway IP %s, gateway router %s and prefix %s", gatewayIP, gatewayRouter, prefix)
		return nil, err
	}

	return found, nil
}

// buildPodSNAT builds per pod SNAT rules towards the nodeIP that are applied to the GR where the pod resides
// if allSNATs flag is set, then all the SNATs (including against egressIPs if any) for that pod will be returned
func buildPodSNAT(extIPs, podIPNets []*net.IPNet) ([]*nbdb.NAT, error) {
	nats := make([]*nbdb.NAT, 0, len(extIPs)*len(podIPNets))
	var nat *nbdb.NAT

	for _, podIPNet := range podIPNets {
		podIP := podIPNet.IP.String()
		mask := util.GetIPFullMask(podIP)
		_, fullMaskPodNet, err := net.ParseCIDR(podIP + mask)
		if err != nil {
			return nil, fmt.Errorf("invalid IP: %s and mask: %s combination, error: %v", podIP, mask, err)
		}
		if len(extIPs) == 0 {
			nat = libovsdbops.BuildSNAT(nil, fullMaskPodNet, "", nil)
		} else {
			for _, gwIPNet := range extIPs {
				gwIP := gwIPNet.IP.String()
				if utilnet.IsIPv6String(gwIP) != utilnet.IsIPv6String(podIP) {
					continue
				}
				nat = libovsdbops.BuildSNAT(&gwIPNet.IP, fullMaskPodNet, "", nil)
			}
		}
		nats = append(nats, nat)
	}
	return nats, nil
}

func getHybridRouteAddrSetDbIDs(nodeName, controller string) *libovsdbops.DbObjectIDs {
	return libovsdbops.NewDbObjectIDs(libovsdbops.AddressSetHybridNodeRoute, controller,
		map[libovsdbops.ExternalIDKey]string{
			// there is only 1 address set of this type per node
			libovsdbops.ObjectNameKey: nodeName,
		})
}

func (c *conntrackClient) deleteGatewayIPs(namespaceName string, _, toBeKept sets.Set[string]) error {
	// loop through all the IPs on the annotations; ARP for their MACs and form an allowlist
	var wg sync.WaitGroup
	wg.Add(len(toBeKept))
	validMACs := sync.Map{}
	klog.Infof("Keeping conntrack entries in namespace %s with gateway IPs %s", namespaceName, strings.Join(sets.List(toBeKept), ","))
	for gwIP := range toBeKept {
		go func(gwIP string) {
			defer wg.Done()
			if len(gwIP) > 0 && !utilnet.IsIPv6String(gwIP) {
				// TODO: Add support for IPv6 external gateways
				if hwAddr, err := util.GetMACAddressFromARP(net.ParseIP(gwIP)); err != nil {
					klog.Errorf("Failed to lookup hardware address for gatewayIP %s: %v", gwIP, err)
				} else if len(hwAddr) > 0 {
					// we need to reverse the mac before passing it to the conntrack filter since OVN saves the MAC in the following format
					// +------------------------------------------------------------ +
					// | 128 ...  112 ... 96 ... 80 ... 64 ... 48 ... 32 ... 16 ... 0|
					// +------------------+-------+--------------------+-------------|
					// |                  | UNUSED|    MAC ADDRESS     |   UNUSED    |
					// +------------------+-------+--------------------+-------------+
					for i, j := 0, len(hwAddr)-1; i < j; i, j = i+1, j-1 {
						hwAddr[i], hwAddr[j] = hwAddr[j], hwAddr[i]
					}
					validMACs.Store(gwIP, []byte(hwAddr))
				}
			}
		}(gwIP)
	}
	wg.Wait()

	validNextHopMACs := [][]byte{}
	validMACs.Range(func(key interface{}, value interface{}) bool {
		validNextHopMACs = append(validNextHopMACs, value.([]byte))
		return true
	})
	// Handle corner case where there are 0 IPs on the annotations OR none of the ARPs were successful; i.e allowMACList={empty}.
	// This means we *need to* pass a label > 128 bits that will not match on any conntrack entry labels for these pods.
	// That way any remaining entries with labels having MACs set will get purged.
	if len(validNextHopMACs) == 0 {
		validNextHopMACs = append(validNextHopMACs, []byte("does-not-contain-anything"))
	}

	pods, err := c.podLister.List(labels.Everything())
	if err != nil {
		return fmt.Errorf("unable to get pods from informer: %v", err)
	}

	var errors []error
	for _, pod := range pods {
		pod := pod
		podIPs, err := util.GetPodIPsOfNetwork(pod, &util.DefaultNetInfo{})
		if err != nil {
			errors = append(errors, fmt.Errorf("unable to fetch IP for pod %s/%s: %v", pod.Namespace, pod.Name, err))
		}
		for _, podIP := range podIPs { // flush conntrack only for UDP
			// for this pod, we check if the conntrack entry has a label that is not in the provided allowlist of MACs
			// only caveat here is we assume egressGW served pods shouldn't have conntrack entries with other labels set
			err := util.DeleteConntrack(podIP.String(), 0, v1.ProtocolUDP, netlink.ConntrackOrigDstIP, validNextHopMACs)
			if err != nil {
				errors = append(errors, fmt.Errorf("failed to delete conntrack entry for pod with IP %s: %v", podIP.String(), err))
				continue
			}
		}
	}
	return kerrors.NewAggregate(errors)
}

// addGatewayIPs is a NOP (no operation) in the conntrack client as it does not add any entry to the conntrack table.
func (c *conntrackClient) addGatewayIPs(pod *v1.Pod, egress gatewayInfoList) error {
	return nil
}
