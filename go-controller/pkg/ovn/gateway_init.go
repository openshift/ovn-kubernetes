package ovn

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	libovsdbclient "github.com/ovn-org/libovsdb/client"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	libovsdbops "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/metrics"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/node"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/gateway"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

// cleanupStalePodSNATs removes SNATs against nodeIP for the given node if the SNAT.logicalIP isn't an active podIP on this node
// We don't have to worry about missing SNATs that should be added because addLogicalPort takes care of this for all pods
// when RequestRetryObjs is called for each node add.
// This is executed only when disableSNATMultipleGateways = true
// SNATs configured for the join subnet are ignored.
//
// NOTE: On startup libovsdb adds back all the pods and this should normally update all existing SNATs
// accordingly. Due to a stale egressIP cache bug https://issues.redhat.com/browse/OCPBUGS-1520 we ended up adding
// wrong pod->nodeSNATs which won't get cleared up unless explicitly deleted.
// NOTE2: egressIP SNATs are synced in EIP controller.
// TODO (tssurya): Add support cleaning up even if disableSNATMultipleGWs=false, we'd need to remove the perPod
// SNATs in case someone switches between these modes. See https://github.com/ovn-org/ovn-kubernetes/issues/3232
func (oc *DefaultNetworkController) cleanupStalePodSNATs(nodeName string, nodeIPs []*net.IPNet) error {
	if !config.Gateway.DisableSNATMultipleGWs {
		return nil
	}
	pods, err := oc.kube.GetPods(metav1.NamespaceAll, metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("spec.nodeName", nodeName).String(),
	})
	if err != nil {
		return fmt.Errorf("unable to list existing pods on node: %s, %w",
			nodeName, err)
	}
	gatewayRouter := nbdb.LogicalRouter{
		Name: oc.GetNetworkScopedGWRouterName(nodeName),
	}
	routerNats, err := libovsdbops.GetRouterNATs(oc.nbClient, &gatewayRouter)
	if err != nil && errors.Is(err, libovsdbclient.ErrNotFound) {
		return fmt.Errorf("unable to get NAT entries for router %s on node %s: %w", gatewayRouter.Name, nodeName, err)
	}
	podIPsOnNode := sets.NewString() // collects all podIPs on node
	for _, pod := range pods {
		pod := *pod
		if !util.PodScheduled(&pod) { //if the pod is not scheduled we should not remove the nat
			continue
		}
		if util.PodCompleted(&pod) {
			collidingPod, err := oc.findPodWithIPAddresses([]net.IP{utilnet.ParseIPSloppy(pod.Status.PodIP)}, "") //even if a pod is completed we should still delete the nat if the ip is not in use anymore
			if err != nil {
				return fmt.Errorf("lookup for pods with same ip as %s %s failed: %w", pod.Namespace, pod.Name, err)
			}
			if collidingPod != nil { //if the ip is in use we should not remove the nat
				continue
			}
		}
		podIPs, err := util.GetPodIPsOfNetwork(&pod, oc.NetInfo)
		if err != nil && errors.Is(err, util.ErrNoPodIPFound) {
			// It is possible that the pod is scheduled during this time, but the LSP add or
			// IP Allocation has not happened and it is waiting for the WatchPods to start
			// after WatchNodes completes (This function is called during syncNodes). So since
			// the pod doesn't have any IPs, there is no SNAT here to keep for this pod so we skip
			// this pod from processing and move onto the next one.
			klog.Warningf("Unable to fetch podIPs for pod %s/%s: %v", pod.Namespace, pod.Name, err)
			continue // no-op
		} else if err != nil {
			return fmt.Errorf("unable to fetch podIPs for pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}
		for _, podIP := range podIPs {
			podIPsOnNode.Insert(podIP.String())
		}
	}
	natsToDelete := []*nbdb.NAT{}
	for _, routerNat := range routerNats {
		routerNat := routerNat
		if routerNat.Type != nbdb.NATTypeSNAT {
			continue
		}
		for _, nodeIP := range nodeIPs {
			logicalIP := net.ParseIP(routerNat.LogicalIP)
			if routerNat.ExternalIP == nodeIP.IP.String() && !config.ContainsJoinIP(logicalIP) && !podIPsOnNode.Has(routerNat.LogicalIP) {
				natsToDelete = append(natsToDelete, routerNat)
			}
		}
	}
	if len(natsToDelete) > 0 {
		err := libovsdbops.DeleteNATs(oc.nbClient, &gatewayRouter, natsToDelete...)
		if err != nil {
			return fmt.Errorf("unable to delete NATs %+v from node %s: %w", natsToDelete, nodeName, err)
		}
	}
	return nil
}

// gatewayInit creates a gateway router for the local chassis.
// enableGatewayMTU enables options:gateway_mtu for gateway routers.
func (oc *DefaultNetworkController) gatewayInit(nodeName string, clusterIPSubnet []*net.IPNet, hostSubnets []*net.IPNet,
	l3GatewayConfig *util.L3GatewayConfig, sctpSupport bool, gwLRPIfAddrs, drLRPIfAddrs []*net.IPNet,
	enableGatewayMTU bool) error {

	gwLRPIPs := make([]net.IP, 0)
	for _, gwLRPIfAddr := range gwLRPIfAddrs {
		gwLRPIPs = append(gwLRPIPs, gwLRPIfAddr.IP)
	}

	// Create a gateway router.
	gatewayRouter := oc.GetNetworkScopedGWRouterName(nodeName)
	physicalIPs := make([]string, len(l3GatewayConfig.IPAddresses))
	for i, ip := range l3GatewayConfig.IPAddresses {
		physicalIPs[i] = ip.IP.String()
	}

	logicalRouterOptions := map[string]string{
		"always_learn_from_arp_request": "false",
		"dynamic_neigh_routers":         "true",
		"chassis":                       l3GatewayConfig.ChassisID,
		"lb_force_snat_ip":              "router_ip",
		"snat-ct-zone":                  "0",
		"mac_binding_age_threshold":     types.GRMACBindingAgeThreshold,
	}
	logicalRouterExternalIDs := map[string]string{
		"physical_ip":  physicalIPs[0],
		"physical_ips": strings.Join(physicalIPs, ","),
	}

	logicalRouter := nbdb.LogicalRouter{
		Name:        gatewayRouter,
		Options:     logicalRouterOptions,
		ExternalIDs: logicalRouterExternalIDs,
		Copp:        &oc.defaultCOPPUUID,
	}

	if oc.clusterLoadBalancerGroupUUID != "" {
		logicalRouter.LoadBalancerGroup = []string{oc.clusterLoadBalancerGroupUUID}
		if l3GatewayConfig.NodePortEnable && oc.routerLoadBalancerGroupUUID != "" {
			// add routerLoadBalancerGroupUUID to the gateway router only if nodePort is enabled
			logicalRouter.LoadBalancerGroup = append(logicalRouter.LoadBalancerGroup, oc.routerLoadBalancerGroupUUID)
		}
	}

	// If l3gatewayAnnotation.IPAddresses changed, we need to update the perPodSNATs,
	// so let's save the old value before we update the router for later use
	var oldExtIPs []net.IP
	oldLogicalRouter, err := libovsdbops.GetLogicalRouter(oc.nbClient, &logicalRouter)
	if err != nil && !errors.Is(err, libovsdbclient.ErrNotFound) {
		return fmt.Errorf("failed in retrieving %s, error: %v", gatewayRouter, err)
	}

	if oldLogicalRouter != nil && oldLogicalRouter.ExternalIDs != nil {
		if physicalIPs, ok := oldLogicalRouter.ExternalIDs["physical_ips"]; ok {
			oldExternalIPs := strings.Split(physicalIPs, ",")
			oldExtIPs = make([]net.IP, len(oldExternalIPs))
			for i, oldExternalIP := range oldExternalIPs {
				cidr := oldExternalIP + util.GetIPFullMaskString(oldExternalIP)
				ip, _, err := net.ParseCIDR(cidr)
				if err != nil {
					return fmt.Errorf("invalid cidr:%s error: %v", cidr, err)
				}
				oldExtIPs[i] = ip
			}
		}
	}

	err = libovsdbops.CreateOrUpdateLogicalRouter(oc.nbClient, &logicalRouter, &logicalRouter.Options,
		&logicalRouter.ExternalIDs, &logicalRouter.LoadBalancerGroup, &logicalRouter.Copp)
	if err != nil {
		return fmt.Errorf("failed to create logical router %+v: %v", logicalRouter, err)
	}

	gwSwitchPort := types.JoinSwitchToGWRouterPrefix + gatewayRouter
	gwRouterPort := types.GWRouterToJoinSwitchPrefix + gatewayRouter

	logicalSwitchPort := nbdb.LogicalSwitchPort{
		Name:      gwSwitchPort,
		Type:      "router",
		Addresses: []string{"router"},
		Options: map[string]string{
			"router-port": gwRouterPort,
		},
	}
	sw := nbdb.LogicalSwitch{Name: oc.GetNetworkScopedJoinSwitchName()}
	err = libovsdbops.CreateOrUpdateLogicalSwitchPortsOnSwitch(oc.nbClient, &sw, &logicalSwitchPort)
	if err != nil {
		return fmt.Errorf("failed to create port %v on logical switch %q: %v", gwSwitchPort, sw.Name, err)
	}

	gwLRPMAC := util.IPAddrToHWAddr(gwLRPIPs[0])
	gwLRPNetworks := []string{}
	for _, gwLRPIfAddr := range gwLRPIfAddrs {
		gwLRPNetworks = append(gwLRPNetworks, gwLRPIfAddr.String())
	}

	var options map[string]string
	if enableGatewayMTU {
		options = map[string]string{
			"gateway_mtu": strconv.Itoa(config.Default.MTU),
		}
	}
	logicalRouterPort := nbdb.LogicalRouterPort{
		Name:     gwRouterPort,
		MAC:      gwLRPMAC.String(),
		Networks: gwLRPNetworks,
		Options:  options,
	}

	err = libovsdbops.CreateOrUpdateLogicalRouterPort(oc.nbClient, &logicalRouter,
		&logicalRouterPort, nil, &logicalRouterPort.MAC, &logicalRouterPort.Networks,
		&logicalRouterPort.Options)
	if err != nil {
		return fmt.Errorf("failed to create port %+v on router %+v: %v", logicalRouterPort, logicalRouter, err)
	}

	for _, entry := range clusterIPSubnet {
		drLRPIfAddr, err := util.MatchFirstIPNetFamily(utilnet.IsIPv6CIDR(entry), drLRPIfAddrs)
		if err != nil {
			return fmt.Errorf("failed to add a static route in GR %s with distributed "+
				"router as the nexthop: %v",
				gatewayRouter, err)
		}

		// TODO There has to be a better way to do this. It seems like the
		// whole purpose is to update the appropriate route in case it already
		// exists *only* in the context of this router. But then it does not
		// make sense to refresh it on every loop, unless it is also way to
		// check for duplicate cluster IP subnets for which there would also be
		// a better way to do it. Adding support for indirection in ModelClients
		// opModel (being able to operate on thins pointed to from another model)
		// would be a great way to simplify this.
		updatedLogicalRouter, err := libovsdbops.GetLogicalRouter(oc.nbClient, &logicalRouter)
		if err != nil {
			return fmt.Errorf("unable to retrieve logical router %+v: %v", logicalRouter, err)
		}

		lrsr := nbdb.LogicalRouterStaticRoute{
			IPPrefix: entry.String(),
			Nexthop:  drLRPIfAddr.IP.String(),
		}
		p := func(item *nbdb.LogicalRouterStaticRoute) bool {
			return item.IPPrefix == lrsr.IPPrefix && libovsdbops.PolicyEqualPredicate(item.Policy, lrsr.Policy) &&
				util.SliceHasStringItem(updatedLogicalRouter.StaticRoutes, item.UUID)
		}
		err = libovsdbops.CreateOrReplaceLogicalRouterStaticRouteWithPredicate(oc.nbClient, gatewayRouter, &lrsr, p,
			&lrsr.Nexthop)
		if err != nil {
			return fmt.Errorf("failed to add a static route %+v in GR %s with distributed router as the nexthop, err: %v", lrsr, gatewayRouter, err)
		}
	}

	if err := oc.addExternalSwitch("",
		l3GatewayConfig.InterfaceID,
		nodeName,
		gatewayRouter,
		l3GatewayConfig.MACAddress.String(),
		types.PhysicalNetworkName,
		l3GatewayConfig.IPAddresses,
		l3GatewayConfig.VLANID); err != nil {
		return err
	}

	if l3GatewayConfig.EgressGWInterfaceID != "" {
		if err := oc.addExternalSwitch(types.EgressGWSwitchPrefix,
			l3GatewayConfig.EgressGWInterfaceID,
			nodeName,
			gatewayRouter,
			l3GatewayConfig.EgressGWMACAddress.String(),
			types.PhysicalNetworkExGwName,
			l3GatewayConfig.EgressGWIPAddresses,
			nil); err != nil {
			return err
		}
	}

	externalRouterPort := types.GWRouterToExtSwitchPrefix + gatewayRouter

	nextHops := l3GatewayConfig.NextHops

	// Remove stale OVN resources with any old masquerade IP
	if err := deleteStaleMasqueradeResources(oc.nbClient, gatewayRouter, nodeName, oc.watchFactory); err != nil {
		return fmt.Errorf("failed to remove stale masquerade resources from northbound database: %w", err)
	}

	if err := gateway.CreateDummyGWMacBindings(oc.nbClient, gatewayRouter); err != nil {
		return err
	}

	for _, nextHop := range node.DummyNextHopIPs() {
		// Add return service route for OVN back to host
		prefix := config.Gateway.V4MasqueradeSubnet
		if utilnet.IsIPv6(nextHop) {
			prefix = config.Gateway.V6MasqueradeSubnet
		}
		lrsr := nbdb.LogicalRouterStaticRoute{
			IPPrefix:    prefix,
			Nexthop:     nextHop.String(),
			OutputPort:  &externalRouterPort,
			ExternalIDs: map[string]string{util.OvnNodeMasqCIDR: ""},
		}
		p := func(item *nbdb.LogicalRouterStaticRoute) bool {
			return item.OutputPort != nil && *item.OutputPort == *lrsr.OutputPort && item.IPPrefix == lrsr.IPPrefix &&
				libovsdbops.PolicyEqualPredicate(item.Policy, lrsr.Policy)
		}
		err = libovsdbops.CreateOrReplaceLogicalRouterStaticRouteWithPredicate(oc.nbClient, gatewayRouter, &lrsr, p,
			&lrsr.Nexthop)
		if err != nil {
			return fmt.Errorf("error creating service static route %+v in GR %s: %v", lrsr, gatewayRouter, err)
		}
	}

	// Add default gateway routes in GR
	for _, nextHop := range nextHops {
		var allIPs string
		if utilnet.IsIPv6(nextHop) {
			allIPs = "::/0"
		} else {
			allIPs = "0.0.0.0/0"
		}

		lrsr := nbdb.LogicalRouterStaticRoute{
			IPPrefix:   allIPs,
			Nexthop:    nextHop.String(),
			OutputPort: &externalRouterPort,
		}
		p := func(item *nbdb.LogicalRouterStaticRoute) bool {
			return item.OutputPort != nil && *item.OutputPort == *lrsr.OutputPort && item.IPPrefix == lrsr.IPPrefix &&
				libovsdbops.PolicyEqualPredicate(lrsr.Policy, item.Policy)
		}
		err := libovsdbops.CreateOrReplaceLogicalRouterStaticRouteWithPredicate(oc.nbClient, gatewayRouter, &lrsr,
			p, &lrsr.Nexthop)
		if err != nil {
			return fmt.Errorf("error creating static route %+v in GR %s: %v", lrsr, gatewayRouter, err)
		}
	}

	// We need to add a route to the Gateway router's IP, on the
	// cluster router, to ensure that the return traffic goes back
	// to the same gateway router
	//
	// This can be removed once https://bugzilla.redhat.com/show_bug.cgi?id=1891516 is fixed.
	// FIXME(trozet): if LRP IP is changed, we do not remove stale instances of these routes
	for _, gwLRPIP := range gwLRPIPs {
		lrsr := nbdb.LogicalRouterStaticRoute{
			IPPrefix: gwLRPIP.String(),
			Nexthop:  gwLRPIP.String(),
		}
		p := func(item *nbdb.LogicalRouterStaticRoute) bool {
			return item.IPPrefix == lrsr.IPPrefix &&
				libovsdbops.PolicyEqualPredicate(lrsr.Policy, item.Policy)
		}
		err := libovsdbops.CreateOrReplaceLogicalRouterStaticRouteWithPredicate(oc.nbClient,
			oc.GetNetworkScopedClusterRouterName(), &lrsr, p, &lrsr.Nexthop)
		if err != nil {
			return fmt.Errorf("error creating static route %+v in %s: %v", lrsr, oc.GetNetworkScopedClusterRouterName(), err)
		}
	}

	// Add source IP address based routes in distributed router
	// for this gateway router.
	for _, hostSubnet := range hostSubnets {
		gwLRPIP, err := util.MatchIPFamily(utilnet.IsIPv6CIDR(hostSubnet), gwLRPIPs)
		if err != nil {
			return fmt.Errorf("failed to add source IP address based "+
				"routes in distributed router %s: %v",
				oc.GetNetworkScopedClusterRouterName(), err)
		}

		lrsr := nbdb.LogicalRouterStaticRoute{
			Policy:   &nbdb.LogicalRouterStaticRoutePolicySrcIP,
			IPPrefix: hostSubnet.String(),
			Nexthop:  gwLRPIP[0].String(),
		}

		if config.Gateway.Mode != config.GatewayModeLocal {
			p := func(item *nbdb.LogicalRouterStaticRoute) bool {
				return item.IPPrefix == lrsr.IPPrefix && libovsdbops.PolicyEqualPredicate(lrsr.Policy, item.Policy)
			}
			// If migrating from local to shared gateway, let's remove the static routes towards
			// management port interface for the hostSubnet prefix before adding the routes
			// towards join switch.
			mgmtIfAddr := util.GetNodeManagementIfAddr(hostSubnet)
			oc.staticRouteCleanup([]net.IP{mgmtIfAddr.IP})

			err := libovsdbops.CreateOrReplaceLogicalRouterStaticRouteWithPredicate(oc.nbClient, oc.GetNetworkScopedClusterRouterName(),
				&lrsr, p, &lrsr.Nexthop)
			if err != nil {
				return fmt.Errorf("error creating static route %+v in GR %s: %v", lrsr, oc.GetNetworkScopedClusterRouterName(), err)
			}
		} else if config.Gateway.Mode == config.GatewayModeLocal {
			// If migrating from shared to local gateway, let's remove the static routes towards
			// join switch for the hostSubnet prefix
			// Note syncManagementPort happens before gateway sync so only remove things pointing to join subnet

			p := func(item *nbdb.LogicalRouterStaticRoute) bool {
				return item.IPPrefix == lrsr.IPPrefix && item.Policy != nil && *item.Policy == *lrsr.Policy &&
					config.ContainsJoinIP(net.ParseIP(item.Nexthop))
			}
			err := libovsdbops.DeleteLogicalRouterStaticRoutesWithPredicate(oc.nbClient, oc.GetNetworkScopedClusterRouterName(), p)
			if err != nil {
				return fmt.Errorf("error deleting static route %+v in GR %s: %v", lrsr, oc.GetNetworkScopedClusterRouterName(), err)
			}
		}
	}

	// if config.Gateway.DisabledSNATMultipleGWs is not set (by default it is not),
	// the NAT rules for pods not having annotations to route through either external
	// gws or pod CNFs will be added within pods.go addLogicalPort
	externalIPs := make([]net.IP, len(l3GatewayConfig.IPAddresses))
	for i, ip := range l3GatewayConfig.IPAddresses {
		externalIPs[i] = ip.IP
	}
	var natsToUpdate []*nbdb.NAT
	// If l3gatewayAnnotation.IPAddresses changed, we need to update the SNATs on the GR
	oldNATs := []*nbdb.NAT{}
	if oldLogicalRouter != nil {
		oldNATs, err = libovsdbops.GetRouterNATs(oc.nbClient, oldLogicalRouter)
		if err != nil && errors.Is(err, libovsdbclient.ErrNotFound) {
			return fmt.Errorf("unable to get NAT entries for router on node %s: %w", nodeName, err)
		}
	}

	for _, nat := range oldNATs {
		nat := nat
		natModified := false

		// if not type snat, we don't need to update as we only configure snat types
		if nat.Type != nbdb.NATTypeSNAT {
			continue
		}
		// check external ip changed
		for _, externalIP := range externalIPs {
			oldExternalIP, err := util.MatchFirstIPFamily(utilnet.IsIPv6(externalIP), oldExtIPs)
			if err != nil {
				return fmt.Errorf("failed to update GW SNAT rule for pods on router %s error: %v", gatewayRouter, err)
			}
			if externalIP.String() == oldExternalIP.String() {
				// no external ip change, skip
				continue
			}
			if nat.ExternalIP == oldExternalIP.String() {
				// needs to be updated
				natModified = true
				nat.ExternalIP = externalIP.String()
			}

		}
		// note, nat.LogicalIP may be a CIDR or IP, we don't care unless it's an IP
		parsedLogicalIP := net.ParseIP(nat.LogicalIP)
		// check if join ip changed
		if config.ContainsJoinIP(parsedLogicalIP) {
			// is a join SNAT, check if IP needs updating
			joinIP, err := util.MatchFirstIPFamily(utilnet.IsIPv6(parsedLogicalIP), gwLRPIPs)
			if err != nil {
				return fmt.Errorf("failed to find valid IP family match for join subnet IP: %s on "+
					"gateway router: %s, provided IPs: %#v", parsedLogicalIP, gatewayRouter, gwLRPIPs)
			}
			if nat.LogicalIP != joinIP.String() {
				// needs to be updated
				natModified = true
				nat.LogicalIP = joinIP.String()
			}
		}
		if natModified {
			natsToUpdate = append(natsToUpdate, nat)
		}
	}

	if len(natsToUpdate) > 0 {
		err = libovsdbops.CreateOrUpdateNATs(oc.nbClient, &logicalRouter, natsToUpdate...)
		if err != nil {
			return fmt.Errorf("failed to update GW SNAT rule for pod on router %s error: %v", gatewayRouter, err)
		}
	}

	// REMOVEME(trozet) workaround - create join subnet SNAT to handle ICMP needs frag return
	joinNATs := make([]*nbdb.NAT, 0, len(gwLRPIPs))
	for _, gwLRPIP := range gwLRPIPs {
		externalIP, err := util.MatchIPFamily(utilnet.IsIPv6(gwLRPIP), externalIPs)
		if err != nil {
			return fmt.Errorf("failed to find valid external IP family match for join subnet IP: %s on "+
				"gateway router: %s", gwLRPIP, gatewayRouter)
		}
		joinIPNet, err := util.GetIPNetFullMask(gwLRPIP.String())
		if err != nil {
			return fmt.Errorf("failed to parse full CIDR mask for join subnet IP: %s", gwLRPIP)
		}
		nat := libovsdbops.BuildSNAT(&externalIP[0], joinIPNet, "", nil)
		joinNATs = append(joinNATs, nat)
	}
	err = libovsdbops.CreateOrUpdateNATs(oc.nbClient, &logicalRouter, joinNATs...)
	if err != nil {
		return fmt.Errorf("failed to create SNAT rule for join subnet on router %s error: %v", gatewayRouter, err)
	}

	nats := make([]*nbdb.NAT, 0, len(clusterIPSubnet))
	var nat *nbdb.NAT
	if !config.Gateway.DisableSNATMultipleGWs {
		// Default SNAT rules. DisableSNATMultipleGWs=false in LGW (traffic egresses via mp0) always.
		// We are not checking for gateway mode to be shared explicitly to reduce topology differences.
		for _, entry := range clusterIPSubnet {
			externalIP, err := util.MatchIPFamily(utilnet.IsIPv6CIDR(entry), externalIPs)
			if err != nil {
				return fmt.Errorf("failed to create default SNAT rules for gateway router %s: %v",
					gatewayRouter, err)
			}
			nat = libovsdbops.BuildSNAT(&externalIP[0], entry, "", nil)
			nats = append(nats, nat)
		}
		err := libovsdbops.CreateOrUpdateNATs(oc.nbClient, &logicalRouter, nats...)
		if err != nil {
			return fmt.Errorf("failed to update SNAT rule for pod on router %s error: %v", gatewayRouter, err)
		}
	} else {
		// ensure we do not have any leftover SNAT entries after an upgrade
		for _, logicalSubnet := range clusterIPSubnet {
			nat = libovsdbops.BuildSNAT(nil, logicalSubnet, "", nil)
			nats = append(nats, nat)
		}
		err := libovsdbops.DeleteNATs(oc.nbClient, &logicalRouter, nats...)
		if err != nil {
			return fmt.Errorf("failed to delete GW SNAT rule for pod on router %s error: %v", gatewayRouter, err)
		}
	}

	if err := oc.cleanupStalePodSNATs(nodeName, l3GatewayConfig.IPAddresses); err != nil {
		return fmt.Errorf("failed to sync stale SNATs on node %s: %v", nodeName, err)
	}

	// recording gateway mode metrics here after gateway setup is done
	metrics.RecordEgressRoutingViaHost()

	return nil
}

// addExternalSwitch creates a switch connected to the external bridge and connects it to
// the gateway router
func (oc *DefaultNetworkController) addExternalSwitch(prefix, interfaceID, nodeName, gatewayRouter, macAddress, physNetworkName string, ipAddresses []*net.IPNet, vlanID *uint) error {
	// Create the GR port that connects to external_switch with mac address of
	// external interface and that IP address. In the case of `local` gateway
	// mode, whenever ovnkube-node container restarts a new br-local bridge will
	// be created with a new `nicMacAddress`.
	externalRouterPort := prefix + types.GWRouterToExtSwitchPrefix + gatewayRouter

	externalRouterPortNetworks := []string{}
	for _, ip := range ipAddresses {
		externalRouterPortNetworks = append(externalRouterPortNetworks, ip.String())
	}
	externalLogicalRouterPort := nbdb.LogicalRouterPort{
		MAC: macAddress,
		ExternalIDs: map[string]string{
			"gateway-physical-ip": "yes",
		},
		Networks: externalRouterPortNetworks,
		Name:     externalRouterPort,
	}
	logicalRouter := nbdb.LogicalRouter{Name: gatewayRouter}

	err := libovsdbops.CreateOrUpdateLogicalRouterPort(oc.nbClient, &logicalRouter,
		&externalLogicalRouterPort, nil, &externalLogicalRouterPort.MAC,
		&externalLogicalRouterPort.Networks, &externalLogicalRouterPort.ExternalIDs,
		&externalLogicalRouterPort.Options)
	if err != nil {
		return fmt.Errorf("failed to add logical router port %+v to router %s: %v", externalLogicalRouterPort, gatewayRouter, err)
	}

	// Create the external switch for the physical interface to connect to
	// and add external interface as a logical port to external_switch.
	// This is a learning switch port with "unknown" address. The external
	// world is accessed via this port.
	externalSwitch := prefix + oc.GetNetworkScopedExtSwitchName(nodeName)
	externalLogicalSwitchPort := nbdb.LogicalSwitchPort{
		Addresses: []string{"unknown"},
		Type:      "localnet",
		Options: map[string]string{
			"network_name": physNetworkName,
		},
		Name: interfaceID,
	}
	if vlanID != nil && int(*vlanID) != 0 {
		intVlanID := int(*vlanID)
		externalLogicalSwitchPort.TagRequest = &intVlanID
	}

	// Also add the port to connect the external_switch to the router.
	externalSwitchPortToRouter := prefix + types.EXTSwitchToGWRouterPrefix + gatewayRouter
	externalLogicalSwitchPortToRouter := nbdb.LogicalSwitchPort{
		Name: externalSwitchPortToRouter,
		Type: "router",
		Options: map[string]string{
			"router-port": externalRouterPort,

			// This option will program OVN to start sending GARPs for all external IPS
			// that the logical switch port has been configured to use. This is
			// necessary for egress IP because if an egress IP is moved between two
			// nodes, the nodes need to actively update the ARP cache of all neighbors
			// as to notify them the change. If this is not the case: packets will
			// continue to be routed to the old node which hosted the egress IP before
			// it was moved, and the connections will fail.
			"nat-addresses": "router",

			// Setting nat-addresses to router will send out GARPs for all externalIPs and LB VIPs
			// hosted on the GR. Setting exclude-lb-vips-from-garp to true will make sure GARPs for
			// LB VIPs are not sent, thereby preventing GARP overload.
			"exclude-lb-vips-from-garp": "true",
		},
		Addresses: []string{macAddress},
	}
	sw := nbdb.LogicalSwitch{Name: externalSwitch}

	err = libovsdbops.CreateOrUpdateLogicalSwitchPortsAndSwitch(oc.nbClient, &sw, &externalLogicalSwitchPort, &externalLogicalSwitchPortToRouter)
	if err != nil {
		return fmt.Errorf("failed to create logical switch ports %+v, %+v, and switch %s: %v",
			externalLogicalSwitchPort, externalLogicalSwitchPortToRouter, externalSwitch, err)
	}

	return nil
}

// cleanupStaleMasqueradeData removes following from northbound database
//   - LogicalRouterStaticRoute for rtoe-<GW_router> OutputPort anf IPPrefix is same as v4 or v6
//     StaleMasqueradeSubnet
//   - StaticMACBinding for rtoe-<GW_router> LogicalPort and referencing old DummyNextHopMasqueradeIP
func deleteStaleMasqueradeResources(nbClient libovsdbclient.Client, routerName, nodeName string, wf *factory.WatchFactory) error {
	var staleMasqueradeIPs config.MasqueradeIPsConfig
	var nextHops []net.IP
	logicalport := types.GWRouterToExtSwitchPrefix + routerName

	// we first examine the kapi node to see if we can determine if there is a stale masquerade subnet
	// if the masquerade subnet on the kapi node matches whats configured for this controller, it
	// doesn't necessarily mean there is not still a stale masquerade config in nbdb because
	// node could have already updated before this process runs.
	// As a backup, if we don't find the positive match in kapi, we execute a negative lookup in NBDB

	node, err := wf.GetNode(nodeName)
	if err != nil {
		if kerrors.IsNotFound(err) {
			// node doesn't exist for some reason, assume we should still try to clean up with auto-detection
			if err := deleteStaleMasqueradeRouteAndMACBinding(nbClient, routerName, nextHops); err != nil {
				return fmt.Errorf("failed to remove stale MAC binding and static route for logical port %s: %w", logicalport, err)
			}
			return nil
		}
		return err
	}

	subnets, err := util.ParseNodeMasqueradeSubnet(node)
	if err != nil {
		if util.IsAnnotationNotSetError(err) {
			// no annotation set, must be initial bring up, nothing to clean
			return nil
		}
		return err
	}

	var v4ConfiguredMasqueradeNet, v6ConfiguredMasqueradeNet *net.IPNet

	for _, subnet := range subnets {
		if utilnet.IsIPv6CIDR(subnet) {
			v6ConfiguredMasqueradeNet = subnet
		} else if utilnet.IsIPv4CIDR(subnet) {
			v4ConfiguredMasqueradeNet = subnet
		} else {
			return fmt.Errorf("invalid subnet for masquerade annotation: %s", subnet)
		}
	}

	// Check for KAPI telling us there is a stale masquerade
	if v4ConfiguredMasqueradeNet != nil && config.Gateway.V4MasqueradeSubnet != v4ConfiguredMasqueradeNet.String() {
		if err := config.AllocateV4MasqueradeIPs(v4ConfiguredMasqueradeNet.IP, &staleMasqueradeIPs); err != nil {
			return fmt.Errorf("unable to determine stale V4MasqueradeIPs: %s", err)
		}
		nextHops = append(nextHops, staleMasqueradeIPs.V4DummyNextHopMasqueradeIP)
	}

	if v6ConfiguredMasqueradeNet != nil && config.Gateway.V6MasqueradeSubnet != v6ConfiguredMasqueradeNet.String() {
		if err := config.AllocateV6MasqueradeIPs(v6ConfiguredMasqueradeNet.IP, &staleMasqueradeIPs); err != nil {
			return fmt.Errorf("unable to determine stale V6MasqueradeIPs: %s", err)
		}
		nextHops = append(nextHops, staleMasqueradeIPs.V6DummyNextHopMasqueradeIP)
	}

	if err := deleteStaleMasqueradeRouteAndMACBinding(nbClient, routerName, nextHops); err != nil {
		return fmt.Errorf("failed to remove stale MAC binding and static route for logical port %s: %w", logicalport, err)
	}

	return nil
}

// deleteStaleMasqueradeRouteAndMACBinding will attempt to remove the corresponding routes and MAC bindings given the
// list of nextHopIPs. If nextHopIPs is empty, then an attempt will be made to detect the stale route and MAC bindings
func deleteStaleMasqueradeRouteAndMACBinding(nbClient libovsdbclient.Client, routerName string, nextHopIPs []net.IP) error {
	logicalport := types.GWRouterToExtSwitchPrefix + routerName
	if len(nextHopIPs) == 0 {
		// build valid values
		validNextHops := []net.IP{config.Gateway.MasqueradeIPs.V4DummyNextHopMasqueradeIP, config.Gateway.MasqueradeIPs.V6DummyNextHopMasqueradeIP}
		// lookup routes for external id that dont match currently configured masquerade subnets
		for _, validNextHop := range validNextHops {
			staticRoutePredicate := func(item *nbdb.LogicalRouterStaticRoute) bool {
				if item.OutputPort != nil && *item.OutputPort == logicalport &&
					item.Nexthop != validNextHop.String() && utilnet.IPFamilyOfString(item.Nexthop) == utilnet.IPFamilyOf(validNextHop) {
					if _, ok := item.ExternalIDs[util.OvnNodeMasqCIDR]; ok {
						return true
					}
				}
				return false
			}

			staleRoutes, err := libovsdbops.FindLogicalRouterStaticRoutesWithPredicate(nbClient, staticRoutePredicate)
			if err != nil {
				return fmt.Errorf("failed to search for stale masquerade routes: %w", err)
			}

			for _, staleRoute := range staleRoutes {
				klog.Infof("Stale masquerade route found: %#v", *staleRoute)
				// found stale routes, derive nexthop and flush the route and mac binding if it exists
				staleNextHop := staleRoute.Nexthop

				macBindingPredicate := func(item *nbdb.StaticMACBinding) bool {
					return item.LogicalPort == logicalport && item.IP == staleNextHop &&
						utilnet.IPFamilyOfString(item.IP) == utilnet.IPFamilyOfString(staleNextHop)
				}
				if err := libovsdbops.DeleteStaticMACBindingWithPredicate(nbClient, macBindingPredicate); err != nil {
					return fmt.Errorf("failed to delete static MAC binding for logical port %s: %v", logicalport, err)
				}
			}
			if err := libovsdbops.DeleteLogicalRouterStaticRoutes(nbClient, routerName, staleRoutes...); err != nil {
				return err
			}
		}
		return nil
	}

	for _, nextHop := range nextHopIPs {
		staticRoutePredicate := func(item *nbdb.LogicalRouterStaticRoute) bool {
			if item.OutputPort != nil && *item.OutputPort == logicalport &&
				item.Nexthop == nextHop.String() && utilnet.IPFamilyOfString(item.Nexthop) == utilnet.IPFamilyOf(nextHop) {
				if _, ok := item.ExternalIDs[util.OvnNodeMasqCIDR]; ok {
					return true
				}
			}
			return false
		}
		if err := libovsdbops.DeleteLogicalRouterStaticRoutesWithPredicate(nbClient, routerName, staticRoutePredicate); err != nil {
			return fmt.Errorf("failed to delete static route from gateway router %s: %v", routerName, err)
		}

		macBindingPredicate := func(item *nbdb.StaticMACBinding) bool {
			return item.LogicalPort == logicalport && item.IP == nextHop.String() &&
				utilnet.IPFamilyOfString(item.IP) == utilnet.IPFamilyOf(nextHop)
		}
		if err := libovsdbops.DeleteStaticMACBindingWithPredicate(nbClient, macBindingPredicate); err != nil {
			return fmt.Errorf("failed to delete static MAC binding for logical port %s: %v", logicalport, err)
		}
	}
	return nil
}
