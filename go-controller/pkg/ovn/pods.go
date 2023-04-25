package ovn

import (
	"context"
	"fmt"
	"net"
	"time"

	ovntypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/metrics"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/ipallocator"
	logicalswitchmanager "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/logical_switch_manager"
	util "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/pkg/errors"
	kapi "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/libovsdb/model"
	"github.com/ovn-org/libovsdb/ovsdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
)

func (oc *Controller) syncPods(pods []interface{}) {
	oc.syncWithRetry("syncPods", func() error { return oc.syncPodsRetriable(pods) })
}

// This function implements the main body of work of syncPods.
// Upon failure, it may be invoked multiple times in order to avoid a pod restart.
func (oc *Controller) syncPodsRetriable(pods []interface{}) error {
	var allOps []ovsdb.Operation
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
		annotations, err := util.UnmarshalPodAnnotation(pod.Annotations)
		if util.PodScheduled(pod) && util.PodWantsNetwork(pod) && !util.PodCompleted(pod) && err == nil {
			// skip nodes that are not running ovnk (inferred from host subnets)
			if oc.lsManager.IsNonHostSubnetSwitch(pod.Spec.NodeName) {
				continue
			}
			logicalPort := util.GetLogicalPortName(pod.Namespace, pod.Name)
			expectedLogicalPorts[logicalPort] = true
			// it is possible to try to add a pod here that has no node. For example if a pod was deleted with
			// a finalizer, and then the node was removed. In this case the pod will still exist in a running state.
			// Terminating pods should still have network connectivity for pre-stop hooks or termination grace period
			if _, err := oc.watchFactory.GetNode(pod.Spec.NodeName); kerrors.IsNotFound(err) &&
				oc.lsManager.GetSwitchSubnets(pod.Spec.NodeName) == nil {
				if util.PodTerminating(pod) {
					klog.Infof("Ignoring IP allocation for terminating pod: %s/%s, on deleted "+
						"node: %s", pod.Namespace, pod.Name, pod.Spec.NodeName)
					continue
				} else {
					// unknown condition how we are getting a non-terminating pod without a node here
					klog.Errorf("Pod IP allocation found for a non-existent node in API with unknown "+
						"condition. Pod: %s/%s, node: %s", pod.Namespace, pod.Name, pod.Spec.NodeName)
				}
			}
			if err = oc.waitForNodeLogicalSwitchInCache(pod.Spec.NodeName); err != nil {
				return fmt.Errorf("failed to wait for node %s to be added to cache. IP allocation may fail",
					pod.Spec.NodeName)
			}
			if err = oc.lsManager.AllocateIPs(pod.Spec.NodeName, annotations.IPs); err != nil {
				if err == ipallocator.ErrAllocated {
					// already allocated: log an error but not stop syncPod from continuing
					klog.Errorf("Already allocated IPs: %s for pod: %s on node: %s",
						util.JoinIPNetIPs(annotations.IPs, " "), logicalPort,
						pod.Spec.NodeName)
				} else {
					return fmt.Errorf("couldn't allocate IPs: %s for pod: %s on node: %s"+
						" error: %v", util.JoinIPNetIPs(annotations.IPs, " "), logicalPort,
						pod.Spec.NodeName, err)
				}
			}
		}
	}

	// in order to minimize the number of database transactions build a map of all ports keyed by UUID
	portCache := make(map[string]nbdb.LogicalSwitchPort)
	lspList := []nbdb.LogicalSwitchPort{}
	ctx, cancel := context.WithTimeout(context.Background(), ovntypes.OVSDBTimeout)
	defer cancel()
	err := oc.nbClient.List(ctx, &lspList)
	if err != nil {
		return fmt.Errorf("cannot sync pods, cannot retrieve list of logical switch ports (%+v)", err)
	}
	for _, lsp := range lspList {
		portCache[lsp.UUID] = lsp
	}
	// get all the nodes from the watchFactory
	nodes, err := oc.watchFactory.GetNodes()
	if err != nil {
		return fmt.Errorf("failed to get nodes: %v", err)
	}
	for _, n := range nodes {
		// skip nodes that are not running ovnk (inferred from host subnets)
		if oc.lsManager.IsNonHostSubnetSwitch(n.Name) {
			continue
		}
		stalePorts := []string{}
		// find the logical switch for the node
		ls := &nbdb.LogicalSwitch{}
		if lsUUID, ok := oc.lsManager.GetUUID(n.Name); !ok {
			klog.Warningf("Error getting logical switch for node %s: %s", n.Name, "Switch not in logical switch cache")

			// Not in cache: Try getting the logical switch from ovn database (slower method)
			// It is possible that logical switch is removed and we can safely skip it, since there
			// are no stale ports to worry about in that case.
			if ls, err = libovsdbops.FindSwitchByName(oc.nbClient, n.Name); err != nil {
				if errors.Is(err, libovsdbclient.ErrNotFound) {
					continue
				}
				return fmt.Errorf("can't find switch for node %s: %v", n.Name, err)
			}
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), ovntypes.OVSDBTimeout)
			defer cancel()

			ls.UUID = lsUUID
			if err := oc.nbClient.Get(ctx, ls); err != nil {
				return fmt.Errorf("error getting logical switch for node %s (UUID: %s) from ovn database (%v)", n.Name, ls.UUID, err)
			}
		}
		for _, port := range ls.Ports {
			if portCache[port].ExternalIDs["pod"] == "true" {
				if _, ok := expectedLogicalPorts[portCache[port].Name]; !ok {
					stalePorts = append(stalePorts, port)
				}
			}
		}
		if len(stalePorts) > 0 {
			ops, err := oc.nbClient.Where(ls).Mutate(ls, model.Mutation{
				Field:   &ls.Ports,
				Mutator: ovsdb.MutateOperationDelete,
				Value:   stalePorts,
			})
			if err != nil {
				return fmt.Errorf("could not generate ops to delete stale ports from logical switch %s (%+v)", n.Name, err)
			}
			allOps = append(allOps, ops...)
		}
	}
	_, err = libovsdbops.TransactAndCheck(oc.nbClient, allOps)
	if err != nil {
		return fmt.Errorf("could not remove stale logicalPorts from switches (%+v)", err)
	}
	return nil
}

// lookupPortUUIDAndNodeName will use libovsdb to locate the logical switch port uuid as well as the logical switch
// that owns such port (aka nodeName), based on the logical port name.
func (oc *Controller) lookupPortUUIDAndNodeName(logicalPort string) (string, string, error) {

	ctx, cancel := context.WithTimeout(context.Background(), ovntypes.OVSDBTimeout)
	defer cancel()
	lsp := &nbdb.LogicalSwitchPort{Name: logicalPort}
	err := oc.nbClient.Get(ctx, lsp)
	if err != nil {
		return "", "", err
	}
	p := func(item *nbdb.LogicalSwitch) bool {
		for _, currPortUUID := range item.Ports {
			if currPortUUID == lsp.UUID {
				return true
			}
		}
		return false
	}
	nodeSwitches, err := libovsdbops.FindLogicalSwitchesWithPredicate(oc.nbClient, p)
	if err != nil {
		return "", "", fmt.Errorf("failed to get node logical switch for logical port %s (%s): %w", logicalPort, lsp.UUID, err)
	}
	if len(nodeSwitches) != 1 {
		return "", "", fmt.Errorf("found %d node logical switch for logical port %s (%s)", len(nodeSwitches), logicalPort, lsp.UUID)
	}
	return lsp.UUID, nodeSwitches[0].Name, nil
}

func (oc *Controller) deleteLogicalPort(pod *kapi.Pod, portInfo *lpInfo) (err error) {
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

	logicalPort := util.GetLogicalPortName(pod.Namespace, pod.Name)
	var portUUID string
	var nodeName string
	var podIfAddrs []*net.IPNet
	if portInfo == nil {
		// If ovnkube-master restarts, it is also possible the Pod's logical switch port
		// is not re-added into the cache. Delete logical switch port anyway.
		annotation, err := util.UnmarshalPodAnnotation(pod.Annotations)
		if err != nil {
			if util.IsAnnotationNotSetError(err) {
				// if the annotation doesn’t exist, that’s not an error. It means logical port does not need to be deleted.
				klog.V(5).Infof("No annotations on pod %s/%s, no need to delete its logical port: %s", pod.Namespace, pod.Name, logicalPort)
				return nil
			}
			return fmt.Errorf("unable to unmarshal pod annotations for pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}

		// Since portInfo is not available, use ovn to locate the logical switch (named after the node name) for the logical port.
		portUUID, nodeName, err = oc.lookupPortUUIDAndNodeName(logicalPort)
		if err != nil {
			if err != libovsdbclient.ErrNotFound {
				return fmt.Errorf("unable to locate portUUID+nodeName for pod %s/%s: %w", pod.Namespace, pod.Name, err)
			}
			// The logical port no longer exists in OVN. The caller expects this function to be idem-potent,
			// so the proper action to take is to use an empty uuid and extract the node name from the pod spec.
			portUUID = ""
			nodeName = pod.Spec.NodeName
		}
		podIfAddrs = annotation.IPs

		klog.Warningf("No cached port info for deleting pod: %s. Using logical switch %s port uuid %s and addrs %v",
			podDesc, nodeName, portUUID, podIfAddrs)
	} else {
		portUUID = portInfo.uuid
		nodeName = portInfo.logicalSwitch // ls <==> nodeName
		podIfAddrs = portInfo.ips
	}

	// Sanity check. The nodeName from pod spec is expected to be the same as the logical switch obtained from the port.
	if nodeName != pod.Spec.NodeName {
		klog.Errorf("Deleting pod %s has an unexpected node name in spec: %s, ovn expects it to be %s for port uuid %s",
			podDesc, pod.Spec.NodeName, nodeName, portUUID)
	}

	shouldRelease := true
	// check to make sure no other pods are using this IP before we try to release it if this is a completed pod.
	if util.PodCompleted(pod) {
		if shouldRelease, err = oc.lsManager.ConditionalIPRelease(nodeName, podIfAddrs, func() (bool, error) {
			var needleIPs []net.IP
			for _, podIPNet := range podIfAddrs {
				needleIPs = append(needleIPs, podIPNet.IP)
			}

			collidingPod, err := oc.findPodWithIPAddresses(needleIPs)
			if err != nil {
				return false, fmt.Errorf("unable to determine if completed pod IP is in use by another pod. "+
					"Will not release pod %s/%s IP: %#v from allocator. %v", pod.Namespace, pod.Name, podIfAddrs, err)
			}

			if collidingPod != nil {
				klog.Infof("Will not release IP address: %s for %s. Detected another pod"+
					" using this IP: %s/%s", util.JoinIPNetIPs(podIfAddrs, " "), podDesc, collidingPod.Namespace, collidingPod.Name)
				return false, nil
			}

			klog.Infof("Releasing IPs for Completed pod: %s/%s, ips: %s", pod.Namespace, pod.Name,
				util.JoinIPNetIPs(podIfAddrs, " "))
			return true, nil
		}); err != nil {
			return fmt.Errorf("cannot determine if IPs are safe to release for completed pod: %s: %w", podDesc, err)
		}
	}

	var allOps, ops []ovsdb.Operation

	// if the ip is in use by another pod we should not try to remove it from the address set
	if shouldRelease {
		if ops, err = oc.deletePodFromNamespace(pod.Namespace, podIfAddrs, portUUID); err != nil {
			return fmt.Errorf("unable to delete pod %s from namespace: %w", podDesc, err)
		}
		allOps = append(allOps, ops...)
	}
	ops, err = oc.delLSPOps(logicalPort, nodeName, portUUID)
	// Tolerate cases where logical switch of the logical port no longer exist in OVN.
	if err != nil && !errors.Is(err, libovsdbclient.ErrNotFound) {
		return fmt.Errorf("failed to create delete ops for the lsp: %s: %s", logicalPort, err)
	}
	allOps = append(allOps, ops...)

	_, err = libovsdbops.TransactAndCheck(oc.nbClient, allOps)
	if err != nil {
		return fmt.Errorf("cannot delete logical switch port %s, %v", logicalPort, err)
	}

	// do not remove SNATs/GW routes/IPAM for an IP address unless we have validated no other pod is using it
	if !shouldRelease {
		return nil
	}

	if config.Gateway.DisableSNATMultipleGWs {
		if err := deletePodSNAT(oc.nbClient, nodeName, []*net.IPNet{}, podIfAddrs); err != nil {
			return fmt.Errorf("cannot delete GR SNAT for pod %s: %w", podDesc, err)
		}
	}
	podNsName := ktypes.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}
	if err := oc.deleteGWRoutesForPod(podNsName, podIfAddrs); err != nil {
		return fmt.Errorf("cannot delete GW Routes for pod %s: %w", podDesc, err)
	}

	// Releasing IPs needs to happen last so that we can deterministically know that if delete failed that
	// the IP of the pod needs to be released. Otherwise we could have a completed pod failed to be removed
	// and we dont know if the IP was released or not, and subsequently could accidentally release the IP
	// while it is now on another pod. Releasing IPs may fail at this point if cache knows nothing about it,
	// which is okay since node may have been deleted.
	klog.Infof("Attempting to release IPs for pod: %s/%s, ips: %s", pod.Namespace, pod.Name,
		util.JoinIPNetIPs(podIfAddrs, " "))
	if err := oc.lsManager.ReleaseIPs(nodeName, podIfAddrs); err != nil {
		if !errors.Is(err, logicalswitchmanager.SwitchNotFound) {
			return fmt.Errorf("cannot release IPs for pod %s on node %s: %w", podDesc, nodeName, err)
		}
		klog.Warningf("Ignoring release IPs failure for pod %s on node %s: %w", podDesc, nodeName, err)
	}

	return nil
}

func (bnc *Controller) findPodWithIPAddresses(needleIPs []net.IP) (*kapi.Pod, error) {
	allPods, err := bnc.watchFactory.GetAllPods()
	if err != nil {
		return nil, fmt.Errorf("unable to get pods: %w", err)
	}

	// iterate through all pods
	for _, p := range allPods {
		if util.PodCompleted(p) || !util.PodWantsNetwork(p) || !util.PodScheduled(p) {
			continue
		}
		// check if the pod addresses match in the OVN annotation
		haystackPodAddrs, err := util.GetAllPodIPs(p)
		if err != nil {
			continue
		}

		for _, haystackPodAddr := range haystackPodAddrs {
			for _, needleIP := range needleIPs {
				if haystackPodAddr.Equal(needleIP) {
					return p, nil
				}
			}
		}
	}

	return nil, nil
}

func (oc *Controller) waitForNodeLogicalSwitch(nodeName string) (*nbdb.LogicalSwitch, error) {
	// Wait for the node logical switch to be created by the ClusterController and be present
	// in libovsdb's cache. The node switch will be created when the node's logical network infrastructure
	// is created by the node watch
	ls := &nbdb.LogicalSwitch{Name: nodeName}
	if err := wait.PollImmediate(30*time.Millisecond, 30*time.Second, func() (bool, error) {
		if lsUUID, ok := oc.lsManager.GetUUID(nodeName); !ok {
			return false, fmt.Errorf("error getting logical switch for node %s: %s", nodeName, "switch not in logical switch cache")
		} else {
			ls.UUID = lsUUID
			return true, nil
		}
	}); err != nil {
		return nil, fmt.Errorf("timed out waiting for logical switch in logical switch cache %q subnet: %v", nodeName, err)
	}
	return ls, nil
}

func (oc *Controller) waitForNodeLogicalSwitchInCache(nodeName string) error {
	// Wait for the node logical switch to be created by the ClusterController.
	// The node switch will be created when the node's logical network infrastructure
	// is created by the node watch.
	var subnets []*net.IPNet
	if err := wait.PollImmediate(30*time.Millisecond, 30*time.Second, func() (bool, error) {
		subnets = oc.lsManager.GetSwitchSubnets(nodeName)
		return subnets != nil, nil
	}); err != nil {
		return fmt.Errorf("timed out waiting for logical switch %q subnet: %v", nodeName, err)
	}
	return nil
}

func (oc *Controller) addRoutesGatewayIP(pod *kapi.Pod, podAnnotation *util.PodAnnotation, nodeSubnets []*net.IPNet,
	routingExternalGWs *gatewayInfo, routingPodGWs map[string]gatewayInfo, hybridOverlayExternalGW net.IP) error {

	// if there are other network attachments for the pod, then check if those network-attachment's
	// annotation has default-route key. If present, then we need to skip adding default route for
	// OVN interface
	networks, err := util.GetK8sPodAllNetworks(pod)
	if err != nil {
		return fmt.Errorf("error while getting network attachment definition for [%s/%s]: %v",
			pod.Namespace, pod.Name, err)
	}
	otherDefaultRouteV4 := false
	otherDefaultRouteV6 := false
	for _, network := range networks {
		for _, gatewayRequest := range network.GatewayRequest {
			if utilnet.IsIPv6(gatewayRequest) {
				otherDefaultRouteV6 = true
			} else {
				otherDefaultRouteV4 = true
			}
		}
	}

	for _, podIfAddr := range podAnnotation.IPs {
		isIPv6 := utilnet.IsIPv6CIDR(podIfAddr)
		nodeSubnet, err := util.MatchIPNetFamily(isIPv6, nodeSubnets)
		if err != nil {
			return err
		}
		// DUALSTACK FIXME: hybridOverlayExternalGW is not Dualstack
		// When oc.getHybridOverlayExternalGwAnnotation() supports dualstack, return error if no match.
		// If external gateway mode is configured, need to use it for all outgoing traffic, so don't want
		// to fall back to the default gateway here
		if hybridOverlayExternalGW != nil && utilnet.IsIPv6(hybridOverlayExternalGW) != isIPv6 {
			klog.Warningf("Pod %s/%s has no external gateway for %s", pod.Namespace, pod.Name, util.IPFamilyName(isIPv6))
			continue
		}

		gatewayIPnet := util.GetNodeGatewayIfAddr(nodeSubnet)

		otherDefaultRoute := otherDefaultRouteV4
		if isIPv6 {
			otherDefaultRoute = otherDefaultRouteV6
		}
		var gatewayIP net.IP
		hasRoutingExternalGWs := len(routingExternalGWs.gws) > 0
		hasPodRoutingGWs := len(routingPodGWs) > 0
		if otherDefaultRoute || (hybridOverlayExternalGW != nil && !hasRoutingExternalGWs && !hasPodRoutingGWs) {
			for _, clusterSubnet := range config.Default.ClusterSubnets {
				if isIPv6 == utilnet.IsIPv6CIDR(clusterSubnet.CIDR) {
					podAnnotation.Routes = append(podAnnotation.Routes, util.PodRoute{
						Dest:    clusterSubnet.CIDR,
						NextHop: gatewayIPnet.IP,
					})
				}
			}
			for _, serviceSubnet := range config.Kubernetes.ServiceCIDRs {
				if isIPv6 == utilnet.IsIPv6CIDR(serviceSubnet) {
					podAnnotation.Routes = append(podAnnotation.Routes, util.PodRoute{
						Dest:    serviceSubnet,
						NextHop: gatewayIPnet.IP,
					})
				}
			}
			if hybridOverlayExternalGW != nil {
				gatewayIP = util.GetNodeHybridOverlayIfAddr(nodeSubnet).IP
			}
		} else {
			gatewayIP = gatewayIPnet.IP
		}

		if len(config.HybridOverlay.ClusterSubnets) > 0 {
			// Add a route for each hybrid overlay subnet via the hybrid
			// overlay port on the pod's logical switch.
			nextHop := util.GetNodeHybridOverlayIfAddr(nodeSubnet).IP
			for _, clusterSubnet := range config.HybridOverlay.ClusterSubnets {
				if utilnet.IsIPv6CIDR(clusterSubnet.CIDR) == isIPv6 {
					podAnnotation.Routes = append(podAnnotation.Routes, util.PodRoute{
						Dest:    clusterSubnet.CIDR,
						NextHop: nextHop,
					})
				}
			}
		}
		if gatewayIP != nil {
			podAnnotation.Gateways = append(podAnnotation.Gateways, gatewayIP)
		}
	}
	return nil
}

func (oc *Controller) addLogicalPort(pod *kapi.Pod) (err error) {
	// If a node does node have an assigned hostsubnet don't wait for the logical switch to appear
	if oc.lsManager.IsNonHostSubnetSwitch(pod.Spec.NodeName) {
		return nil
	}

	// Keep track of how long syncs take.
	start := time.Now()
	defer func() {
		klog.Infof("[%s/%s] addLogicalPort took %v", pod.Namespace, pod.Name, time.Since(start))
	}()

	// it is possible to try to add a pod here that has no node. For example if a pod was deleted with
	// a finalizer, and then the node was removed. In this case the pod will still exist in a running state.
	// Terminating pods should still have network connectivity for pre-stop hooks or termination grace period
	// We cannot wire a pod that has no node/switch, so retry again later
	if _, err := oc.watchFactory.GetNode(pod.Spec.NodeName); kerrors.IsNotFound(err) &&
		oc.lsManager.GetSwitchSubnets(pod.Spec.NodeName) == nil {
		podState := "unknown"
		if util.PodTerminating(pod) {
			podState = "terminating"
		}
		return fmt.Errorf("[%s/%s] Non-existent node: %s in API for pod with %s state",
			pod.Namespace, pod.Name, pod.Spec.NodeName, podState)
	}

	logicalSwitch := pod.Spec.NodeName
	ls, err := oc.waitForNodeLogicalSwitch(logicalSwitch)
	if err != nil {
		return err
	}

	portName := util.GetLogicalPortName(pod.Namespace, pod.Name)
	klog.Infof("[%s/%s] creating logical port for pod on switch %s", pod.Namespace, pod.Name, logicalSwitch)

	var podMac net.HardwareAddr
	var podIfAddrs []*net.IPNet
	var allOps []ovsdb.Operation
	var addresses []string
	var releaseIPs bool
	lspExist := false
	needsIP := true

	ctx, cancel := context.WithTimeout(context.Background(), ovntypes.OVSDBTimeout)
	defer cancel()
	// Check if the pod's logical switch port already exists. If it
	// does don't re-add the port to OVN as this will change its
	// UUID and and the port cache, address sets, and port groups
	// will still have the old UUID.
	getLSP := &nbdb.LogicalSwitchPort{Name: portName}
	err = oc.nbClient.Get(ctx, getLSP)
	if err != nil && err != libovsdbclient.ErrNotFound {
		return fmt.Errorf("unable to get the lsp: %s from the nbdb: %s", portName, err)
	}
	lsp := &nbdb.LogicalSwitchPort{Name: portName}
	if len(getLSP.UUID) == 0 {
		lsp.UUID = libovsdbops.BuildNamedUUID()
	} else {
		lsp.UUID = getLSP.UUID
		lspExist = true
	}

	// Sanity check. If port exists, it should be in the logical switch obtained from the pod spec.
	if lspExist {
		portFound := false
		ls, err = libovsdbops.FindSwitchByName(oc.nbClient, logicalSwitch)
		if err != nil {
			return fmt.Errorf("[%s/%s] unable to find logical switch %s in NBDB", pod.Namespace, pod.Name,
				logicalSwitch)
		}
		for _, currPortUUID := range ls.Ports {
			if currPortUUID == getLSP.UUID {
				portFound = true
				break
			}
		}
		if !portFound {
			// This should never happen and indicates we failed to clean up an LSP for a pod that was recreated
			return fmt.Errorf("[%s/%s] failed to locate existing logical port %s (%s) in logical switch %s",
				pod.Namespace, pod.Name, getLSP.Name, getLSP.UUID, logicalSwitch)
		}
	}

	lsp.Options = make(map[string]string)
	// Unique identifier to distinguish interfaces for recreated pods, also set by ovnkube-node
	// ovn-controller will claim the OVS interface only if external_ids:iface-id
	// matches with the Port_Binding.logical_port and external_ids:iface-id-ver matches
	// with the Port_Binding.options:iface-id-ver. This is not mandatory.
	// If Port_binding.options:iface-id-ver is not set, then OVS
	// Interface.external_ids:iface-id-ver if set is ignored.
	// Don't set iface-id-ver for already existing LSP if it wasn't set before,
	// because the corresponding OVS port may not have it set
	// (then ovn-controller won't bind the interface).
	// May happen on upgrade, because ovnkube-node doesn't update
	// existing OVS interfaces with new iface-id-ver option.
	if !lspExist || len(getLSP.Options["iface-id-ver"]) != 0 {
		lsp.Options["iface-id-ver"] = string(pod.UID)
	}
	// Bind the port to the node's chassis; prevents ping-ponging between
	// chassis if ovnkube-node isn't running correctly and hasn't cleared
	// out iface-id for an old instance of this pod, and the pod got
	// rescheduled.
	lsp.Options["requested-chassis"] = pod.Spec.NodeName

	annotation, err := util.UnmarshalPodAnnotation(pod.Annotations)

	// the IPs we allocate in this function need to be released back to the
	// IPAM pool if there is some error in any step of addLogicalPort past
	// the point the IPs were assigned via the IPAM manager.
	// this needs to be done only when releaseIPs is set to true (the case where
	// we truly have assigned podIPs in this call) AND when there is no error in
	// the rest of the functionality of addLogicalPort. It is important to use a
	// named return variable for defer to work correctly.

	defer func() {
		if releaseIPs && err != nil {
			if relErr := oc.lsManager.ReleaseIPs(logicalSwitch, podIfAddrs); relErr != nil {
				klog.Errorf("Error when releasing IPs for node: %s, err: %q",
					logicalSwitch, relErr)
			} else {
				klog.Infof("Released IPs: %s for node: %s", util.JoinIPNetIPs(podIfAddrs, " "), logicalSwitch)
			}
		}
	}()

	if err == nil {
		podMac = annotation.MAC
		podIfAddrs = annotation.IPs

		// If the pod already has annotations use the existing static
		// IP/MAC from the annotation.
		lsp.DynamicAddresses = nil

		// ensure we have reserved the IPs in the annotation
		if err = oc.lsManager.AllocateIPs(logicalSwitch, podIfAddrs); err != nil && err != ipallocator.ErrAllocated {
			return fmt.Errorf("unable to ensure IPs allocated for already annotated pod: %s, IPs: %s, error: %v",
				pod.Name, util.JoinIPNetIPs(podIfAddrs, " "), err)
		} else {
			needsIP = false
		}
	}

	if needsIP {
		// try to get the IP from existing port in OVN first
		podMac, podIfAddrs, err = oc.getPortAddresses(logicalSwitch, portName)
		if err != nil {
			return fmt.Errorf("failed to get pod addresses for pod %s on node: %s, err: %v",
				portName, logicalSwitch, err)
		}
		needsNewAllocation := false
		// ensure we have reserved the IPs found in OVN
		if len(podIfAddrs) == 0 {
			needsNewAllocation = true
		} else if err = oc.lsManager.AllocateIPs(logicalSwitch, podIfAddrs); err != nil && err != ipallocator.ErrAllocated {
			klog.Warningf("Unable to allocate IPs found on existing OVN port: %s, for pod %s on node: %s"+
				" error: %v", util.JoinIPNetIPs(podIfAddrs, " "), portName, logicalSwitch, err)

			needsNewAllocation = true
		}
		if needsNewAllocation {
			// Previous attempts to use already configured IPs failed, need to assign new
			podMac, podIfAddrs, err = oc.assignPodAddresses(logicalSwitch)
			if err != nil {
				return fmt.Errorf("failed to assign pod addresses for pod %s on node: %s, err: %v",
					portName, logicalSwitch, err)
			}
		}

		releaseIPs = true

	}

	// Ensure the namespace/nsInfo exists
	routingExternalGWs, routingPodGWs, hybridOverlayExternalGW, ops, err := oc.addPodToNamespace(pod.Namespace, podIfAddrs)
	if err != nil {
		return err
	}
	allOps = append(allOps, ops...)

	if needsIP {
		network, err := util.GetK8sPodDefaultNetwork(pod)
		// handle error cases separately first to ensure binding to err, otherwise the
		// defer will fail
		if err != nil {
			return fmt.Errorf("error while getting custom MAC config for port %q from "+
				"default-network's network-attachment: %v", portName, err)
		}

		if network != nil && network.MacRequest != "" {
			klog.V(5).Infof("Pod %s/%s requested custom MAC: %s", pod.Namespace, pod.Name, network.MacRequest)
			podMac, err = net.ParseMAC(network.MacRequest)
			if err != nil {
				return fmt.Errorf("failed to parse mac %s requested in annotation for pod %s: Error %v",
					network.MacRequest, pod.Name, err)
			}
		}
		podAnnotation := util.PodAnnotation{
			IPs: podIfAddrs,
			MAC: podMac,
		}
		var nodeSubnets []*net.IPNet
		if nodeSubnets = oc.lsManager.GetSwitchSubnets(logicalSwitch); nodeSubnets == nil {
			return fmt.Errorf("cannot retrieve subnet for assigning gateway routes for pod %s, node: %s",
				pod.Name, logicalSwitch)
		}
		err = oc.addRoutesGatewayIP(pod, &podAnnotation, nodeSubnets, routingExternalGWs, routingPodGWs, hybridOverlayExternalGW)
		if err != nil {
			return err
		}

		var marshalledAnnotation map[string]interface{}
		marshalledAnnotation, err = util.MarshalPodAnnotation(&podAnnotation)
		if err != nil {
			return fmt.Errorf("error creating pod network annotation: %v", err)
		}

		klog.V(5).Infof("Annotation values: ip=%v ; mac=%s ; gw=%s\nAnnotation=%s",
			podIfAddrs, podMac, podAnnotation.Gateways, marshalledAnnotation)
		if err = oc.kube.SetAnnotationsOnPod(pod.Namespace, pod.Name, marshalledAnnotation); err != nil {
			return fmt.Errorf("failed to set annotation on pod %s: %v", pod.Name, err)
		}
		releaseIPs = false
	}

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
		err = oc.addGWRoutesForPod(gateways, podIfAddrs, podNsName, pod.Spec.NodeName)
		if err != nil {
			return err
		}
	} else if config.Gateway.DisableSNATMultipleGWs && !util.PodCompleted(pod) {
		// Add NAT rules to pods if disable SNAT is set and does not have
		// namespace annotations to go through external egress router
		if extIPs, err := getExternalIPsGR(oc.watchFactory, pod.Spec.NodeName); err != nil {
			return err
		} else if err = addOrUpdatePodSNAT(oc.nbClient, pod.Spec.NodeName, extIPs, podIfAddrs); err != nil {
			return err
		}
	}

	// check if this pod is serving as an external GW
	err = oc.addPodExternalGW(pod)
	if err != nil {
		return fmt.Errorf("failed to handle external GW check: %v", err)
	}

	// set addresses on the port
	// LSP addresses in OVN are a single space-separated value
	addresses = []string{podMac.String()}
	for _, podIfAddr := range podIfAddrs {
		addresses[0] = addresses[0] + " " + podIfAddr.IP.String()
	}

	lsp.Addresses = addresses

	// add external ids
	lsp.ExternalIDs = map[string]string{"namespace": pod.Namespace, "pod": "true"}

	// CNI depends on the flows from port security, delay setting it until end
	lsp.PortSecurity = addresses

	if !lspExist {
		timeout := ovntypes.OVSDBWaitTimeout
		allOps = append(allOps, ovsdb.Operation{
			Op:      ovsdb.OperationWait,
			Timeout: &timeout,
			Table:   "Logical_Switch_Port",
			Where:   []ovsdb.Condition{{Column: "name", Function: ovsdb.ConditionEqual, Value: lsp.Name}},
			Columns: []string{"name"},
			Until:   "!=",
			Rows:    []ovsdb.Row{{"name": lsp.Name}},
		})

		// create new logical switch port
		ops, err := oc.nbClient.Create(lsp)
		if err != nil {
			return err
		}
		allOps = append(allOps, ops...)

		//add the logical switch port to the logical switch
		ops, err = oc.nbClient.Where(ls).Mutate(ls, model.Mutation{
			Field:   &ls.Ports,
			Mutator: ovsdb.MutateOperationInsert,
			Value:   []string{lsp.UUID},
		})
		if err != nil {
			return err
		}
		allOps = append(allOps, ops...)

	} else {
		//update Existing logical switch port
		ops, err := oc.nbClient.Where(lsp).Update(lsp, &lsp.Addresses, &lsp.ExternalIDs, &lsp.Options, &lsp.PortSecurity)
		if err != nil {
			return fmt.Errorf("could not create commands to update logical switch port %s - %+v", portName, err)
		}
		allOps = append(allOps, ops...)
	}

	results, err := libovsdbops.TransactAndCheckAndSetUUIDs(oc.nbClient, lsp, allOps)
	if err != nil {

		return fmt.Errorf("could not perform creation or update of logical switch port %s - %+v", portName, err)
	}
	oc.metricsRecorder.AddLSP(pod.UID)

	// if somehow lspUUID is empty, there is a bug here with interpreting OVSDB results
	if len(lsp.UUID) == 0 {
		return fmt.Errorf("UUID is empty from LSP: %q create operation. OVSDB results: %#v", portName, results)
	}

	// Add the pod's logical switch port to the port cache
	portInfo := oc.logicalPortCache.add(logicalSwitch, portName, lsp.UUID, podMac, podIfAddrs)

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
	// observe the pod creation latency metric.
	metrics.RecordPodCreated(pod)
	return nil
}

// Given a node, gets the next set of addresses (from the IPAM) for each of the node's
// subnets to assign to the new pod
func (oc *Controller) assignPodAddresses(nodeName string) (net.HardwareAddr, []*net.IPNet, error) {
	var (
		podMAC   net.HardwareAddr
		podCIDRs []*net.IPNet
		err      error
	)
	podCIDRs, err = oc.lsManager.AllocateNextIPs(nodeName)
	if err != nil {
		return nil, nil, err
	}
	if len(podCIDRs) > 0 {
		podMAC = util.IPAddrToHWAddr(podCIDRs[0].IP)
	}
	return podMAC, podCIDRs, nil
}

// Given a pod and the node on which it is scheduled, get all addresses currently assigned
// to it from the nbdb.
func (oc *Controller) getPortAddresses(nodeName, portName string) (net.HardwareAddr, []*net.IPNet, error) {
	podMac, podIPs, err := util.GetPortAddresses(portName, oc.nbClient)
	if err != nil {
		return nil, nil, err
	}

	if podMac == nil || len(podIPs) == 0 {
		return nil, nil, nil
	}

	var podIPNets []*net.IPNet

	nodeSubnets := oc.lsManager.GetSwitchSubnets(nodeName)

	for _, ip := range podIPs {
		for _, subnet := range nodeSubnets {
			if subnet.Contains(ip) {
				podIPNets = append(podIPNets,
					&net.IPNet{
						IP:   ip,
						Mask: subnet.Mask,
					})
				break
			}
		}
	}
	return podMac, podIPNets, nil
}

// delLSPOps returns the ovsdb operations required to delete the given logical switch port (LSP)
func (oc *Controller) delLSPOps(logicalPort, logicalSwitch, lspUUID string) ([]ovsdb.Operation, error) {
	var allOps []ovsdb.Operation

	lsp := &nbdb.LogicalSwitchPort{
		UUID: lspUUID,
		Name: logicalPort,
	}
	if lspUUID == "" {
		ctx, cancel := context.WithTimeout(context.Background(), ovntypes.OVSDBTimeout)
		defer cancel()
		if err := oc.nbClient.Get(ctx, lsp); err != nil && err != libovsdbclient.ErrNotFound {
			return nil, fmt.Errorf("cannot delete logical switch port %s failed retrieving the object %v", logicalPort, err)
		} else if err == libovsdbclient.ErrNotFound {
			// lsp doesn't exist; nothing to do
			return allOps, nil
		}
	}

	ls := &nbdb.LogicalSwitch{}
	var err error
	if lsUUID, ok := oc.lsManager.GetUUID(logicalSwitch); !ok {
		klog.Errorf("Error getting logical switch for node %s: switch not in logical switch cache", logicalSwitch)
		// Not in cache: Try getting the logical switch from ovn database (slower method)
		if ls, err = libovsdbops.FindSwitchByName(oc.nbClient, logicalSwitch); err != nil {
			if err == libovsdbclient.ErrNotFound {
				// ls doesn't exist; nothing to do
				return allOps, nil
			}
			return nil, fmt.Errorf("can't find switch for node %s: %v", logicalSwitch, err)
		}
	} else {
		ls.UUID = lsUUID
	}

	ops, err := oc.nbClient.Where(ls).Mutate(ls, model.Mutation{
		Field:   &ls.Ports,
		Mutator: ovsdb.MutateOperationDelete,
		Value:   []string{lsp.UUID},
	})
	if err != nil {
		return nil, fmt.Errorf("cannot generate ops delete logical switch port %s: %v", logicalPort, err)
	}
	allOps = append(allOps, ops...)

	// for testing purposes the explicit delete of the logical switch port is required
	ops, err = oc.nbClient.Where(lsp).Delete()
	if err != nil {
		return nil, fmt.Errorf("cannot generate ops delete logical switch port %s: %v", logicalPort, err)
	}
	allOps = append(allOps, ops...)

	return allOps, nil
}
