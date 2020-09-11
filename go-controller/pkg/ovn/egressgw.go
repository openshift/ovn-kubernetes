package ovn

import (
	"encoding/json"
	"fmt"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	utilnet "k8s.io/utils/net"
	"net"
	"strings"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	nettypes "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"

	kapi "k8s.io/api/core/v1"
	"k8s.io/klog"
)

// addPodExternalGW handles detecting if a pod is serving as an external gateway for namespace(s) and adding routes
// to all pods in that namespace
func (oc *Controller) addPodExternalGW(pod *kapi.Pod) error {
	podRoutingNamespaceAnno := pod.Annotations[routingNamespaceAnnotation]
	if podRoutingNamespaceAnno == "" {
		return nil
	}
	klog.Infof("External gateway pod: %s, detected for namespace(s) %s", pod.Name, podRoutingNamespaceAnno)
	var foundGws []net.IP

	if pod.Annotations[routingNetworkAnnotation] != "" {
		var multusNetworks []nettypes.NetworkStatus
		err := json.Unmarshal([]byte(pod.ObjectMeta.Annotations[nettypes.NetworkStatusAnnot]), &multusNetworks)
		if err != nil {
			return fmt.Errorf("unable to unmarshall annotation k8s.v1.cni.cncf.io/network-status on pod %s: %v", pod.Name, err)
		}
		for _, multusNetwork := range multusNetworks {
			if multusNetwork.Name == pod.Annotations[routingNetworkAnnotation] {
				for _, gwIP := range multusNetwork.IPs {
					ip := net.ParseIP(gwIP)
					if ip != nil {
						foundGws = append(foundGws, ip)
					}
				}
			}
		}
	} else if pod.Spec.HostNetwork {
		for _, podIP := range pod.Status.PodIPs {
			ip := net.ParseIP(podIP.IP)
			if ip != nil {
				foundGws = append(foundGws, ip)
			}
		}
	} else {
		klog.Errorf("Ignoring pod %s as an external gateway candidate. Invalid combination "+
			"of host network: %t and routing-network annotation: %s", pod.Name, pod.Spec.HostNetwork,
			pod.Annotations[routingNetworkAnnotation])
		return nil
	}

	// if we found any gateways then we need to update current pods routing in the relevant namespace
	if len(foundGws) == 0 {
		klog.Warningf("No valid gateway IPs found for requested external gateway pod: %s", pod.Name)
		return nil
	}

	for _, namespace := range strings.Split(podRoutingNamespaceAnno, ",") {
		err := oc.addPodExternalGWForNamespace(namespace, pod, foundGws)
		if err != nil {
			return err
		}
	}
	return nil
}

// addPodExternalGWForNamespace handles adding routes to all pods in that namespace for a pod GW
func (oc *Controller) addPodExternalGWForNamespace(namespace string, pod *kapi.Pod, gws []net.IP) error {
	nsInfo, err := oc.waitForNamespaceLocked(namespace)
	if err != nil {
		return err
	}
	defer nsInfo.Unlock()
	nsInfo.routingExternalPodGWs[pod.Name] = gws
	return oc.addGWRoutesForNamespace(namespace, gws, nsInfo)
}

// addExternalGWsForNamespace handles adding annotated gw routes to all pods in namespace
// This should only be called with a lock on nsInfo
func (oc *Controller) addExternalGWsForNamespace(gateways []net.IP, nsInfo *namespaceInfo, namespace string) error {
	if gateways == nil {
		return fmt.Errorf("unable to add gateways routes for namespace: %s, gateways are nil", namespace)
	}
	nsInfo.routingExternalGWs = gateways
	return oc.addGWRoutesForNamespace(namespace, gateways, nsInfo)
}

// addGWRoutesForNamespace handles adding routes for all existing pods in namespace
// This should only be called with a lock on nsInfo
func (oc *Controller) addGWRoutesForNamespace(namespace string, gws []net.IP, nsInfo *namespaceInfo) error {
	existingPods, err := oc.watchFactory.GetPods(namespace)
	if err != nil {
		return fmt.Errorf("failed to get all the pods (%v)", err)
	}
	// TODO (trozet): use the go bindings here and batch commands
	for _, pod := range existingPods {
		gr := "GR_" + pod.Spec.NodeName
		for _, gw := range gws {
			for _, podIP := range pod.Status.PodIPs {
				mask := GetIPFullMask(podIP.IP)
				_, stderr, err := util.RunOVNNbctl("--", "--may-exist", "--policy=src-ip", "--ecmp-symmetric-reply",
					"lr-route-add", gr, podIP.IP+mask, gw.String())
				if err != nil {
					return fmt.Errorf("unable to add src-ip route to GR router, stderr:%q, err:%v", stderr, err)
				}
				if err := oc.addHybridRoutePolicyForPod(net.ParseIP(podIP.IP), pod.Spec.NodeName); err != nil {
					return err
				}
				if nsInfo.podExternalRoutes[podIP.IP] == nil {
					nsInfo.podExternalRoutes[podIP.IP] = make(map[string]string)
				}
				nsInfo.podExternalRoutes[podIP.IP][gw.String()] = gr
			}
		}
	}
	return nil
}

// deletePodExternalGW detects if a given pod is acting as an external GW and removes all routes in all namespaces
// associated with that pod
func (oc *Controller) deletePodExternalGW(pod *kapi.Pod) {
	podRoutingNamespaceAnno := pod.Annotations[routingNamespaceAnnotation]
	if podRoutingNamespaceAnno == "" {
		return
	}
	klog.Infof("Deleting routes for external gateway pod: %s, for namespace(s) %s", pod.Name,
		podRoutingNamespaceAnno)
	for _, namespace := range strings.Split(podRoutingNamespaceAnno, ",") {
		oc.deletePodGWRoutesForNamespace(pod.Name, namespace, pod.Spec.NodeName)
	}
}

// deletePodGwRoutesForNamespace handles deleting all routes in a namespace for a specific pod GW
func (oc *Controller) deletePodGWRoutesForNamespace(pod, namespace, node string) {
	nsInfo := oc.getNamespaceLocked(namespace)
	if nsInfo == nil {
		return
	}
	defer nsInfo.Unlock()
	// check if any gateways were stored for this pod
	foundGws := nsInfo.routingExternalPodGWs[pod]
	if foundGws == nil {
		klog.Infof("No gateways found to remove for annotated gateway pod: %s on namespace: %s",
			pod, namespace)
		return
	}

	for _, gwIP := range foundGws {
		// check for previously configured pod routes
		for podIP, gwInfo := range nsInfo.podExternalRoutes {
			if len(gwInfo) == 0 {
				continue
			}
			gr := gwInfo[gwIP.String()]
			if gr == "" {
				continue
			}
			mask := GetIPFullMask(podIP)
			// TODO (trozet): use the go bindings here and batch commands
			if err := oc.delHybridRoutePolicyForPod(net.ParseIP(podIP), node); err != nil {
				klog.Error(err)
			}

			_, stderr, err := util.RunOVNNbctl("--", "--if-exists", "--policy=src-ip",
				"lr-route-del", gr, podIP+mask, gwIP.String())
			if err != nil {
				klog.Errorf("Unable to delete pod %s route to GR %s, GW: %s, stderr:%q, err:%v",
					pod, gr, gwIP.String(), stderr, err)
			} else {
				klog.V(5).Infof("ECMP route deleted for pod: %s, on gr: %s, to gw: %s", pod,
					gr, gwIP.String())
				delete(nsInfo.podExternalRoutes[podIP], gwIP.String())
				// clean up if there are no more routes for this podIP
				if entry := nsInfo.podExternalRoutes[podIP]; len(entry) == 0 {
					delete(nsInfo.podExternalRoutes, podIP)
				}
			}
		}
	}
	delete(nsInfo.routingExternalPodGWs, pod)
}

// deleteGwRoutesForNamespace handles deleting all routes to gateways for a pod on a specific GR
// This should only be called with a lock on nsInfo
func (oc *Controller) deleteGWRoutesForNamespace(nsInfo *namespaceInfo) {
	if nsInfo == nil {
		return
	}
	// TODO(trozet): batch all of these with ebay bindings
	for podIP, gwToGr := range nsInfo.podExternalRoutes {
		for gw, gr := range gwToGr {
			mask := GetIPFullMask(podIP)
			node := strings.TrimPrefix(gr, "GR_")
			if err := oc.delHybridRoutePolicyForPod(net.ParseIP(podIP), node); err != nil {
				klog.Error(err)
			}
			_, stderr, err := util.RunOVNNbctl("--", "--if-exists", "--policy=src-ip",
				"lr-route-del", gr, podIP+mask, gw)
			if err != nil {
				klog.Errorf("Unable to delete src-ip route to GR router, stderr:%q, err:%v", stderr, err)
			} else {
				delete(nsInfo.podExternalRoutes, podIP)
			}
		}
	}
	nsInfo.routingExternalGWs = nil
}

// deleteGwRoutesForPod handles deleting all routes to gateways for a pod IP on a specific GR
func (oc *Controller) deleteGWRoutesForPod(namespace string, podIPNets []*net.IPNet) {
	// delete src-ip cached route to GR
	nsInfo := oc.getNamespaceLocked(namespace)
	if nsInfo == nil {
		return
	}
	defer nsInfo.Unlock()
	for _, podIPNet := range podIPNets {
		pod := podIPNet.IP.String()
		if gwToGr, ok := nsInfo.podExternalRoutes[pod]; ok {
			if len(gwToGr) == 0 {
				delete(nsInfo.podExternalRoutes, pod)
				return
			}
			mask := GetIPFullMask(pod)
			for gw, gr := range gwToGr {
				node := strings.TrimPrefix(gr, "GR_")
				if err := oc.delHybridRoutePolicyForPod(podIPNet.IP, node); err != nil {
					klog.Error(err)
				}
				_, stderr, err := util.RunOVNNbctl("--", "--if-exists", "--policy=src-ip",
					"lr-route-del", gr, pod+mask, gw)
				if err != nil {
					klog.Errorf("Unable to delete external gw ecmp route to GR router, stderr:%q, err:%v", stderr, err)
				} else {
					delete(nsInfo.podExternalRoutes, pod)
				}
			}
		}
	}
}

// addEgressGwRoutesForPod handles adding all routes to gateways for a pod on a specific GR
func (oc *Controller) addGWRoutesForPod(routingGWs []net.IP, podIfAddrs []*net.IPNet, namespace, node string) error {
	nsInfo, err := oc.waitForNamespaceLocked(namespace)
	if err != nil {
		return err
	}
	defer nsInfo.Unlock()
	gr := "GR_" + node
	for _, v := range routingGWs {
		gw := v.String()
		// TODO (trozet): use the go bindings here and batch commands
		for _, podIPNet := range podIfAddrs {
			podIP := podIPNet.IP.String()
			mask := GetIPFullMask(podIP)
			_, stderr, err := util.RunOVNNbctl("--may-exist", "--policy=src-ip", "--ecmp-symmetric-reply",
				"lr-route-add", gr, podIP+mask, gw)
			if err != nil {
				return fmt.Errorf("unable to add external gw src-ip route to GR router, stderr:%q, err:%v", stderr, err)
			}

			if err := oc.addHybridRoutePolicyForPod(podIPNet.IP, node); err != nil {
				return err
			}
			if nsInfo.podExternalRoutes[podIP] == nil {
				nsInfo.podExternalRoutes[podIP] = make(map[string]string)
			}
			nsInfo.podExternalRoutes[podIP][gw] = gr
		}
	}
	return nil
}

// deletePerPodGRSNAT removes per pod SNAT rules that are applied to the GR where the pod resides if
// there are no gateways
func (oc *Controller) deletePerPodGRSNAT(node string, podIPNets []*net.IPNet) {
	gr := "GR_" + node
	for _, podIPNet := range podIPNets {
		podIP := podIPNet.IP.String()
		stdout, stderr, err := util.RunOVNNbctl("--", "--if-exists", "lr-nat-del",
			gr, "snat", podIP)
		if err != nil {
			klog.Errorf("Failed to delete SNAT rule for pod on gateway router %s, "+
				"stdout: %q, stderr: %q, error: %v", gr, stdout, stderr, err)
		}
	}
}

func (oc *Controller) addPerPodGRSNAT(pod *kapi.Pod, podIfAddrs []*net.IPNet) error {
	nodeName := pod.Spec.NodeName
	node, err := oc.watchFactory.GetNode(nodeName)
	if err != nil {
		return fmt.Errorf("failed to get node %s: %v", nodeName, err)
	}
	l3GWConfig, err := util.ParseNodeL3GatewayAnnotation(node)
	if err != nil {
		return fmt.Errorf("unable to parse node L3 gw annotation: %v", err)
	}
	gr := "GR_" + nodeName
	for _, gwIPNet := range l3GWConfig.IPAddresses {
		gwIP := gwIPNet.IP.String()
		for _, podIPNet := range podIfAddrs {
			podIP := podIPNet.IP.String()
			mask := GetIPFullMask(podIP)
			// may-exist works only if the the nat rule being added has everything the same i.e.,
			// the type, the router name, external IP and the logical IP must match
			// else the tuple is considered different one than existing.
			// If the type is snat and the logical IP is the same, but external IP is different,
			// even with --may-exist, the add may error out. this is because, for snat,
			// (type, router, logical ip) is considered a key for uniqueness
			stdout, stderr, err := util.RunOVNNbctl("--if-exists", "lr-nat-del", gr, "snat", podIP+mask,
				"--", "lr-nat-add",
				gr, "snat", gwIP, podIP+mask)
			if err != nil {
				return fmt.Errorf("failed to create SNAT rule for pod on gateway router %s, "+
					"stdout: %q, stderr: %q, error: %v", gr, stdout, stderr, err)
			}
		}
	}
	return nil
}

// addHybridRoutePolicyForPod handles adding a higher priority allow policy to allow traffic to be routed normally
// by ecmp routes
func (oc *Controller) addHybridRoutePolicyForPod(podIP net.IP, node string) error {
	if config.Gateway.Mode == config.GatewayModeLocal {
		// add allow policy to bypass lr-policy in GR
		var l3Prefix string
		if utilnet.IsIPv6(podIP) {
			l3Prefix = "ip6"
		} else {
			l3Prefix = "ip4"
		}
		// get the GR to join switch ip address
		out, stderr, err := util.RunOVNNbctl("--data=bare", "--no-heading", "--columns=networks", "find",
			"logical_router_port", fmt.Sprintf("name=rtoj-GR_%s", node))
		if err != nil {
			return fmt.Errorf("unable to find IP address for node: %s, rtoj port, stderr: %s, err: %v", node,
				stderr, err)
		}
		grJoinIP, _, err := net.ParseCIDR(out)
		if err != nil {
			return fmt.Errorf("failed to parse gateway router join interface IP: %s, err: %v", grJoinIP, err)
		}
		matchStr := fmt.Sprintf(`inport == "rtos-%s" && %s.src == %s`, node, l3Prefix, podIP)
		_, stderr, err = util.RunOVNNbctl("lr-policy-add", ovnClusterRouter, "501", matchStr, "reroute",
			grJoinIP.String())
		if err != nil {
			// TODO: lr-policy-add doesn't support --may-exist, resort to this workaround for now.
			// Have raised an issue against ovn repository (https://github.com/ovn-org/ovn/issues/49)
			if !strings.Contains(stderr, "already existed") {
				return fmt.Errorf("failed to add policy route '%s' to %s "+
					"stderr: %s, error: %v", matchStr, ovnClusterRouter, stderr, err)
			}
		}
	}
	return nil
}

// delHybridRoutePolicyForPod handles deleting a higher priority allow policy to allow traffic to be routed normally
// by ecmp routes
func (oc *Controller) delHybridRoutePolicyForPod(podIP net.IP, node string) error {
	if config.Gateway.Mode == config.GatewayModeLocal {
		// delete allow policy to bypass lr-policy in GR
		var l3Prefix string
		if utilnet.IsIPv6(podIP) {
			l3Prefix = "ip6"
		} else {
			l3Prefix = "ip4"
		}
		matchStr := fmt.Sprintf(`inport == "rtos-%s" && %s.src == %s`, node, l3Prefix, podIP)
		_, stderr, err := util.RunOVNNbctl("lr-policy-del", ovnClusterRouter, "501", matchStr)
		if err != nil {
			klog.Errorf("Failed to remove policy: %s, on: %s, stderr: %s, err: %v",
				matchStr, ovnClusterRouter, stderr, err)
		}
	}
	return nil
}
