package ovn

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/ovn-org/libovsdb/ovsdb"
	hotypes "github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	addressset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/address_set"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
)

// This function implements the main body of work of syncNamespaces.
// Upon failure, it may be invoked multiple times in order to avoid a pod restart.
func (oc *Controller) syncNamespaces(namespaces []interface{}) error {
	expectedNs := make(map[string]bool)
	for _, nsInterface := range namespaces {
		ns, ok := nsInterface.(*kapi.Namespace)
		if !ok {
			return fmt.Errorf("spurious object in syncNamespaces: %v", nsInterface)
		}
		expectedNs[ns.Name] = true
	}

	err := oc.addressSetFactory.ProcessEachAddressSet(func(addrSetName, namespaceName, nameSuffix string) error {
		if nameSuffix == "" && !expectedNs[namespaceName] {
			if err := oc.addressSetFactory.DestroyAddressSetInBackingStore(addrSetName); err != nil {
				klog.Errorf(err.Error())
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("error in syncing namespaces: %v", err)
	}
	return nil
}

func (oc *Controller) getRoutingExternalGWs(nsInfo *namespaceInfo) *gatewayInfo {
	res := gatewayInfo{}
	// return a copy of the object so it can be handled without the
	// namespace locked
	res.bfdEnabled = nsInfo.routingExternalGWs.bfdEnabled
	res.gws = sets.NewString(nsInfo.routingExternalGWs.gws.UnsortedList()...)
	return &res
}

// wrapper function to log if there are duplicate gateway IPs present in the cache
func validateRoutingPodGWs(podGWs map[string]gatewayInfo) error {
	// map to hold IP/podName
	ipTracker := make(map[string]string)
	for podName, gwInfo := range podGWs {
		for _, gwIP := range gwInfo.gws.UnsortedList() {
			if foundPod, ok := ipTracker[gwIP]; ok {
				return fmt.Errorf("duplicate IP found in ECMP Pod route cache! IP: %q, first pod: %q, second "+
					"pod: %q", gwIP, podName, foundPod)
			}
			ipTracker[gwIP] = podName
		}
	}
	return nil
}

func (oc *Controller) getRoutingPodGWs(nsInfo *namespaceInfo) map[string]gatewayInfo {
	// return a copy of the object so it can be handled without the
	// namespace locked
	res := make(map[string]gatewayInfo)
	for k, v := range nsInfo.routingExternalPodGWs {
		item := gatewayInfo{
			bfdEnabled: v.bfdEnabled,
			gws:        sets.NewString(v.gws.UnsortedList()...),
		}
		res[k] = item
	}
	return res
}

// addPodToNamespace returns pod's routing gateway info and the ops needed
// to add pod's IP to the namespace's address set.
func (oc *Controller) addPodToNamespace(ns string, ips []*net.IPNet) (*gatewayInfo, map[string]gatewayInfo, net.IP, []ovsdb.Operation, error) {
	var ops []ovsdb.Operation
	var err error
	nsInfo, nsUnlock, err := oc.ensureNamespaceLocked(ns, true, nil)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to ensure namespace locked: %v", err)
	}

	defer nsUnlock()

	if ops, err = nsInfo.addressSet.AddIPsReturnOps(createIPAddressSlice(ips)); err != nil {
		return nil, nil, nil, nil, err
	}

	return oc.getRoutingExternalGWs(nsInfo), oc.getRoutingPodGWs(nsInfo), nsInfo.hybridOverlayExternalGW, ops, nil
}

func (oc *Controller) deletePodFromNamespace(ns string, podIfAddrs []*net.IPNet, portUUID string) ([]ovsdb.Operation, error) {
	nsInfo, nsUnlock := oc.getNamespaceLocked(ns, true)
	if nsInfo == nil {
		return nil, nil
	}
	defer nsUnlock()
	var ops []ovsdb.Operation
	var err error
	if nsInfo.addressSet != nil {
		if ops, err = nsInfo.addressSet.DeleteIPsReturnOps(createIPAddressSlice(podIfAddrs)); err != nil {
			return nil, err
		}
	}

	// Remove the port from the multicast allow policy.
	if oc.multicastSupport && nsInfo.multicastEnabled && len(portUUID) > 0 {
		if err = podDeleteAllowMulticastPolicy(oc.nbClient, ns, portUUID); err != nil {
			return nil, err
		}
	}

	return ops, nil
}

func createIPAddressSlice(ips []*net.IPNet) []net.IP {
	ipAddrs := make([]net.IP, 0)
	for _, ip := range ips {
		ipAddrs = append(ipAddrs, ip.IP)
	}
	return ipAddrs
}

func isNamespaceMulticastEnabled(annotations map[string]string) bool {
	return annotations[util.NsMulticastAnnotation] == "true"
}

// Creates an explicit "allow" policy for multicast traffic within the
// namespace if multicast is enabled. Otherwise, removes the "allow" policy.
// Traffic will be dropped by the default multicast deny ACL.
func (oc *Controller) multicastUpdateNamespace(ns *kapi.Namespace, nsInfo *namespaceInfo) {
	if !oc.multicastSupport {
		return
	}

	enabled := isNamespaceMulticastEnabled(ns.Annotations)
	enabledOld := nsInfo.multicastEnabled
	if enabledOld == enabled {
		return
	}

	var err error
	nsInfo.multicastEnabled = enabled
	if enabled {
		err = oc.createMulticastAllowPolicy(ns.Name, nsInfo)
	} else {
		err = deleteMulticastAllowPolicy(oc.nbClient, ns.Name)
	}
	if err != nil {
		klog.Errorf(err.Error())
		return
	}
}

// Cleans up the multicast policy for this namespace if multicast was
// previously allowed.
func (oc *Controller) multicastDeleteNamespace(ns *kapi.Namespace, nsInfo *namespaceInfo) {
	if nsInfo.multicastEnabled {
		nsInfo.multicastEnabled = false
		if err := deleteMulticastAllowPolicy(oc.nbClient, ns.Name); err != nil {
			klog.Errorf(err.Error())
		}
	}
}

// AddNamespace creates corresponding addressset in ovn db
func (oc *Controller) AddNamespace(ns *kapi.Namespace) {
	klog.Infof("[%s] adding namespace", ns.Name)
	// Keep track of how long syncs take.
	start := time.Now()
	defer func() {
		klog.Infof("[%s] adding namespace took %v", ns.Name, time.Since(start))
	}()

	nsInfo, nsUnlock, err := oc.ensureNamespaceLocked(ns.Name, false, ns)
	if err != nil {
		klog.Errorf("Failed to ensure namespace locked: %v", err)
		return
	}

	defer nsUnlock()

	annotation := ns.Annotations[hotypes.HybridOverlayExternalGw]
	if annotation != "" {
		parsedAnnotation := net.ParseIP(annotation)
		if parsedAnnotation == nil {
			klog.Errorf("Could not parse hybrid overlay external gw annotation")
		} else {
			nsInfo.hybridOverlayExternalGW = parsedAnnotation
		}
	}
	annotation = ns.Annotations[hotypes.HybridOverlayVTEP]
	if annotation != "" {
		parsedAnnotation := net.ParseIP(annotation)
		if parsedAnnotation == nil {
			klog.Errorf("Could not parse hybrid overlay VTEP annotation")
		} else {
			nsInfo.hybridOverlayVTEP = parsedAnnotation
		}
	}
}

// configureNamespace ensures internal structures are updated based on namespace
// must be called with nsInfo lock
func (oc *Controller) configureNamespace(nsInfo *namespaceInfo, ns *kapi.Namespace) {
	if annotation, ok := ns.Annotations[util.RoutingExternalGWsAnnotation]; ok {
		exGateways, err := util.ParseRoutingExternalGWAnnotation(annotation)
		if err != nil {
			klog.Errorf(err.Error())
		} else {
			_, bfdEnabled := ns.Annotations[util.BfdAnnotation]
			err = oc.addExternalGWsForNamespace(gatewayInfo{gws: exGateways, bfdEnabled: bfdEnabled}, nsInfo, ns.Name)
			if err != nil {
				klog.Error(err.Error())
			}
		}
		if _, ok := ns.Annotations[util.BfdAnnotation]; ok {
			nsInfo.routingExternalGWs.bfdEnabled = true
		}
	}

	annotation := ns.Annotations[util.AclLoggingAnnotation]
	if annotation != "" {
		if oc.aclLoggingCanEnable(annotation, nsInfo) {
			klog.Infof("Namespace %s: ACL logging is set to deny=%s allow=%s", ns.Name, nsInfo.aclLogging.Deny, nsInfo.aclLogging.Allow)
		} else {
			klog.Warningf("Namespace %s: ACL logging is not enabled due to malformed annotation", ns.Name)
		}
	}

	// TODO(trozet) figure out if there is any possibility of detecting if a pod GW already exists, which
	// is servicing this namespace. Right now that would mean searching through all pods, which is very inefficient.
	// For now it is required that a pod serving as a gateway for a namespace is added AFTER the serving namespace is
	// created

	// If multicast enabled, adds all current pods in the namespace to the allow policy
	oc.multicastUpdateNamespace(ns, nsInfo)
}

func (oc *Controller) updateNamespace(old, newer *kapi.Namespace) {
	klog.Infof("[%s] updating namespace", old.Name)

	nsInfo, nsUnlock := oc.getNamespaceLocked(old.Name, false)
	if nsInfo == nil {
		klog.Warningf("Update event for unknown namespace %q", old.Name)
		return
	}
	defer nsUnlock()

	gwAnnotation := newer.Annotations[util.RoutingExternalGWsAnnotation]
	oldGWAnnotation := old.Annotations[util.RoutingExternalGWsAnnotation]
	_, newBFDEnabled := newer.Annotations[util.BfdAnnotation]
	_, oldBFDEnabled := old.Annotations[util.BfdAnnotation]

	if gwAnnotation != oldGWAnnotation || newBFDEnabled != oldBFDEnabled {
		// if old gw annotation was empty, new one must not be empty, so we should remove any per pod SNAT towards nodeIP
		if oldGWAnnotation == "" {
			if config.Gateway.DisableSNATMultipleGWs {
				existingPods, err := oc.watchFactory.GetPods(old.Name)
				if err != nil {
					klog.Errorf("Failed to get all the pods (%v)", err)
				}
				for _, pod := range existingPods {
					logicalPort := util.GetLogicalPortName(pod.Namespace, pod.Name)
					if !util.PodWantsNetwork(pod) {
						continue
					}
					podIPs, err := util.GetAllPodIPs(pod)
					if err != nil {
						klog.Warningf("Unable to get pod %q IPs for SNAT rule removal", logicalPort)
					}
					ips := make([]*net.IPNet, 0, len(podIPs))
					for _, podIP := range podIPs {
						ips = append(ips, &net.IPNet{IP: podIP})
					}
					if len(ips) > 0 {
						if extIPs, err := getExternalIPsGRSNAT(oc.watchFactory, pod.Spec.NodeName); err != nil {
							klog.Error(err.Error())
						} else if err = deletePerPodGRSNAT(oc.nbClient, pod.Spec.NodeName, extIPs, ips); err != nil {
							klog.Error(err.Error())
						}
					}
				}
			}
		} else {
			if err := oc.deleteGWRoutesForNamespace(old.Name, nil); err != nil {
				klog.Error(err.Error())
			}
			nsInfo.routingExternalGWs = gatewayInfo{}
		}
		exGateways, err := util.ParseRoutingExternalGWAnnotation(gwAnnotation)
		if err != nil {
			klog.Error(err.Error())
		} else {
			err = oc.addExternalGWsForNamespace(gatewayInfo{gws: exGateways, bfdEnabled: newBFDEnabled}, nsInfo, old.Name)
			if err != nil {
				klog.Error(err.Error())
			}
		}
		// if new annotation is empty, exgws were removed, may need to add SNAT per pod
		// check if there are any pod gateways serving this namespace as well
		if gwAnnotation == "" && len(nsInfo.routingExternalPodGWs) == 0 && config.Gateway.DisableSNATMultipleGWs {
			existingPods, err := oc.watchFactory.GetPods(old.Name)
			if err != nil {
				klog.Errorf("Failed to get all the pods (%v)", err)
			}
			for _, pod := range existingPods {
				podAnnotation, err := util.UnmarshalPodAnnotation(pod.Annotations)
				if err != nil {
					klog.Error(err.Error())
				} else {
					if extIPs, err := getExternalIPsGRSNAT(oc.watchFactory, pod.Spec.NodeName); err != nil {
						klog.Error(err.Error())
					} else if err = addOrUpdatePerPodGRSNAT(oc.nbClient, pod.Spec.NodeName, extIPs, podAnnotation.IPs); err != nil {
						klog.Error(err.Error())
					}
				}
			}
		}
	}
	aclAnnotation := newer.Annotations[util.AclLoggingAnnotation]
	oldACLAnnotation := old.Annotations[util.AclLoggingAnnotation]
	// support for ACL logging update, if new annotation is empty, make sure we propagate new setting
	if aclAnnotation != oldACLAnnotation && (oc.aclLoggingCanEnable(aclAnnotation, nsInfo) || aclAnnotation == "") {
		if len(nsInfo.networkPolicies) > 0 {
			// deny rules are all one per namespace
			if err := oc.setNetworkPolicyACLLoggingForNamespace(old.Name, nsInfo); err != nil {
				klog.Warningf(err.Error())
			} else {
				klog.Infof("Namespace %s: NetworkPolicy ACL logging setting updated to deny=%s allow=%s",
					old.Name, nsInfo.aclLogging.Deny, nsInfo.aclLogging.Allow)
			}
		}
		// Trigger an egress fw logging update - this will only happen if an egress firewall exists for the NS, otherwise
		// this will not do anything.
		updated, err := oc.refreshEgressFirewallLogging(old.Name)
		if err != nil {
			klog.Warningf(err.Error())
		} else if updated {
			klog.Infof("Namespace %s: EgressFirewall ACL logging setting updated to deny=%s allow=%s",
				old.Name, nsInfo.aclLogging.Deny, nsInfo.aclLogging.Allow)
		}
	}

	annotation := newer.Annotations[hotypes.HybridOverlayExternalGw]
	if annotation != "" {
		parsedAnnotation := net.ParseIP(annotation)
		if parsedAnnotation == nil {
			klog.Errorf("Could not parse hybrid overlay external gw annotation")
		} else {
			nsInfo.hybridOverlayExternalGW = parsedAnnotation
		}
	} else {
		nsInfo.hybridOverlayExternalGW = nil
	}
	annotation = newer.Annotations[hotypes.HybridOverlayVTEP]
	if annotation != "" {
		parsedAnnotation := net.ParseIP(annotation)
		if parsedAnnotation == nil {
			klog.Errorf("Could not parse hybrid overlay VTEP annotation")
		} else {
			nsInfo.hybridOverlayVTEP = parsedAnnotation
		}
	} else {
		nsInfo.hybridOverlayVTEP = nil
	}
	oc.multicastUpdateNamespace(newer, nsInfo)
}

func (oc *Controller) deleteNamespace(ns *kapi.Namespace) {
	klog.Infof("[%s] deleting namespace", ns.Name)

	nsInfo := oc.deleteNamespaceLocked(ns.Name)
	if nsInfo == nil {
		return
	}
	defer nsInfo.Unlock()

	klog.V(5).Infof("Deleting Namespace's NetworkPolicy entities")
	for _, np := range nsInfo.networkPolicies {
		key := getPolicyNamespacedName(np.policy)
		oc.retryNetworkPolicies.skipRetryObj(key)
		// add the full np object to the retry entry, since the namespace is going to be removed
		// along with any mappings of nsInfo -> network policies
		oc.retryNetworkPolicies.initRetryObjWithDelete(np.policy, key, np, false)
		isLastPolicyInNamespace := len(nsInfo.networkPolicies) == 1
		if err := oc.destroyNetworkPolicy(np, isLastPolicyInNamespace); err != nil {
			klog.Errorf("Failed to delete network policy: %s, error: %v", key, err)
			oc.retryNetworkPolicies.unSkipRetryObj(key)
		} else {
			oc.retryNetworkPolicies.deleteRetryObj(key, true)
			delete(nsInfo.networkPolicies, np.name)
		}
	}
	if err := oc.deleteGWRoutesForNamespace(ns.Name, nil); err != nil {
		klog.Errorf("Failed to delete GW routes for namespace: %s, error: %v", ns.Name, err)
	}
	oc.multicastDeleteNamespace(ns, nsInfo)
}

// getNamespaceLocked locks namespacesMutex, looks up ns, and (if found), returns it with
// its mutex locked. If ns is not known, nil will be returned
func (oc *Controller) getNamespaceLocked(ns string, readOnly bool) (*namespaceInfo, func()) {
	// Only hold namespacesMutex while reading/modifying oc.namespaces. In particular,
	// we drop namespacesMutex while trying to claim nsInfo.Mutex, because something
	// else might have locked the nsInfo and be doing something slow with it, and we
	// don't want to block all access to oc.namespaces while that's happening.
	oc.namespacesMutex.Lock()
	nsInfo := oc.namespaces[ns]
	oc.namespacesMutex.Unlock()

	if nsInfo == nil {
		return nil, nil
	}
	var unlockFunc func()
	if readOnly {
		unlockFunc = func() { nsInfo.RUnlock() }
		nsInfo.RLock()
	} else {
		unlockFunc = func() { nsInfo.Unlock() }
		nsInfo.Lock()
	}
	// Check that the namespace wasn't deleted while we were waiting for the lock
	oc.namespacesMutex.Lock()
	defer oc.namespacesMutex.Unlock()
	if nsInfo != oc.namespaces[ns] {
		unlockFunc()
		return nil, nil
	}
	return nsInfo, unlockFunc
}

// ensureNamespaceLocked locks namespacesMutex, gets/creates an entry for ns, configures OVN nsInfo, and returns it
// with its mutex locked.
// ns is the name of the namespace, while namespace is the optional k8s namespace object
// if no k8s namespace object is provided, this function will attempt to find it via informer cache
func (oc *Controller) ensureNamespaceLocked(ns string, readOnly bool, namespace *kapi.Namespace) (*namespaceInfo, func(), error) {
	oc.namespacesMutex.Lock()
	nsInfo := oc.namespaces[ns]
	nsInfoExisted := false
	if nsInfo == nil {
		nsInfo = &namespaceInfo{
			networkPolicies:       make(map[string]*networkPolicy),
			multicastEnabled:      false,
			routingExternalPodGWs: make(map[string]gatewayInfo),
			routingExternalGWs:    gatewayInfo{gws: sets.NewString(), bfdEnabled: false},
		}
		// we are creating nsInfo and going to set it in namespaces map
		// so safe to hold the lock while we create and add it
		defer oc.namespacesMutex.Unlock()
		// create the adddress set for the new namespace
		var err error
		nsInfo.addressSet, err = oc.createNamespaceAddrSetAllPods(ns)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create address set for namespace: %s, error: %v", ns, err)
		}
		oc.namespaces[ns] = nsInfo
	} else {
		nsInfoExisted = true
		// if we found an existing nsInfo, do not hold the namespaces lock
		// while waiting for nsInfo to Lock
		oc.namespacesMutex.Unlock()
	}

	var unlockFunc func()
	if readOnly {
		unlockFunc = func() { nsInfo.RUnlock() }
		nsInfo.RLock()
	} else {
		unlockFunc = func() { nsInfo.Unlock() }
		nsInfo.Lock()
	}

	if nsInfoExisted {
		// Check that the namespace wasn't deleted while we were waiting for the lock
		oc.namespacesMutex.Lock()
		defer oc.namespacesMutex.Unlock()
		if nsInfo != oc.namespaces[ns] {
			unlockFunc()
			return nil, nil, fmt.Errorf("namespace %s, was removed during ensure", ns)
		}
	}

	// nsInfo and namespace didn't exist, get it from lister
	if namespace == nil {
		var err error
		namespace, err = oc.watchFactory.GetNamespace(ns)
		if err != nil {
			namespace, err = oc.client.CoreV1().Namespaces().Get(context.TODO(), ns, metav1.GetOptions{})
			if err != nil {
				klog.Warningf("Unable to find namespace during ensure in informer cache or kube api server. " +
					"Will defer configuring namespace.")
			}
		}
	}

	if namespace != nil {
		// if we have the namespace, attempt to configure nsInfo with it
		oc.configureNamespace(nsInfo, namespace)
	}

	return nsInfo, unlockFunc, nil
}

// deleteNamespaceLocked locks namespacesMutex, finds and deletes ns, and returns the
// namespace, locked.
func (oc *Controller) deleteNamespaceLocked(ns string) *namespaceInfo {
	// The locking here is the same as in getNamespaceLocked

	oc.namespacesMutex.Lock()
	nsInfo := oc.namespaces[ns]
	oc.namespacesMutex.Unlock()

	if nsInfo == nil {
		return nil
	}
	nsInfo.Lock()

	oc.namespacesMutex.Lock()
	defer oc.namespacesMutex.Unlock()
	if nsInfo != oc.namespaces[ns] {
		nsInfo.Unlock()
		return nil
	}
	if nsInfo.addressSet != nil {
		// Empty the address set, then delete it after an interval.
		if err := nsInfo.addressSet.SetIPs(nil); err != nil {
			klog.Errorf("Warning: failed to empty address set for deleted NS %s: %v", ns, err)
		}

		// Delete the address set after a short delay.
		// This is so NetworkPolicy handlers can converge and stop referencing it.
		addressSet := nsInfo.addressSet
		go func() {
			select {
			case <-oc.stopChan:
				return
			case <-time.After(20 * time.Second):
				// Check to see if the NS was re-added in the meanwhile. If so,
				// only delete if the new NS's AddressSet shouldn't exist.
				nsInfo, nsUnlock := oc.getNamespaceLocked(ns, true)
				if nsInfo != nil {
					defer nsUnlock()
					if nsInfo.addressSet != nil {
						klog.V(5).Infof("Skipping deferred deletion of AddressSet for NS %s: re-created", ns)
						return
					}
				}

				klog.V(5).Infof("Finishing deferred deletion of AddressSet for NS %s", ns)
				if err := addressSet.Destroy(); err != nil {
					klog.Errorf("Failed to delete AddressSet for NS %s: %v", ns, err.Error())
				}
			}
		}()
	}
	delete(oc.namespaces, ns)

	return nsInfo
}

func (oc *Controller) createNamespaceAddrSetAllPods(ns string) (addressset.AddressSet, error) {
	var ips []net.IP
	// special handling of host network namespace
	if config.Kubernetes.HostNetworkNamespace != "" &&
		ns == config.Kubernetes.HostNetworkNamespace {
		// add the mp0 interface addresses to this namespace.
		existingNodes, err := oc.watchFactory.GetNodes()
		if err != nil {
			klog.Errorf("Failed to get all nodes (%v)", err)
		} else {
			ips = make([]net.IP, 0, len(existingNodes))
			for _, node := range existingNodes {
				hostSubnets, err := util.ParseNodeHostSubnetAnnotation(node)
				if err != nil {
					klog.Warningf("Error parsing host subnet annotation for node %s (%v)",
						node.Name, err)
				}
				for _, hostSubnet := range hostSubnets {
					mgmtIfAddr := util.GetNodeManagementIfAddr(hostSubnet)
					ips = append(ips, mgmtIfAddr.IP)
				}
				// for shared gateway mode we will use LRP IPs to SNAT host network traffic
				// so add these to the address set.
				lrpIPs, err := oc.joinSwIPManager.EnsureJoinLRPIPs(node.Name)
				if err != nil {
					klog.Errorf("Failed to get join switch port IP address for node %s: %v", node.Name, err)
				}

				for _, lrpIP := range lrpIPs {
					ips = append(ips, lrpIP.IP)
				}
			}
		}
	}
	// Get all the pods in the namespace and append their IP to the address_set
	existingPods, err := oc.watchFactory.GetPods(ns)
	if err != nil {
		klog.Errorf("Failed to get all the pods (%v)", err)
	} else {
		ips = make([]net.IP, 0, len(existingPods))
		for _, pod := range existingPods {
			if util.PodWantsNetwork(pod) && !util.PodCompleted(pod) && util.PodScheduled(pod) {
				podIPs, err := util.GetAllPodIPs(pod)
				if err != nil {
					klog.Warningf(err.Error())
					continue
				}
				ips = append(ips, podIPs...)
			}
		}
	}
	return oc.addressSetFactory.NewAddressSet(ns, ips)
}
