package ovn

import (
	"fmt"
	"net"
	"time"

	"github.com/ovn-org/libovsdb/ovsdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	libovsdbops "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
)

func (oc *DefaultNetworkController) getRoutingExternalGWs(nsInfo *namespaceInfo) *gatewayInfo {
	res := gatewayInfo{}
	// return a copy of the object so it can be handled without the
	// namespace locked
	res.bfdEnabled = nsInfo.routingExternalGWs.bfdEnabled
	res.gws = sets.New(nsInfo.routingExternalGWs.gws.UnsortedList()...)
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

func (oc *DefaultNetworkController) getRoutingPodGWs(nsInfo *namespaceInfo) map[string]gatewayInfo {
	// return a copy of the object so it can be handled without the
	// namespace locked
	res := make(map[string]gatewayInfo)
	for k, v := range nsInfo.routingExternalPodGWs {
		item := gatewayInfo{
			bfdEnabled: v.bfdEnabled,
			gws:        sets.New(v.gws.UnsortedList()...),
		}
		res[k] = item
	}
	return res
}

// addPodToNamespace returns pod's routing gateway info and the ops needed
// to add pod's IP to the namespace's address set.
func (oc *DefaultNetworkController) addPodToNamespace(ns string, ips []*net.IPNet) (*gatewayInfo, map[string]gatewayInfo, []ovsdb.Operation, error) {
	var ops []ovsdb.Operation
	var err error
	nsInfo, nsUnlock, err := oc.ensureNamespaceLocked(ns, true, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to ensure namespace locked: %v", err)
	}

	defer nsUnlock()

	if ops, err = nsInfo.addressSet.AddIPsReturnOps(createIPAddressSlice(ips)); err != nil {
		return nil, nil, nil, err
	}

	return oc.getRoutingExternalGWs(nsInfo), oc.getRoutingPodGWs(nsInfo), ops, nil
}

func (oc *DefaultNetworkController) addRemotePodToNamespace(ns string, ips []*net.IPNet) error {
	_, _, ops, err := oc.addPodToNamespace(ns, ips)

	if err == nil {
		_, err = libovsdbops.TransactAndCheck(oc.nbClient, ops)
		if err != nil {
			return fmt.Errorf("could not add pod IPs to the namespace address set - %+v", err)
		}
	}
	return err
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

// AddNamespace creates corresponding addressset in ovn db
func (oc *DefaultNetworkController) AddNamespace(ns *kapi.Namespace) error {
	klog.Infof("[%s] adding namespace", ns.Name)
	// Keep track of how long syncs take.
	start := time.Now()
	defer func() {
		klog.Infof("[%s] adding namespace took %v", ns.Name, time.Since(start))
	}()

	_, nsUnlock, err := oc.ensureNamespaceLocked(ns.Name, false, ns)
	if err != nil {
		return fmt.Errorf("failed to ensure namespace locked: %v", err)
	}
	defer nsUnlock()
	return nil
}

// configureNamespace ensures internal structures are updated based on namespace
// must be called with nsInfo lock
func (oc *DefaultNetworkController) configureNamespace(nsInfo *namespaceInfo, ns *kapi.Namespace) error {
	var errors []error

	if annotation, ok := ns.Annotations[util.RoutingExternalGWsAnnotation]; ok {
		exGateways, err := util.ParseRoutingExternalGWAnnotation(annotation)
		if err != nil {
			errors = append(errors, fmt.Errorf("failed to parse external gateway annotation (%v)", err))
		} else {
			_, bfdEnabled := ns.Annotations[util.BfdAnnotation]
			err = oc.addExternalGWsForNamespace(gatewayInfo{gws: exGateways, bfdEnabled: bfdEnabled}, nsInfo, ns.Name)
			if err != nil {
				errors = append(errors, fmt.Errorf("failed to add external gateway for namespace %s (%v)", ns.Name, err))
			}
		}
		if _, ok := ns.Annotations[util.BfdAnnotation]; ok {
			nsInfo.routingExternalGWs.bfdEnabled = true
		}
	}

	if err := oc.configureNamespaceCommon(nsInfo, ns); err != nil {
		errors = append(errors, err)
	}
	return kerrors.NewAggregate(errors)
}

func (oc *DefaultNetworkController) updateNamespace(old, newer *kapi.Namespace) error {
	var errors []error
	klog.Infof("[%s] updating namespace", old.Name)

	nsInfo, nsUnlock := oc.getNamespaceLocked(old.Name, false)
	if nsInfo == nil {
		klog.Warningf("Update event for unknown namespace %q", old.Name)
		return nil
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
					errors = append(errors, fmt.Errorf("failed to get all the pods (%v)", err))
				}
				for _, pod := range existingPods {
					if !oc.isPodScheduledinLocalZone(pod) {
						continue
					}

					logicalPort := util.GetLogicalPortName(pod.Namespace, pod.Name)
					if util.PodWantsHostNetwork(pod) {
						continue
					}
					podIPs, err := util.GetPodIPsOfNetwork(pod, oc.NetInfo)
					if err != nil {
						errors = append(errors, fmt.Errorf("unable to get pod %q IPs for SNAT rule removal err (%v)", logicalPort, err))
					}
					ips := make([]*net.IPNet, 0, len(podIPs))
					for _, podIP := range podIPs {
						ips = append(ips, &net.IPNet{IP: podIP})
					}
					if len(ips) > 0 {
						if extIPs, err := getExternalIPsGR(oc.watchFactory, pod.Spec.NodeName); err != nil {
							errors = append(errors, err)
						} else if err = oc.deletePodSNAT(pod.Spec.NodeName, extIPs, ips); err != nil {
							errors = append(errors, err)
						}
					}
				}
			}
		} else {
			if err := oc.deleteGWRoutesForNamespace(old.Name, nil); err != nil {
				errors = append(errors, err)
			}
			nsInfo.routingExternalGWs = gatewayInfo{}
		}
		exGateways, err := util.ParseRoutingExternalGWAnnotation(gwAnnotation)
		if err != nil {
			errors = append(errors, err)
		} else {
			if exGateways.Len() != 0 {
				err = oc.addExternalGWsForNamespace(gatewayInfo{gws: exGateways, bfdEnabled: newBFDEnabled}, nsInfo, old.Name)
				if err != nil {
					errors = append(errors, err)
				}
			}
		}
		// if new annotation is empty, exgws were removed, may need to add SNAT per pod
		// check if there are any pod gateways serving this namespace as well
		if gwAnnotation == "" && len(nsInfo.routingExternalPodGWs) == 0 && config.Gateway.DisableSNATMultipleGWs {
			existingPods, err := oc.watchFactory.GetPods(old.Name)
			if err != nil {
				errors = append(errors, fmt.Errorf("failed to get all the pods (%v)", err))
			}
			for _, pod := range existingPods {
				if !oc.isPodScheduledinLocalZone(pod) && !util.PodNeedsSNAT(pod) {
					continue
				}
				podAnnotation, err := util.UnmarshalPodAnnotation(pod.Annotations, types.DefaultNetworkName)
				if err != nil {
					errors = append(errors, err)
				} else {
					if extIPs, err := getExternalIPsGR(oc.watchFactory, pod.Spec.NodeName); err != nil {
						errors = append(errors, err)
					} else if err = addOrUpdatePodSNAT(oc.nbClient, pod.Spec.NodeName, extIPs, podAnnotation.IPs); err != nil {
						errors = append(errors, err)
					}
				}
			}
		}
	}
	aclAnnotation := newer.Annotations[util.AclLoggingAnnotation]
	oldACLAnnotation := old.Annotations[util.AclLoggingAnnotation]
	// support for ACL logging update, if new annotation is empty, make sure we propagate new setting
	if aclAnnotation != oldACLAnnotation {
		if err := oc.updateNamespaceAclLogging(old.Name, aclAnnotation, nsInfo); err != nil {
			errors = append(errors, err)
		}
		// Trigger an egress fw logging update - this will only happen if an egress firewall exists for the NS, otherwise
		// this will not do anything.
		updated, err := oc.updateACLLoggingForEgressFirewall(old.Name, nsInfo)
		if err != nil {
			errors = append(errors, err)
		} else if updated {
			klog.Infof("Namespace %s: EgressFirewall ACL logging setting updated to deny=%s allow=%s",
				old.Name, nsInfo.aclLogging.Deny, nsInfo.aclLogging.Allow)
		}
	}

	if err := oc.multicastUpdateNamespace(newer, nsInfo); err != nil {
		errors = append(errors, err)
	}
	return kerrors.NewAggregate(errors)
}

func (oc *DefaultNetworkController) deleteNamespace(ns *kapi.Namespace) error {
	klog.Infof("[%s] deleting namespace", ns.Name)

	nsInfo := oc.deleteNamespaceLocked(ns.Name)
	if nsInfo == nil {
		return nil
	}
	defer nsInfo.Unlock()

	if err := oc.deleteGWRoutesForNamespace(ns.Name, nil); err != nil {
		return fmt.Errorf("failed to delete GW routes for namespace: %s, error: %v", ns.Name, err)
	}
	if err := oc.multicastDeleteNamespace(ns, nsInfo); err != nil {
		return fmt.Errorf("failed to delete multicast namespace error %v", err)
	}
	return nil
}

// ensureNamespaceLocked locks namespacesMutex, gets/creates an entry for ns, configures OVN nsInfo, and returns it
// with its mutex locked.
// ns is the name of the namespace, while namespace is the optional k8s namespace object
func (oc *DefaultNetworkController) ensureNamespaceLocked(ns string, readOnly bool, namespace *kapi.Namespace) (*namespaceInfo, func(), error) {
	ipsGetter := func(ns string) []net.IP {
		// special handling of host network namespace. issues/3381
		if config.Kubernetes.HostNetworkNamespace != "" && ns == config.Kubernetes.HostNetworkNamespace {
			return oc.getAllHostNamespaceAddresses()
		}
		return oc.getAllNamespacePodAddresses(ns)
	}
	return oc.ensureNamespaceLockedCommon(ns, readOnly, namespace, ipsGetter, oc.configureNamespace)
}

func (oc *DefaultNetworkController) getAllHostNamespaceAddresses() []net.IP {
	var ips []net.IP
	// add the mp0 interface addresses to this namespace.
	existingNodes, err := oc.watchFactory.GetNodes()
	if err != nil {
		klog.Errorf("Failed to get all nodes (%v)", err)
	} else {
		ips = make([]net.IP, 0, len(existingNodes))
		for _, node := range existingNodes {
			hostSubnets, err := util.ParseNodeHostSubnetAnnotation(node, types.DefaultNetworkName)
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
			lrpIPs, err := util.ParseNodeGatewayRouterLRPAddrs(node)
			if err != nil {
				klog.Errorf("Failed to get join switch port IP address for node %s: %v", node.Name, err)
			}

			for _, lrpIP := range lrpIPs {
				ips = append(ips, lrpIP.IP)
			}
		}
	}
	return ips
}
