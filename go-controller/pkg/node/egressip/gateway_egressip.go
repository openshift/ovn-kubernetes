package egressip

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	corev1informers "k8s.io/client-go/informers/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"

	"github.com/gaissmai/cidrtree"
	egressipv1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1"
	egressipinformers "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/informers/externalversions/egressip/v1"
	egressiplisters "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/listers/egressip/v1"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/node/linkmanager"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

// markIPs contains packet mark and associated EgressIP IP for IPv4 / IPv6. Key is packet mark, value egress IP
type markIPs struct {
	v4 map[int]string
	v6 map[int]string
}

func (e markIPs) insert(mark util.EgressIPMark, ip net.IP) {
	if len(ip) == 0 || !mark.IsAvailable() || !mark.IsValid() {
		klog.Errorf("Insertion of EgressIP config failed: invalid: IP %v, mark %v", ip, mark)
		return
	}
	if ip.To4() != nil {
		e.v4[mark.ToInt()] = ip.String()
	} else if ip.To16() != nil {
		e.v6[mark.ToInt()] = ip.String()
	}
}

func (e markIPs) delete(mark util.EgressIPMark, ip net.IP) {
	if ip == nil || !mark.IsAvailable() || !mark.IsValid() {
		klog.Errorf("Deletion of EgressIP config failed: invalid: IP %v, mark %v", ip, mark)
		return
	}
	if ip.To4() != nil {
		delete(e.v4, mark.ToInt())
	} else if ip.To16() != nil {
		delete(e.v6, mark.ToInt())
	}
}

func (e markIPs) containsIP(ip net.IP) bool {
	if len(ip) == 0 {
		klog.Errorf("Invalid IP argument therefore not checking EgressIP config cache: IP %v", ip)
		return false
	}
	ipStr := ip.String()
	var m map[int]string
	if ip.To4() != nil {
		m = e.v4
	} else if ip.To16() != nil {
		m = e.v6
	}
	for _, existingIP := range m {
		if existingIP == ipStr {
			return true
		}
	}
	return false
}

type MarkIPsCache struct {
	mu          sync.Mutex
	hasSyncOnce bool
	markToIPs   markIPs
	IPToMark    map[string]int
}

func NewMarkIPsCache() *MarkIPsCache {
	return &MarkIPsCache{
		mu: sync.Mutex{},
		markToIPs: markIPs{
			v4: make(map[int]string),
			v6: make(map[int]string),
		},
		IPToMark: map[string]int{},
	}
}

func (mic *MarkIPsCache) IsIPPresent(ip net.IP) bool {
	mic.mu.Lock()
	defer mic.mu.Unlock()
	if ip == nil {
		return false
	}
	_, isFound := mic.IPToMark[ip.String()]
	return isFound
}

func (mic *MarkIPsCache) insertMarkIP(pktMark util.EgressIPMark, ip net.IP) {
	mic.mu.Lock()
	defer mic.mu.Unlock()
	if ip == nil {
		return
	}
	mic.markToIPs.insert(pktMark, ip)
	mic.IPToMark[ip.String()] = pktMark.ToInt()
}

func (mic *MarkIPsCache) deleteMarkIP(pktMark util.EgressIPMark, ip net.IP) {
	mic.mu.Lock()
	defer mic.mu.Unlock()
	if ip == nil {
		return
	}
	mic.markToIPs.delete(pktMark, ip)
	delete(mic.IPToMark, ip.String())
}

func (mic *MarkIPsCache) replaceAll(markIPs markIPs) {
	mic.mu.Lock()
	mic.markToIPs = markIPs
	for mark, ipv4 := range markIPs.v4 {
		mic.IPToMark[ipv4] = mark
	}
	for mark, ipv6 := range markIPs.v6 {
		mic.IPToMark[ipv6] = mark
	}
	mic.mu.Unlock()
}

func (mic *MarkIPsCache) GetIPv4() map[int]string {
	mic.mu.Lock()
	defer mic.mu.Unlock()
	dupe := make(map[int]string)
	for key, value := range mic.markToIPs.v4 {
		if value == "" {
			continue
		}
		dupe[key] = value
	}
	return dupe
}

func (mic *MarkIPsCache) GetIPv6() map[int]string {
	mic.mu.Lock()
	defer mic.mu.Unlock()
	dupe := make(map[int]string)
	for key, value := range mic.markToIPs.v6 {
		if value == "" {
			continue
		}
		dupe[key] = value
	}
	return dupe
}

func (mic *MarkIPsCache) HasSyncdOnce() bool {
	mic.mu.Lock()
	defer mic.mu.Unlock()
	return mic.hasSyncOnce
}

func (mic *MarkIPsCache) setSyncdOnce() {
	mic.mu.Lock()
	mic.hasSyncOnce = true
	mic.mu.Unlock()
}

type BridgeEIPAddrManager struct {
	nodeName         string
	bridgeName       string
	nodeAnnotationMu sync.Mutex
	eIPLister        egressiplisters.EgressIPLister
	eIPInformer      cache.SharedIndexInformer
	nodeLister       corev1listers.NodeLister
	podLister        corev1listers.PodLister
	namespaceLister  corev1listers.NamespaceLister
	kube             kube.Interface
	addrManager      *linkmanager.Controller
	cache            *MarkIPsCache
}

// NewBridgeEIPAddrManager manages EgressIP IPs that must be added to ovs bridges to support EgressIP feature for user
// defined networks. It saves the assigned IPs to its respective Node annotation in-order to understand which IPs it assigned
// prior to restarting.
// It provides the assigned IPs info node IP handler. Node IP handler must not consider assigned EgressIP IPs as possible node IPs.
// Openflow manager must generate the SNAT openflow conditional on packet marks and therefore needs access to EIP IPs and associated packet marks.
// bridgeEIPAddrManager must be able to force Openflow manager to resync if EgressIP assignment for the node changes.
func newBridgeEIPAddrManager(nodeName, bridgeName string, linkManager *linkmanager.Controller,
	kube kube.Interface, eIPInformer egressipinformers.EgressIPInformer, nodeInformer corev1informers.NodeInformer,
	podInformer corev1informers.PodInformer, namespaceInformer corev1informers.NamespaceInformer) *BridgeEIPAddrManager {
	return &BridgeEIPAddrManager{
		nodeName:         nodeName,     // k8 node name
		bridgeName:       bridgeName,   // bridge name for which EIP IPs are managed
		nodeAnnotationMu: sync.Mutex{}, // mu for updating Node annotation
		eIPLister:        eIPInformer.Lister(),
		eIPInformer:      eIPInformer.Informer(),
		nodeLister:       nodeInformer.Lister(),
		podLister:        podInformer.Lister(),
		namespaceLister:  namespaceInformer.Lister(),
		kube:             kube,
		addrManager:      linkManager,
		cache:            NewMarkIPsCache(), // cache to store pkt mark -> EIP IP.
	}
}

func (g *BridgeEIPAddrManager) GetCache() *MarkIPsCache {
	return g.cache
}

// NewBridgeEIPAddrManager creates a new bridge EIP address manager
func NewBridgeEIPAddrManager(nodeName, bridgeName string, linkManager *linkmanager.Controller,
	kube kube.Interface, eIPInformer egressipinformers.EgressIPInformer, nodeInformer corev1informers.NodeInformer) *BridgeEIPAddrManager {
	return newBridgeEIPAddrManager(nodeName, bridgeName, linkManager, kube, eIPInformer, nodeInformer, nil, nil)
}

// findLinkOnSameNetworkAsIPUsingLPM finds the correct interface for an EgressIP using longest prefix match
// This is based on the implementation in the secondary EgressIP controller
func (g *BridgeEIPAddrManager) findLinkOnSameNetworkAsIPUsingLPM(ip net.IP, v4, v6 bool) (bool, netlink.Link, error) {
	prefixLinks := map[string]netlink.Link{} // key is network CIDR
	prefixes := make([]netip.Prefix, 0)
	links, err := util.GetNetLinkOps().LinkList()
	if err != nil {
		return false, nil, fmt.Errorf("failed to list links: %v", err)
	}
	for _, link := range links {
		link := link
		linkPrefixes, err := g.getFilteredPrefixes(link, v4, v6)
		if err != nil {
			klog.Errorf("Failed to get address from link %s: %v", link.Attrs().Name, err)
			continue
		}
		prefixes = append(prefixes, linkPrefixes...)
		// create lookup table for later retrieval
		for _, prefixFound := range linkPrefixes {
			_, ipNet, err := net.ParseCIDR(prefixFound.String())
			if err != nil {
				klog.Errorf("Egress IP: skipping prefix %q due to parsing CIDR error: %v", prefixFound.String(), err)
				continue
			}
			prefixLinks[ipNet.String()] = link
		}
	}
	lpmTree := cidrtree.New(prefixes...)
	addr, err := netip.ParseAddr(ip.String())
	if err != nil {
		return false, nil, fmt.Errorf("failed to convert IP %s to netip addr: %v", ip.String(), err)
	}
	network, found := lpmTree.Lookup(addr)
	if !found {
		return false, nil, nil
	}
	link, ok := prefixLinks[network.String()]
	if !ok {
		return false, nil, nil
	}
	return true, link, nil
}

// getFilteredPrefixes returns address Prefixes from interfaces with filtering
func (g *BridgeEIPAddrManager) getFilteredPrefixes(link netlink.Link, v4, v6 bool) ([]netip.Prefix, error) {
	validAddresses := make([]netip.Prefix, 0)
	flags := link.Attrs().Flags.String()
	if !g.isLinkUp(flags) {
		return validAddresses, nil
	}
	linkAddresses, err := util.GetFilteredInterfaceAddrs(link, v4, v6)
	if err != nil {
		return validAddresses, err
	}
	for _, addr := range linkAddresses {
		// Skip single-host addresses (/32 for IPv4, /128 for IPv6)
		ones, bits := addr.Mask.Size()
		if ones == bits {
			continue
		}
		// Convert to netip.Prefix
		prefix, err := netip.ParsePrefix(addr.String())
		if err != nil {
			klog.Errorf("Failed to parse address %s as netip.Prefix: %v", addr.String(), err)
			continue
		}
		validAddresses = append(validAddresses, prefix)
	}
	return validAddresses, nil
}

// isLinkUp checks if a network link is up
func (g *BridgeEIPAddrManager) isLinkUp(flags string) bool {
	return (flags != "" && (flags == "up" || flags == "up|broadcast|multicast"))
}

// hasMatchingPods checks if there are any pods matching the EgressIP's namespace and pod selectors
func (g *BridgeEIPAddrManager) hasMatchingPods(eip *egressipv1.EgressIP) (bool, error) {
	namespaceSelector, err := metav1.LabelSelectorAsSelector(&eip.Spec.NamespaceSelector)
	if err != nil {
		return false, fmt.Errorf("failed to convert namespace selector: %v", err)
	}

	podSelector, err := metav1.LabelSelectorAsSelector(&eip.Spec.PodSelector)
	if err != nil {
		return false, fmt.Errorf("failed to convert pod selector: %v", err)
	}

	// Get all namespaces and filter by label selector
	allNamespaces, err := g.namespaceLister.List(labels.Everything())
	if err != nil {
		return false, fmt.Errorf("failed to list all namespaces: %v", err)
	}

	for _, namespace := range allNamespaces {
		namespaceLabels := labels.Set(namespace.Labels)
		if !namespaceSelector.Matches(namespaceLabels) {
			continue
		}

		// Get all pods in this namespace and filter by pod selector
		allPods, err := g.podLister.Pods(namespace.Name).List(labels.Everything())
		if err != nil {
			return false, fmt.Errorf("failed to list pods in namespace %s: %v", namespace.Name, err)
		}

		for _, pod := range allPods {
			podLabels := labels.Set(pod.Labels)
			if !podSelector.Matches(podLabels) {
				continue
			}

			// Check if pod is actually running and has IPs
			if !util.PodCompleted(pod) && !util.PodWantsHostNetwork(pod) && len(pod.Status.PodIPs) > 0 {
				return true, nil
			}
		}
	}

	return false, nil
}

func (g *BridgeEIPAddrManager) AddEgressIP(eip *egressipv1.EgressIP) (bool, error) {
	var isUpdated bool
	if !util.IsEgressIPMarkSet(eip.Annotations) {
		return isUpdated, nil
	}

	// First check if there are any matching pods for this EgressIP
	hasMatchingPods, err := g.hasMatchingPods(eip)
	if err != nil {
		return isUpdated, fmt.Errorf("failed to check for matching pods: %v", err)
	}
	if !hasMatchingPods {
		klog.V(5).Infof("EgressIP %s has no matching pods yet, skipping bridge IP assignment", eip.Name)
		return isUpdated, nil
	}

	for _, status := range eip.Status.Items {
		if status.Node != g.nodeName {
			continue
		}
		ip, pktMark, err := parseEIPMarkIP(eip.Annotations, status.EgressIP)
		if err != nil {
			return isUpdated, fmt.Errorf("failed to add EgressIP gateway config because unable to extract config from EgressIP obj: %v", err)
		}

		// Use longest prefix matching to determine the correct interface for this EgressIP
		egressIP := net.ParseIP(status.EgressIP)
		if egressIP == nil {
			return isUpdated, fmt.Errorf("failed to parse EgressIP %s", status.EgressIP)
		}

		isEIPv4 := egressIP.To4() != nil
		found, correctLink, err := g.findLinkOnSameNetworkAsIPUsingLPM(egressIP, isEIPv4, !isEIPv4)
		if err != nil {
			return isUpdated, fmt.Errorf("failed to find correct interface using LPM: %v", err)
		}
		if !found {
			klog.Warningf("No suitable interface found for EgressIP %s using LPM", status.EgressIP)
			return isUpdated, nil
		}

		// Only proceed if the bridge we're managing is the correct interface
		if correctLink.Attrs().Name != g.bridgeName {
			klog.V(5).Infof("EgressIP %s should be assigned to interface %s, not bridge %s, skipping",
				status.EgressIP, correctLink.Attrs().Name, g.bridgeName)
			return isUpdated, nil
		}

		klog.Infof("Adding EgressIP %s to bridge %s based on LPM and matching pods", status.EgressIP, g.bridgeName)

		// must always add to cache before adding IP because we want to inform node ip handler that this is not a valid node IP
		g.cache.insertMarkIP(pktMark, ip)
		if err = g.addIPToAnnotation(ip); err != nil {
			return isUpdated, fmt.Errorf("failed to add EgressIP gateway config because unable to add EgressIP IP to Node annotation: %v", err)
		}
		if err = g.addIPBridge(ip); err != nil {
			return isUpdated, fmt.Errorf("failed to add EgressIP gateway config because failed to add address to link: %v", err)
		}
		isUpdated = true
		break // no need to continue as only one EIP IP is assigned to a node
	}
	return isUpdated, nil
}

func (g *BridgeEIPAddrManager) UpdateEgressIP(oldEIP, newEIP *egressipv1.EgressIP) (bool, error) {
	var isUpdated bool
	// at most, one status item for this node will be found.
	for _, oldStatus := range oldEIP.Status.Items {
		if oldStatus.Node != g.nodeName {
			continue
		}
		if !util.IsEgressIPMarkSet(oldEIP.Annotations) {
			// this scenario may occur during upgrade from when ovn-k didn't apply marks to EIP objs
			break
		}
		if util.IsItemInSlice(newEIP.Status.Items, oldStatus) {
			// if one status entry exists in both status items, then nothing needs to be done because no status update.
			// also, because at most only one status item can be assigned to a node, we can return early.
			return isUpdated, nil
		}
		ip, pktMark, err := parseEIPMarkIP(oldEIP.Annotations, oldStatus.EgressIP)
		if err != nil {
			return isUpdated, fmt.Errorf("failed to update EgressIP SNAT for ext bridge cache because unable to extract config from old EgressIP obj: %v", err)
		}
		if err = g.deleteIPBridge(ip); err != nil {
			return isUpdated, fmt.Errorf("failed to update EgressIP gateway config because failed to delete address from link: %v", err)
		}
		g.cache.deleteMarkIP(pktMark, ip)
		if err = g.deleteIPsFromAnnotation(ip); err != nil {
			return isUpdated, fmt.Errorf("failed to update EgressIP gateway config because unable to delete EgressIP IP from Node annotation: %v", err)
		}
		isUpdated = true
		break
	}
	for _, newStatus := range newEIP.Status.Items {
		if newStatus.Node != g.nodeName {
			continue
		}
		if !util.IsEgressIPMarkSet(newEIP.Annotations) {
			// this scenario may occur during upgrade from when ovn-k didn't apply marks to EIP objs
			return isUpdated, nil
		}
		ip, pktMark, err := parseEIPMarkIP(newEIP.Annotations, newStatus.EgressIP)
		if err != nil {
			return isUpdated, fmt.Errorf("failed to update EgressIP gateway config because unable to extract config from EgressIP obj: %v", err)
		}
		// must always add to OF cache before adding IP because we want to inform node ip handler that this is not a valid node IP
		g.cache.insertMarkIP(pktMark, ip)
		if err = g.addIPToAnnotation(ip); err != nil {
			return isUpdated, fmt.Errorf("failed to update EgressIP gateway config because unable to add EgressIP IP to Node annotation: %v", err)
		}
		if err = g.addIPBridge(ip); err != nil {
			return isUpdated, fmt.Errorf("failed to update EgressIP gateway config because failed to add address to link: %v", err)
		}
		isUpdated = true
		break
	}
	return isUpdated, nil
}

func (g *BridgeEIPAddrManager) DeleteEgressIP(eip *egressipv1.EgressIP) (bool, error) {
	var isUpdated bool
	if !util.IsEgressIPMarkSet(eip.Annotations) {
		return isUpdated, nil
	}
	for _, status := range eip.Status.Items {
		if status.Node != g.nodeName {
			continue
		}
		if !util.IsEgressIPMarkSet(eip.Annotations) {
			continue
		}
		ip, pktMark, err := parseEIPMarkIP(eip.Annotations, status.EgressIP)
		if err != nil {
			return isUpdated, fmt.Errorf("failed to delete EgressIP gateway config because unable to extract config from EgressIP obj: %v", err)
		}
		if err = g.deleteIPBridge(ip); err != nil {
			return isUpdated, fmt.Errorf("failed to delete EgressIP gateway config because failed to delete address from link: %v", err)
		}
		g.cache.deleteMarkIP(pktMark, ip)
		if err = g.deleteIPsFromAnnotation(ip); err != nil {
			return isUpdated, fmt.Errorf("failed to delete EgressIP gateway config because failed to delete EgressIP IP from Node annotation: %v", err)
		}
		isUpdated = true
		break // no need to continue as only one EIP IP is assigned per node
	}
	return isUpdated, nil
}

func (g *BridgeEIPAddrManager) SyncEgressIP(objs []interface{}) error {
	// caller must synchronise
	annotIPs, err := g.getAnnotationIPs()
	if err != nil {
		return fmt.Errorf("failed to sync EgressIP gateway config because unable to get Node annotation: %v", err)
	}
	configs := markIPs{v4: map[int]string{}, v6: map[int]string{}}
	for _, obj := range objs {
		eip, ok := obj.(*egressipv1.EgressIP)
		if !ok {
			return fmt.Errorf("expected EgressIP type but received %T", obj)
		}
		// This may happen during upgrade when node controllers upgrade before cluster manager upgrades when cluster manager doesn't contain func
		// to add a pkt mark to EgressIPs.
		if !util.IsEgressIPMarkSet(eip.Annotations) {
			continue
		}
		for _, status := range eip.Status.Items {
			if status.Node != g.nodeName {
				continue
			}
			if ip, pktMark, err := parseEIPMarkIP(eip.Annotations, status.EgressIP); err != nil {
				klog.Errorf("Failed to sync EgressIP %s gateway config because unable to extract config from EIP obj: %v", eip.Name, err)
			} else {
				configs.insert(pktMark, ip)
				if err = g.addIPToAnnotation(ip); err != nil {
					return fmt.Errorf("failed to sync EgressIP gateway config because unable to add EgressIP IP to Node annotation: %v", err)
				}
				if err = g.addIPBridge(ip); err != nil {
					return fmt.Errorf("failed to sync EgressIP gateway config because failed to add address to link: %v", err)
				}
			}
			break
		}
	}
	ipsToDel := make([]net.IP, 0)
	for _, annotIP := range annotIPs {
		if configs.containsIP(annotIP) {
			continue
		}
		if err = g.deleteIPBridge(annotIP); err != nil {
			klog.Errorf("Failed to delete stale EgressIP IP %s from gateway: %v", annotIP, err)
			continue
		}
		ipsToDel = append(ipsToDel, annotIP)
	}
	if len(ipsToDel) > 0 {
		if err = g.deleteIPsFromAnnotation(ipsToDel...); err != nil {
			return fmt.Errorf("failed to delete EgressIP IPs from Node annotation: %v", err)
		}
	}
	g.cache.replaceAll(configs)
	g.cache.setSyncdOnce()
	return nil
}

// addIPToAnnotation adds an address to the collection of existing addresses stored in the nodes annotation. Caller
// may repeat addition of addresses without care for duplicate addresses being added.
func (g *BridgeEIPAddrManager) addIPToAnnotation(candidateIP net.IP) error {
	g.nodeAnnotationMu.Lock()
	defer g.nodeAnnotationMu.Unlock()
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		node, err := g.nodeLister.Get(g.nodeName)
		if err != nil {
			return err
		}
		existingIPsStr, err := util.ParseNodeBridgeEgressIPsAnnotation(node)
		if err != nil {
			if util.IsAnnotationNotSetError(err) {
				existingIPsStr = make([]string, 0)
			} else {
				return fmt.Errorf("failed to parse annotation key %q from node object: %v", util.OVNNodeBridgeEgressIPs, err)
			}
		}
		existingIPsSet := sets.New[string](existingIPsStr...)
		candidateIPStr := candidateIP.String()
		if existingIPsSet.Has(candidateIPStr) {
			return nil
		}
		patch, err := json.Marshal(existingIPsSet.Insert(candidateIPStr).UnsortedList())
		if err != nil {
			return err
		}
		node.Annotations[util.OVNNodeBridgeEgressIPs] = string(patch)
		return g.kube.UpdateNodeStatus(node)
	})
}

// deleteIPsFromAnnotation deletes address from annotation. If multiple users, callers must synchronise.
// deletion of address that doesn't exist will not cause an error.
func (g *BridgeEIPAddrManager) deleteIPsFromAnnotation(candidateIPs ...net.IP) error {
	g.nodeAnnotationMu.Lock()
	defer g.nodeAnnotationMu.Unlock()
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		node, err := g.nodeLister.Get(g.nodeName)
		if err != nil {
			return err
		}
		existingIPsStr, err := util.ParseNodeBridgeEgressIPsAnnotation(node)
		if err != nil {
			if util.IsAnnotationNotSetError(err) {
				existingIPsStr = make([]string, 0)
			} else {
				return fmt.Errorf("failed to parse annotation key %q from node object: %v", util.OVNNodeBridgeEgressIPs, err)
			}
		}
		if len(existingIPsStr) == 0 {
			return nil
		}
		existingIPsSet := sets.New[string](existingIPsStr...)
		candidateIPsStr := getIPsStr(candidateIPs...)
		if !existingIPsSet.HasAny(candidateIPsStr...) {
			return nil
		}
		existingIPsSet.Delete(candidateIPsStr...)
		patch, err := json.Marshal(existingIPsSet.UnsortedList())
		if err != nil {
			return err
		}
		node.Annotations[util.OVNNodeBridgeEgressIPs] = string(patch)
		return g.kube.UpdateNodeStatus(node)
	})
}

func (g *BridgeEIPAddrManager) addIPBridge(ip net.IP) error {
	link, err := util.GetNetLinkOps().LinkByName(g.bridgeName)
	if err != nil {
		return fmt.Errorf("failed to get link obj by name %s: %v", g.bridgeName, err)
	}
	return g.addrManager.AddAddress(getEIPBridgeNetlinkAddress(ip, link.Attrs().Index))
}

func (g *BridgeEIPAddrManager) deleteIPBridge(ip net.IP) error {
	link, err := util.GetNetLinkOps().LinkByName(g.bridgeName)
	if err != nil {
		return fmt.Errorf("failed to get link obj by name %s: %v", g.bridgeName, err)
	}
	return g.addrManager.DelAddress(getEIPBridgeNetlinkAddress(ip, link.Attrs().Index))
}

// getAnnotationIPs retrieves the egress IP annotation from the current node Nodes object. If multiple users, callers must synchronise.
// if annotation isn't present, empty set is returned
func (g *BridgeEIPAddrManager) getAnnotationIPs() ([]net.IP, error) {
	node, err := g.nodeLister.Get(g.nodeName)
	if err != nil {
		return nil, fmt.Errorf("failed to get node %s from lister: %v", g.nodeName, err)
	}
	ipsStr, err := util.ParseNodeBridgeEgressIPsAnnotation(node)
	if err != nil {
		if util.IsAnnotationNotSetError(err) {
			ipsStr = make([]string, 0)
		} else {
			return nil, err
		}
	}
	ips := make([]net.IP, 0, len(ipsStr))
	for _, ipStr := range ipsStr {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return nil, fmt.Errorf("failed to parse IPs from Node annotation %s: %v", util.OVNNodeBridgeEgressIPs, ipsStr)
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func parseEIPMarkIP(annotations map[string]string, eip string) (net.IP, util.EgressIPMark, error) {
	pktMark, err := util.ParseEgressIPMark(annotations)
	if err != nil {
		return nil, pktMark, fmt.Errorf("failed to extract packet mark from EgressIP annotations: %v", err)
	}
	// status update and pkt mark should be configured as one operation by cluster manager
	if !pktMark.IsAvailable() {
		return nil, pktMark, fmt.Errorf("packet mark is not set")
	}
	if !pktMark.IsValid() {
		return nil, pktMark, fmt.Errorf("packet mark is not valid")
	}
	ip := net.ParseIP(eip)
	if ip == nil {
		return nil, pktMark, fmt.Errorf("invalid IP")
	}
	return ip, pktMark, nil
}

func getIPsStr(ips ...net.IP) []string {
	ipsStr := make([]string, 0, len(ips))
	for _, ip := range ips {
		ipsStr = append(ipsStr, ip.String())
	}
	return ipsStr
}

func getEIPBridgeNetlinkAddress(ip net.IP, ifindex int) netlink.Addr {
	return netlink.Addr{
		IPNet:     &net.IPNet{IP: ip, Mask: util.GetIPFullMask(ip)},
		Flags:     getEIPNetlinkAddressFlag(ip),
		Scope:     int(netlink.SCOPE_UNIVERSE),
		ValidLft:  getEIPNetlinkAddressValidLft(ip),
		LinkIndex: ifindex,
	}
}

func getEIPNetlinkAddressFlag(ip net.IP) int {
	// isV6?
	if ip.To4() == nil && ip.To16() != nil {
		return unix.IFA_F_NODAD
	}
	return 0
}

func getEIPNetlinkAddressValidLft(ip net.IP) int {
	// isV6?
	if ip.To4() == nil && ip.To16() != nil {
		return math.MaxUint32
	}
	return 0
}
