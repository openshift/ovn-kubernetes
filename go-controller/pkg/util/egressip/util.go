package egressip

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/gaissmai/cidrtree"
	ocpconfigapi "github.com/openshift/api/config/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	informerscorev1 "k8s.io/client-go/informers/core/v1"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	egressipinformerv1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/informers/externalversions/egressip/v1"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/networkmanager"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

func PlatformTypeIsEgressIPCloudProvider() bool {
	return config.Kubernetes.PlatformType == string(ocpconfigapi.AWSPlatformType) ||
		config.Kubernetes.PlatformType == string(ocpconfigapi.GCPPlatformType) ||
		config.Kubernetes.PlatformType == string(ocpconfigapi.AzurePlatformType) ||
		config.Kubernetes.PlatformType == string(ocpconfigapi.OpenStackPlatformType)
}

// GetNodeEIPConfig attempts to generate EIP configuration from a nodes annotations.
// If the platform is running in the cloud, retrieve config info from node obj annotation added by Cloud Network Config
// Controller (CNCC). If not on a cloud platform (i.e. baremetal), retrieve from the node obj primary interface annotation.
func GetNodeEIPConfig(node *corev1.Node) (*util.ParsedNodeEgressIPConfiguration, error) {
	var parsedEgressIPConfig *util.ParsedNodeEgressIPConfiguration
	var err error
	if PlatformTypeIsEgressIPCloudProvider() {
		parsedEgressIPConfig, err = util.ParseCloudEgressIPConfig(node)
	} else {
		parsedEgressIPConfig, err = util.ParseNodePrimaryIfAddr(node)
	}
	if err != nil {
		return nil, fmt.Errorf("unable to generate egress IP config for node %s: %w", node.Name, err)
	}
	return parsedEgressIPConfig, nil
}

type watchFactory interface {
	//GetEgressIP(name string) (*egressipv1.EgressIP, error)
	NamespaceInformer() informerscorev1.NamespaceInformer
	EgressIPInformer() egressipinformerv1.EgressIPInformer
}

func IsEgressIPLocalOrAdvertised(
	wf watchFactory,
	nm networkmanager.Interface,
	eipCponfig *util.ParsedNodeEgressIPConfiguration,
	node *corev1.Node,
	eip string,
	ip net.IP,
) (bool, error) {
	local, managed, _, err := getEgressIPLocalManaged(wf, nm, eipCponfig, node, eip, ip)
	if err != nil {
		return false, err
	}
	return local || managed, nil
}

func IsEgressIPOVNManaged(
	wf watchFactory,
	nm networkmanager.Interface,
	eipCponfig *util.ParsedNodeEgressIPConfiguration,
	node *corev1.Node,
	eip string,
	ip net.IP,
) (bool, error) {
	_, managed, _, err := getEgressIPLocalManaged(wf, nm, eipCponfig, node, eip, ip)
	if err != nil {
		return false, err
	}
	return managed, nil
}

func GetSecondaryHostNetworkContainingIP(
	wf watchFactory,
	nm networkmanager.Interface,
	eipCponfig *util.ParsedNodeEgressIPConfiguration,
	node *corev1.Node,
	eip string,
	ip net.IP,
) (bool, string, error) {
	_, managed, secondary, err := getEgressIPLocalManaged(wf, nm, eipCponfig, node, eip, ip)
	if err != nil {
		return false, "", err
	}
	return managed, secondary, nil
}

func getEgressIPLocalManaged(
	wf watchFactory,
	nm networkmanager.Interface,
	eipCponfig *util.ParsedNodeEgressIPConfiguration,
	node *corev1.Node,
	eip string,
	ip net.IP,
) (local, managed bool, secondary string, err error) {
	isOVNNetwork := isOVNNetwork(eipCponfig, ip)
	if isOVNNetwork {
		local = true
		managed = true
		return
	}
	secondary, err = getSecondaryHostNetworkContainingIP(node, ip)
	if err != nil {
		return
	}
	if secondary != "" {
		local = true
		managed = false
		return
	}
	if !config.OVNKubernetesFeature.EnableRouteAdvertisements {
		return
	}
	var isAdvertised bool
	isAdvertised, err = isAdvertisedOnNode(wf, nm, eip, node.Name)
	if err != nil {
		return
	}
	if isAdvertised {
		local = false
		managed = true
	}
	return
}

// isOVNNetwork attempts to detect if the argument IP can be hosted by a network managed by OVN. Currently, this is
// only the primary OVN network
func isOVNNetwork(eIPConfig *util.ParsedNodeEgressIPConfiguration, ip net.IP) bool {
	if eIPConfig.V4.Net != nil && eIPConfig.V4.Net.Contains(ip) {
		return true
	}
	if eIPConfig.V6.Net != nil && eIPConfig.V6.Net.Contains(ip) {
		return true
	}
	return false
}

// GetEgressIPNetwork attempts to retrieve a network that contains EgressIP. Check the OVN network first as
// represented by parameter eIPConfig, and if no match is found, and if not in a cloud environment, check secondary host networks.
func GetEgressIPNetwork(node *corev1.Node, eIPConfig *util.ParsedNodeEgressIPConfiguration, eIP net.IP) (string, error) {
	if eIPConfig.V4.Net != nil && eIPConfig.V4.Net.Contains(eIP) {
		return eIPConfig.V4.Net.String(), nil
	}
	if eIPConfig.V6.Net != nil && eIPConfig.V6.Net.Contains(eIP) {
		return eIPConfig.V6.Net.String(), nil
	}
	// Do not attempt to check if a secondary host network may host an EIP if we are in a cloud environment
	if util.PlatformTypeIsEgressIPCloudProvider() {
		return "", nil
	}
	network, err := getSecondaryHostNetworkContainingIP(node, eIP)
	if err != nil {
		return "", fmt.Errorf("failed to get Egress IP %s network for node %s: %v", eIP.String(), node.Name, err)
	}
	return network, nil
}

func ReconcileEgressIPNetworkChangeAnyNode(old, new util.NetInfo) bool {
	return reconcileEgressIPNetworkChange(nil, old, new)
}

func ReconcileEgressIPNetworkChangeOnNodes(nodes []string, old, new util.NetInfo) bool {
	return reconcileEgressIPNetworkChange(nodes, old, new)
}


func reconcileEgressIPNetworkChange(nodes []string, old, new util.NetInfo) bool {
	getNamespacesAndEgressIPNodes := func(net util.NetInfo) (sets.Set[string], sets.Set[string]) {
		ns, nodes := sets.New[string](), sets.New[string]()
		if net != nil && (net.IsPrimaryNetwork() || net.IsDefault()) {
			ns.Insert(net.GetNamespaces()...)
			nodes.Insert(net.GetEgressIPAdvertisedNodes()...)
		}
		return ns, nodes
	}

	oldNs, oldNodes := getNamespacesAndEgressIPNodes(old)
	newNs, newNodes := getNamespacesAndEgressIPNodes(new)
	hadNsChanges := !oldNs.Equal(newNs)
	var hadNodeChanges bool
	switch {
	case len(nodes) == 0:
		hadNodeChanges = !oldNodes.Equal(newNodes)
	case len(nodes) > 0:
		hadNodeChanges = oldNodes.HasAny(nodes...) != newNodes.HasAny(nodes...)

	}

	if !hadNsChanges && !hadNodeChanges {
		return false
	}
	return true
}

// GetSecondaryHostNetworkContainingIP attempts to find a secondary host network to host the argument IP
// and includes only global unicast addresses.
func getSecondaryHostNetworkContainingIP(node *corev1.Node, ip net.IP) (string, error) {
	networks, err := util.ParseNodeHostCIDRsExcludeOVNNetworks(node)
	if err != nil {
		return "", fmt.Errorf("failed to get host-cidrs annotation excluding OVN networks for node %s: %v",
			node.Name, err)
	}
	cidrs, err := makeCIDRs(networks...)
	if err != nil {
		return "", err
	}
	if len(cidrs) == 0 {
		return "", nil
	}
	isIPv6 := ip.To4() == nil
	cidrs = filterIPVersion(cidrs, isIPv6)
	lpmTree := cidrtree.New(cidrs...)
	for _, prefix := range cidrs {
		if !prefix.Addr().IsGlobalUnicast() {
			lpmTree.Delete(prefix)
		}
	}
	addr, err := netip.ParseAddr(ip.String())
	if err != nil {
		return "", fmt.Errorf("failed to convert IP %s to netip address: %v", ip.String(), err)
	}
	match, found := lpmTree.Lookup(addr)
	if !found {
		return "", nil
	}
	return match.String(), nil
}

func isAdvertisedOnNode(wf watchFactory, nm networkmanager.Interface, eip, node string) (bool, error) {
	if !config.OVNKubernetesFeature.EnableRouteAdvertisements {
		return false, nil
	}
	egressip, err := wf.EgressIPInformer().Lister().Get(eip)
	if err != nil {
		return false, fmt.Errorf("failed to get Egress IP %s: %v", eip, err)
	}
	selector, err := metav1.LabelSelectorAsSelector(&egressip.Spec.NamespaceSelector)
	if err != nil {
		return false, fmt.Errorf("failed to parse Egress IP %s namespace selector: %v", metav1.NamespaceAll, err)
	}
	selectedNs, err := wf.NamespaceInformer().Lister().List(selector)
	if err != nil {
		return false, fmt.Errorf("failed to list selected namespaces of Egress IP %s: %v", eip, err)
	}
	for _, ns := range selectedNs {
		network := nm.GetActiveNetworkForNamespaceFast(ns.Name)
		advertisements := network.GetEgressIPAdvertisedVRFs()
		advertised := len(advertisements[node]) > 0
		if advertised {
			return true, nil
		}
	}
	return false, nil
}

func makeCIDRs(s ...string) (cidrs []netip.Prefix, err error) {
	for _, cidrString := range s {
		prefix, err := netip.ParsePrefix(cidrString)
		if err != nil {
			return nil, err
		}
		cidrs = append(cidrs, prefix)
	}
	return cidrs, nil
}

func filterIPVersion(cidrs []netip.Prefix, v6 bool) []netip.Prefix {
	validCIDRs := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		if cidr.Addr().Is4() && v6 {
			continue
		}
		if cidr.Addr().Is6() && !v6 {
			continue
		}
		validCIDRs = append(validCIDRs, cidr)
	}
	return validCIDRs
}
