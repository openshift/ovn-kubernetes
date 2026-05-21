package ovn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"
	"github.com/ovn-kubernetes/libovsdb/ovsdb"

	libovsdbops "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	libovsdbutil "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/libovsdb/util"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/nbdb"
	addressset "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/ovn/address_set"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util/batching"
	utilerrors "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util/errors"
)

const (
	// UDN ACL names, should be unique across all controllers
	// Default network-only ACLs:
	allowHostARPACL        = "AllowHostARPPrimaryUDN"
	allowHostPrimaryUDNACL = "AllowHostPrimaryUDN"
	denyPrimaryUDNACL      = "DenyPrimaryUDN"
	// OpenPortACLPrefix is used to build per-pod ACLs, pod name should be added to the prefix to build a unique name
	OpenPortACLPrefix = "OpenPort-"
	// the same tier is used for all UDN isolation ACLs
	isolationTier = types.PrimaryACLTier

	// Port Group ID for pods with primary UDN
	// Note, this is left with wording "Secondary" because we do not currently allow
	// mutating a port group's name. ACL match criteria may reference this name, so it
	// is unsafe to update. Therefore we keep the legacy name for now.
	legacySecondaryPodPGName = "SecondaryPods"

	// deprecated Legacy versions
	allowHostSecondaryACL = "AllowHostSecondary"
	denySecondaryACL      = "DenySecondary"
	legacyAllowHostARPACL = "AllowHostARPSecondary"
)

// setupUDNACLs should be called after the node's management port was configured
// Only used on default network switches.
func (oc *DefaultNetworkController) setupUDNACLs(mgmtPortIPs []net.IP) error {
	if !util.IsNetworkSegmentationSupportEnabled() {
		return nil
	}
	// add port group to track UDN primary pods
	pgIDs := oc.getSecondaryPodsPortGroupDbIDs()
	pg := &nbdb.PortGroup{
		Name: libovsdbutil.GetPortGroupName(pgIDs),
	}
	_, err := libovsdbops.GetPortGroup(oc.nbClient, pg)
	if err != nil {
		if !errors.Is(err, libovsdbclient.ErrNotFound) {
			return err
		}
		// we didn't find an existing secondaryPodsPG, let's create a new empty PG
		pg = libovsdbutil.BuildPortGroup(pgIDs, nil, nil)
		err = libovsdbops.CreateOrUpdatePortGroups(oc.nbClient, pg)
		if err != nil {
			klog.Errorf("Failed to create secondary pods port group: %v", err)
			return err
		}
	}
	// Now add ACLs to limit non-primary pods traffic to only allow kubelet probes
	// - egress+ingress -> allow ARP to/from mgmtPort
	// - ingress -> allow-related all from mgmtPort
	// - egress+ingress -> deny everything else
	pgName := libovsdbutil.GetPortGroupName(pgIDs)
	egressDenyIDs := oc.getUDNACLDbIDs(denyPrimaryUDNACL, libovsdbutil.ACLEgress)
	match := libovsdbutil.GetACLMatch(pgName, "", libovsdbutil.ACLEgress)
	egressDenyACL := libovsdbutil.BuildACL(egressDenyIDs, types.PrimaryUDNDenyPriority, match, nbdb.ACLActionDrop,
		nil, libovsdbutil.LportEgress, isolationTier)

	getARPMatch := func(direction libovsdbutil.ACLDirection) string {
		match := "("
		for i, mgmtPortIP := range mgmtPortIPs {
			var protoMatch string
			if utilnet.IsIPv6(mgmtPortIP) {
				protoMatch = "( nd && nd.target == " + mgmtPortIP.String() + " )"
			} else {
				dir := "t"
				if direction == libovsdbutil.ACLIngress {
					dir = "s"
				}
				protoMatch = fmt.Sprintf("( arp && arp.%spa == %s )", dir, mgmtPortIP.String())
			}
			if i > 0 {
				match += " || "
			}
			match += protoMatch
		}
		match += ")"
		return match
	}

	egressARPIDs := oc.getUDNACLDbIDs(allowHostARPACL, libovsdbutil.ACLEgress)
	match = libovsdbutil.GetACLMatch(pgName, getARPMatch(libovsdbutil.ACLEgress), libovsdbutil.ACLEgress)
	egressARPACL := libovsdbutil.BuildACL(egressARPIDs, types.PrimaryUDNAllowPriority, match, nbdb.ACLActionAllow,
		nil, libovsdbutil.LportEgress, isolationTier)

	ingressDenyIDs := oc.getUDNACLDbIDs(denyPrimaryUDNACL, libovsdbutil.ACLIngress)
	match = libovsdbutil.GetACLMatch(pgName, "", libovsdbutil.ACLIngress)
	ingressDenyACL := libovsdbutil.BuildACL(ingressDenyIDs, types.PrimaryUDNDenyPriority, match, nbdb.ACLActionDrop,
		nil, libovsdbutil.LportIngress, isolationTier)

	ingressARPIDs := oc.getUDNACLDbIDs(allowHostARPACL, libovsdbutil.ACLIngress)
	match = libovsdbutil.GetACLMatch(pgName, getARPMatch(libovsdbutil.ACLIngress), libovsdbutil.ACLIngress)
	ingressARPACL := libovsdbutil.BuildACL(ingressARPIDs, types.PrimaryUDNAllowPriority, match, nbdb.ACLActionAllow,
		nil, libovsdbutil.LportIngress, isolationTier)

	ingressAllowIDs := oc.getUDNACLDbIDs(allowHostPrimaryUDNACL, libovsdbutil.ACLIngress)
	match = "("
	for i, mgmtPortIP := range mgmtPortIPs {
		ipFamily := "ip4"
		if utilnet.IsIPv6(mgmtPortIP) {
			ipFamily = "ip6"
		}
		ipMatch := fmt.Sprintf("%s.src==%s", ipFamily, mgmtPortIP.String())
		if i > 0 {
			match += " || "
		}
		match += ipMatch
	}
	match += ")"
	match = libovsdbutil.GetACLMatch(pgName, match, libovsdbutil.ACLIngress)
	ingressAllowACL := libovsdbutil.BuildACL(ingressAllowIDs, types.PrimaryUDNAllowPriority, match, nbdb.ACLActionAllowRelated,
		nil, libovsdbutil.LportIngress, isolationTier)

	klog.Infof("[UDN-DEBUG] setupUDNACLs: creating/updating isolation ACLs for portGroup=%s with mgmtPortIPs=%v", pgName, mgmtPortIPs)
	klog.Infof("[UDN-DEBUG] setupUDNACLs: egressDenyACL match=%q action=%s", egressDenyACL.Match, egressDenyACL.Action)
	klog.Infof("[UDN-DEBUG] setupUDNACLs: egressARPACL match=%q action=%s", egressARPACL.Match, egressARPACL.Action)
	klog.Infof("[UDN-DEBUG] setupUDNACLs: ingressDenyACL match=%q action=%s", ingressDenyACL.Match, ingressDenyACL.Action)
	klog.Infof("[UDN-DEBUG] setupUDNACLs: ingressARPACL match=%q action=%s", ingressARPACL.Match, ingressARPACL.Action)
	klog.Infof("[UDN-DEBUG] setupUDNACLs: ingressAllowACL match=%q action=%s", ingressAllowACL.Match, ingressAllowACL.Action)

	ops, err := libovsdbops.CreateOrUpdateACLsOps(oc.nbClient, nil, oc.GetSamplingConfig(), egressDenyACL, egressARPACL, ingressARPACL, ingressDenyACL, ingressAllowACL)
	if err != nil {
		return fmt.Errorf("failed to create or update UDN ACLs: %v", err)
	}

	ops, err = libovsdbops.AddACLsToPortGroupOps(oc.nbClient, ops, pgName, egressDenyACL, egressARPACL, ingressARPACL, ingressDenyACL, ingressAllowACL)
	if err != nil {
		return fmt.Errorf("failed to add UDN ACLs to portGroup %s: %v", pgName, err)
	}

	klog.Infof("[UDN-DEBUG] setupUDNACLs: transacting %d ops to apply isolation ACLs to portGroup=%s", len(ops), pgName)
	_, err = libovsdbops.TransactAndCheck(oc.nbClient, ops)
	if err != nil {
		klog.Errorf("[UDN-DEBUG] setupUDNACLs: TransactAndCheck FAILED: %v", err)
	} else {
		klog.Infof("[UDN-DEBUG] setupUDNACLs: TransactAndCheck succeeded for portGroup=%s", pgName)
	}
	return err
}

func (oc *DefaultNetworkController) getSecondaryPodsPortGroupDbIDs() *libovsdbops.DbObjectIDs {
	return libovsdbops.NewDbObjectIDs(libovsdbops.PortGroupUDN, oc.controllerName,
		map[libovsdbops.ExternalIDKey]string{
			libovsdbops.ObjectNameKey: legacySecondaryPodPGName,
		})
}

func (oc *DefaultNetworkController) getUDNACLDbIDs(name string, aclDir libovsdbutil.ACLDirection) *libovsdbops.DbObjectIDs {
	return libovsdbops.NewDbObjectIDs(libovsdbops.ACLUDN, oc.controllerName,
		map[libovsdbops.ExternalIDKey]string{
			libovsdbops.ObjectNameKey:      name,
			libovsdbops.PolicyDirectionKey: string(aclDir),
		})
}

func getPortsMatches(podAnnotations map[string]string, lspName string) (string, string, error) {
	if lspName == "" {
		return "", "", nil
	}
	ports, err := util.UnmarshalUDNOpenPortsAnnotation(podAnnotations)
	if err != nil {
		return "", "", err
	}
	if len(ports) == 0 {
		return "", "", nil
	}
	// protocol match is only used for ingress rules, use dst match
	portMatches := []string{}
	for _, portDef := range ports {
		if portDef.Protocol == "icmp" {
			// from the ovn docs:
			// "icmp expands to icmp4 || icmp6"
			portMatches = append(portMatches, "icmp")
		} else {
			portMatches = append(portMatches, fmt.Sprintf("%s.dst == %d", portDef.Protocol, *portDef.Port))
		}
	}
	protoMatch := strings.Join(portMatches, " || ")
	// allow ingress for ARP or ND and open ports
	// allow egress for ARP or ND
	ingressMatch := fmt.Sprintf(`outport == "%s" && (arp || nd || (%s))`, lspName, protoMatch)
	egressMatch := fmt.Sprintf(`inport == "%s" && (arp || nd)`, lspName)

	return ingressMatch, egressMatch, nil
}

// setUDNPodOpenPorts should be called after the pod's lsp is created to add ACLs that allow ingress on required ports.
// When lspName="", ACLs are removed. If annotation can't be parsed correctly, ACLs will be deleted.
func (oc *DefaultNetworkController) setUDNPodOpenPorts(podNamespacedName string, podAnnotations map[string]string, lspName string) error {
	ops, parseErr, err := oc.setUDNPodOpenPortsOps(podNamespacedName, podAnnotations, lspName, nil)
	if err != nil {
		return errors.Join(parseErr, err)
	}
	_, err = libovsdbops.TransactAndCheck(oc.nbClient, ops)
	if err != nil {
		return utilerrors.Join(parseErr, fmt.Errorf("failed to transact open ports UDN ACLs: %v", err))
	}
	return parseErr
}

// setUDNPodOpenPortsOps returns the operations to add or remove ACLs that allow ingress on required ports.
// first returned error is parse error, second is db ops error
func (oc *DefaultNetworkController) setUDNPodOpenPortsOps(podNamespacedName string, podAnnotations map[string]string, lspName string,
	ops []ovsdb.Operation) ([]ovsdb.Operation, error, error) {
	udnPGName := libovsdbutil.GetPortGroupName(oc.getSecondaryPodsPortGroupDbIDs())

	ingressMatch, egressMatch, parseErr := getPortsMatches(podAnnotations, lspName)
	klog.Infof("[UDN-DEBUG] setUDNPodOpenPortsOps: pod=%s lspName=%q ingressMatch=%q egressMatch=%q parseErr=%v", podNamespacedName, lspName, ingressMatch, egressMatch, parseErr)
	// don't return on parseErr, as we need to cleanup potentially present ACLs from the previous config
	ingressIDs := oc.getUDNOpenPortDbIDs(podNamespacedName, libovsdbutil.ACLIngress)
	ingressACL := libovsdbutil.BuildACL(ingressIDs, types.PrimaryUDNAllowPriority,
		ingressMatch, nbdb.ACLActionAllowRelated, nil, libovsdbutil.LportIngress, isolationTier)

	egressIDs := oc.getUDNOpenPortDbIDs(podNamespacedName, libovsdbutil.ACLEgress)
	egressACL := libovsdbutil.BuildACL(egressIDs, types.PrimaryUDNAllowPriority,
		egressMatch, nbdb.ACLActionAllow, nil, libovsdbutil.LportEgress, isolationTier)

	var err error
	if ingressMatch == "" && egressMatch == "" || parseErr != nil {
		// no open ports or error parsing annotations, remove ACLs
		foundACLs, err := libovsdbops.FindACLs(oc.nbClient, []*nbdb.ACL{ingressACL, egressACL})
		if err != nil {
			return ops, parseErr, fmt.Errorf("failed to find open ports UDN ACLs: %v", err)
		}
		ops, err = libovsdbops.DeleteACLsFromPortGroupOps(oc.nbClient, ops, udnPGName, foundACLs...)
		if err != nil {
			return ops, parseErr, fmt.Errorf("failed to remove open ports ACLs from portGroup %s: %v", udnPGName, err)
		}
	} else {
		// update ACLs
		ops, err = libovsdbops.CreateOrUpdateACLsOps(oc.nbClient, ops, oc.GetSamplingConfig(), ingressACL, egressACL)
		if err != nil {
			return ops, parseErr, fmt.Errorf("failed to create or update open ports UDN ACLs: %v", err)
		}

		ops, err = libovsdbops.AddACLsToPortGroupOps(oc.nbClient, ops, udnPGName, ingressACL, egressACL)
		if err != nil {
			return ops, parseErr, fmt.Errorf("failed to add open ports ACLs to portGroup %s: %v", udnPGName, err)
		}
	}
	return ops, parseErr, nil
}

func (oc *DefaultNetworkController) getUDNOpenPortDbIDs(podNamespacedName string, aclDir libovsdbutil.ACLDirection) *libovsdbops.DbObjectIDs {
	return libovsdbops.NewDbObjectIDs(libovsdbops.ACLUDN, oc.controllerName,
		map[libovsdbops.ExternalIDKey]string{
			libovsdbops.ObjectNameKey:      OpenPortACLPrefix + podNamespacedName,
			libovsdbops.PolicyDirectionKey: string(aclDir),
		})
}

// advertisedNetworkSubnetsKey is the object name key for the global advertised networks addressset and the global deny ACL
const advertisedNetworkSubnetsKey = "advertised-network-subnets"

// GetAdvertisedNetworkSubnetsAddressSetDBIDs returns the DB IDs for the advertised network subnets addressset
func GetAdvertisedNetworkSubnetsAddressSetDBIDs() *libovsdbops.DbObjectIDs {
	return libovsdbops.NewDbObjectIDs(libovsdbops.AddressSetAdvertisedNetwork, types.DefaultNetworkControllerName, map[libovsdbops.ExternalIDKey]string{
		libovsdbops.ObjectNameKey: advertisedNetworkSubnetsKey,
	})
}

// GetAdvertisedNetworkSubnetsDropACLdbIDs returns the DB IDs for the advertised network subnets drop ACL
func GetAdvertisedNetworkSubnetsDropACLdbIDs() *libovsdbops.DbObjectIDs {
	return libovsdbops.NewDbObjectIDs(libovsdbops.ACLAdvertisedNetwork, types.DefaultNetworkControllerName,
		map[libovsdbops.ExternalIDKey]string{
			libovsdbops.ObjectNameKey: advertisedNetworkSubnetsKey,
			libovsdbops.NetworkKey:    "",
		})
}

// GetAdvertisedNetworkSubnetsPassACLdbIDs returns the DB IDs for the advertised network subnets pass ACL
func GetAdvertisedNetworkSubnetsPassACLdbIDs(controller, networkName string, networkID int) *libovsdbops.DbObjectIDs {
	return libovsdbops.NewDbObjectIDs(libovsdbops.ACLAdvertisedNetwork, controller,
		map[libovsdbops.ExternalIDKey]string{
			libovsdbops.ObjectNameKey: networkName,
			libovsdbops.NetworkKey:    strconv.Itoa(networkID),
		})
}

// BuildAdvertisedNetworkSubnetsDropACL builds the advertised network subnets drop ACL:
// action match                                                                       priority
// ------ --------------------------------------------------------------------------- --------
// drop   "(ip[4|6].src == $<ALL_ADV_SUBNETS> && ip[4|6].dst == $<ALL_ADV_SUBNETS>)"    1050
func BuildAdvertisedNetworkSubnetsDropACL(advertisedNetworkSubnetsAddressSet addressset.AddressSet) *nbdb.ACL {
	var dropMatches []string
	v4AddrSet, v6AddrSet := advertisedNetworkSubnetsAddressSet.GetASHashNames()
	if v4AddrSet != "" {
		dropMatches = append(dropMatches, fmt.Sprintf("(ip4.src == $%s && ip4.dst == $%s)", v4AddrSet, v4AddrSet))
	}
	if v6AddrSet != "" {
		dropMatches = append(dropMatches, fmt.Sprintf("(ip6.src == $%s && ip6.dst == $%s)", v6AddrSet, v6AddrSet))
	}

	dropACL := libovsdbutil.BuildACL(
		GetAdvertisedNetworkSubnetsDropACLdbIDs(),
		types.AdvertisedNetworkDenyPriority,
		strings.Join(dropMatches, " || "),
		nbdb.ACLActionDrop,
		nil,
		libovsdbutil.LportEgressAfterLB,
		isolationTier)
	return dropACL
}

// addAdvertisedNetworkIsolation adds advertised network isolation rules to the given node.
// It adds the following ACLs to the node switch:
// action match                                                                       priority
// ------ --------------------------------------------------------------------------- --------
// pass   "(ip[4|6].src == <UDN_SUBNET> && ip[4|6].dst == <UDN_SUBNET>)"                1100
// drop   "(ip[4|6].src == $<ALL_ADV_SUBNETS> && ip[4|6].dst == $<ALL_ADV_SUBNETS>)"    1050
func (bnc *BaseNetworkController) addAdvertisedNetworkIsolation(nodeName string) error {
	klog.Infof("[UDN-DEBUG] addAdvertisedNetworkIsolation: entry for node=%s network=%s topology=%s", nodeName, bnc.GetNetworkName(), bnc.TopologyType())
	var passMatches, cidrs []string
	var ops []ovsdb.Operation

	addrSet, err := bnc.addressSetFactory.GetAddressSet(GetAdvertisedNetworkSubnetsAddressSetDBIDs())
	if err != nil {
		return fmt.Errorf("failed to get advertised subnets addresset %s for network %s: %w", GetAdvertisedNetworkSubnetsAddressSetDBIDs(), bnc.GetNetworkName(), err)
	}
	var ipv4Subnets, ipv6Subnets []*net.IPNet
	for _, subnet := range bnc.Subnets() {
		if utilnet.IsIPv6CIDR(subnet.CIDR) {
			ipv6Subnets = append(ipv6Subnets, subnet.CIDR)
		} else {
			ipv4Subnets = append(ipv4Subnets, subnet.CIDR)
		}
		cidrs = append(cidrs, subnet.CIDR.String())
	}
	if len(ipv4Subnets) > 0 {
		var srcMatches, dstMatches []string
		for _, subnet := range ipv4Subnets {
			srcMatches = append(srcMatches, fmt.Sprintf("ip4.src == %s", subnet))
			dstMatches = append(dstMatches, fmt.Sprintf("ip4.dst == %s", subnet))
		}
		// build match ((ip4.src == subnet1 || ip4.src == subnet2 ...) && (ip4.dst == subnet1 || ip4.dst == subnet2 ...))
		passMatches = append(passMatches, fmt.Sprintf("((%s) && (%s))", strings.Join(srcMatches, " || "), strings.Join(dstMatches, " || ")))
	}
	if len(ipv6Subnets) > 0 {
		var srcMatches, dstMatches []string
		for _, subnet := range ipv6Subnets {
			srcMatches = append(srcMatches, fmt.Sprintf("ip6.src == %s", subnet))
			dstMatches = append(dstMatches, fmt.Sprintf("ip6.dst == %s", subnet))
		}
		// build match ((ip6.src == subnet1 || ip6.src == subnet2 ...) && (ip6.dst == subnet1 || ip6.dst == subnet2 ...))
		passMatches = append(passMatches, fmt.Sprintf("((%s) && (%s))", strings.Join(srcMatches, " || "), strings.Join(dstMatches, " || ")))
	}
	addrOps, err := addrSet.AddAddressesReturnOps(cidrs)
	if err != nil {
		return fmt.Errorf("failed to add addresses %q to the %s address set for network %s: %w", cidrs, GetAdvertisedNetworkSubnetsAddressSetDBIDs(), bnc.GetNetworkName(), err)
	}
	ops = append(ops, addrOps...)

	if len(passMatches) > 0 {
		passACL := libovsdbutil.BuildACL(
			GetAdvertisedNetworkSubnetsPassACLdbIDs(bnc.controllerName, bnc.GetNetworkName(), bnc.GetNetworkID()),
			types.AdvertisedNetworkPassPriority,
			strings.Join(passMatches, " || "),
			nbdb.ACLActionPass,
			nil,
			libovsdbutil.LportEgressAfterLB,
			isolationTier)

		ops, err = libovsdbops.CreateOrUpdateACLsOps(bnc.nbClient, ops, nil, passACL)
		if err != nil {
			return fmt.Errorf("failed to create or update network isolation pass ACL %s for network %s: %w", GetAdvertisedNetworkSubnetsPassACLdbIDs(bnc.controllerName, bnc.GetNetworkName(), bnc.GetNetworkID()), bnc.GetNetworkName(), err)
		}
		ops, err = libovsdbops.AddACLsToLogicalSwitchOps(bnc.nbClient, ops, bnc.GetNetworkScopedSwitchName(nodeName), passACL)
		if err != nil {
			return fmt.Errorf("failed to add network isolation pass ACL to switch %s for network %s: %w", bnc.GetNetworkScopedSwitchName(nodeName), bnc.GetNetworkName(), err)
		}
	}

	dropACL := BuildAdvertisedNetworkSubnetsDropACL(addrSet)
	ops, err = libovsdbops.CreateOrUpdateACLsOps(bnc.nbClient, ops, nil, dropACL)
	if err != nil {
		return fmt.Errorf("failed to create or update network isolation drop ACL %v", err)
	}
	ops, err = libovsdbops.AddACLsToLogicalSwitchOps(bnc.nbClient, ops, bnc.GetNetworkScopedSwitchName(nodeName), dropACL)
	if err != nil {
		return fmt.Errorf("failed to add network isolation drop ACL to switch %s for network %s: %w", bnc.GetNetworkScopedSwitchName(nodeName), bnc.GetNetworkName(), err)
	}

	klog.Infof("[UDN-DEBUG] addAdvertisedNetworkIsolation: transacting %d ops for node=%s network=%s switchName=%s cidrs=%v passMatches=%v",
		len(ops), nodeName, bnc.GetNetworkName(), bnc.GetNetworkScopedSwitchName(nodeName), cidrs, passMatches)
	if _, err = libovsdbops.TransactAndCheck(bnc.nbClient, ops); err != nil {
		klog.Errorf("[UDN-DEBUG] addAdvertisedNetworkIsolation: TransactAndCheck FAILED for node=%s network=%s: %v", nodeName, bnc.GetNetworkName(), err)
		return fmt.Errorf("failed to configure network isolation OVN rules for network %s: %w", bnc.GetNetworkName(), err)
	}
	klog.Infof("[UDN-DEBUG] addAdvertisedNetworkIsolation: TransactAndCheck succeeded for node=%s network=%s", nodeName, bnc.GetNetworkName())
	return nil
}

// deleteAdvertisedNetworkIsolation deletes advertised network isolation rules from the given node switch.
// It removes the network CIDRs from the global advertised networks addresset together with the ACLs on the node switch.
func (bnc *BaseNetworkController) deleteAdvertisedNetworkIsolation(nodeName string) error {
	klog.Infof("[UDN-DEBUG] deleteAdvertisedNetworkIsolation: entry for node=%s network=%s topology=%s", nodeName, bnc.GetNetworkName(), bnc.TopologyType())
	addrSet, err := bnc.addressSetFactory.GetAddressSet(GetAdvertisedNetworkSubnetsAddressSetDBIDs())
	if err != nil && !errors.Is(err, libovsdbclient.ErrNotFound) {
		return fmt.Errorf("failed to get advertised subnets addresset %s for network %s: %w", GetAdvertisedNetworkSubnetsAddressSetDBIDs(), bnc.GetNetworkName(), err)
	}

	var ops []ovsdb.Operation
	if addrSet != nil {
		var cidrs []string
		for _, subnet := range bnc.Subnets() {
			cidrs = append(cidrs, subnet.CIDR.String())
		}
		ops, err = addrSet.DeleteAddressesReturnOps(cidrs)
		if err != nil {
			return fmt.Errorf("failed to create ovsdb ops for deleting the addresses from %s addresset for network %s: %w", GetAdvertisedNetworkSubnetsAddressSetDBIDs(), bnc.GetNetworkName(), err)
		}
	}

	passACLIDs := GetAdvertisedNetworkSubnetsPassACLdbIDs(bnc.controllerName, bnc.GetNetworkName(), bnc.GetNetworkID())
	dropACLIDs := GetAdvertisedNetworkSubnetsDropACLdbIDs()
	passACLPredicate := libovsdbops.GetPredicate[*nbdb.ACL](passACLIDs, nil)
	dropACLPredicate := libovsdbops.GetPredicate[*nbdb.ACL](dropACLIDs, nil)
	// Create a combined predicate to find both ACLs in a single lookup
	combinedACLPredicate := func(acl *nbdb.ACL) bool {
		// Check if ACL matches either pass or drop ACL IDs
		return passACLPredicate(acl) || dropACLPredicate(acl)
	}

	// Find both ACLs in a single lookup
	allACLsToRemove, err := libovsdbops.FindACLsWithPredicate(bnc.nbClient, combinedACLPredicate)
	if err != nil {
		return fmt.Errorf("unable to find pass and/or drop ACLs for advertised network %s: %w", bnc.GetNetworkName(), err)
	}

	// ACLs referenced by the switch will be deleted by db if there are no other references
	p := func(sw *nbdb.LogicalSwitch) bool { return sw.Name == bnc.GetNetworkScopedSwitchName(nodeName) }
	if len(allACLsToRemove) > 0 {
		ops, err = libovsdbops.RemoveACLsFromLogicalSwitchesWithPredicateOps(bnc.nbClient, ops, p, allACLsToRemove...)
		if err != nil {
			return fmt.Errorf("failed to create ovsdb ops for removing network isolation ACLs from the %s switch for network %s: %w", bnc.GetNetworkScopedSwitchName(nodeName), bnc.GetNetworkName(), err)
		}
	}

	klog.Infof("[UDN-DEBUG] deleteAdvertisedNetworkIsolation: transacting %d ops for node=%s network=%s, ACLsToRemove=%d",
		len(ops), nodeName, bnc.GetNetworkName(), len(allACLsToRemove))
	_, err = libovsdbops.TransactAndCheck(bnc.nbClient, ops)
	if err != nil {
		klog.Errorf("[UDN-DEBUG] deleteAdvertisedNetworkIsolation: TransactAndCheck FAILED for node=%s network=%s: %v", nodeName, bnc.GetNetworkName(), err)
	} else {
		klog.Infof("[UDN-DEBUG] deleteAdvertisedNetworkIsolation: TransactAndCheck succeeded for node=%s network=%s", nodeName, bnc.GetNetworkName())
	}
	return err
}

// debugVerifyUDNIsolationState is a diagnostic function that verifies the
// SecondaryPods port group has ACLs and ports present in NBDB. It reads
// the port group state and logs it, including full ACL details (match, action,
// direction, priority), LSP details (name, addresses, up status), and UDN
// service route status. This provides a complete "why is communication broken"
// snapshot when the failure is permanent.
func (oc *DefaultNetworkController) debugVerifyUDNIsolationState() {
	if !util.IsNetworkSegmentationSupportEnabled() {
		return
	}
	pgIDs := oc.getSecondaryPodsPortGroupDbIDs()
	pgName := libovsdbutil.GetPortGroupName(pgIDs)
	pg := &nbdb.PortGroup{Name: pgName}
	pg, err := libovsdbops.GetPortGroup(oc.nbClient, pg)
	if err != nil {
		klog.Errorf("[UDN-DEBUG] PERIODIC-CHECK: cannot read SecondaryPods portGroup=%s: %v", pgName, err)
		return
	}

	// Check that the port group has ACLs attached — 5 is expected
	if len(pg.ACLs) == 0 {
		klog.Errorf("[UDN-DEBUG] PERIODIC-CHECK: SecondaryPods portGroup=%s has ZERO ACLs! Isolation rules are missing.", pgName)
	} else if len(pg.ACLs) != 5 {
		klog.Warningf("[UDN-DEBUG] PERIODIC-CHECK: SecondaryPods portGroup=%s has unexpected aclCount=%d (expected 5) portCount=%d",
			pgName, len(pg.ACLs), len(pg.Ports))
	} else {
		klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: SecondaryPods portGroup=%s aclCount=%d portCount=%d portUUIDs=%v",
			pgName, len(pg.ACLs), len(pg.Ports), pg.Ports)
	}

	// Dump full ACL details for each ACL in the port group
	for i, aclUUID := range pg.ACLs {
		aclLookup := &nbdb.ACL{UUID: aclUUID}
		foundACLs, aclErr := libovsdbops.FindACLs(oc.nbClient, []*nbdb.ACL{aclLookup})
		if aclErr != nil || len(foundACLs) == 0 {
			klog.Errorf("[UDN-DEBUG] PERIODIC-CHECK: ACL[%d] uuid=%s LOOKUP FAILED: %v", i, aclUUID, aclErr)
			continue
		}
		a := foundACLs[0]
		aclName := ""
		if a.Name != nil {
			aclName = *a.Name
		}
		klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: ACL[%d] uuid=%s name=%q direction=%s action=%s priority=%d tier=%d match=%q",
			i, a.UUID, aclName, a.Direction, a.Action, a.Priority, a.Tier, a.Match)
	}

	// Dump LSP details for each port in the port group
	var firstPodIP, firstPodName, firstNodeName string
	for i, portUUID := range pg.Ports {
		lsp := &nbdb.LogicalSwitchPort{UUID: portUUID}
		lsp, lspErr := libovsdbops.GetLogicalSwitchPort(oc.nbClient, lsp)
		if lspErr != nil {
			klog.Errorf("[UDN-DEBUG] PERIODIC-CHECK: PORT[%d] uuid=%s LOOKUP FAILED: %v", i, portUUID, lspErr)
			continue
		}
		upStr := "nil"
		if lsp.Up != nil {
			upStr = fmt.Sprintf("%v", *lsp.Up)
		}
		klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: PORT[%d] uuid=%s name=%s up=%s addresses=%v portSecurity=%v pod=%s",
			i, lsp.UUID, lsp.Name, upStr, lsp.Addresses, lsp.PortSecurity, lsp.ExternalIDs["pod"])

		// Capture first pod details for OVS diagnostics
		if i == 0 && len(lsp.Addresses) > 0 {
			firstPodName = lsp.Name
			// Extract IP from addresses (format: ["MAC IP"])
			for _, addr := range lsp.Addresses {
				parts := strings.Fields(addr)
				if len(parts) > 1 {
					firstPodIP = parts[1] // IP is second field
					break
				}
			}
			// Extract node name from LSP options
			if nodeName, ok := lsp.Options["requested-chassis"]; ok {
				firstNodeName = nodeName
			}
		}
	}

	// CRITICAL: Check SBDB to verify NBDB ACLs are translated to logical flows
	// This detects if the control plane → data plane translation is broken
	oc.checkSBDBLogicalFlows(pgName)

	// Log OVS flow diagnostics for manual verification on worker nodes
	if firstPodIP != "" && firstNodeName != "" {
		oc.logOVSFlowDiagnostics(firstPodName, firstPodIP, firstNodeName)
	}

	// Check UDN service routes — look for static routes with UDN-enabled-service external IDs
	udnRoutes, routeErr := libovsdbops.FindLogicalRouterStaticRoutesWithPredicate(oc.nbClient, func(route *nbdb.LogicalRouterStaticRoute) bool {
		_, hasUDNService := route.ExternalIDs[types.UDNEnabledServiceExternalID]
		return hasUDNService
	})
	if routeErr != nil {
		klog.Errorf("[UDN-DEBUG] PERIODIC-CHECK: failed to look up UDN service routes: %v", routeErr)
	} else if len(udnRoutes) == 0 {
		klog.Warningf("[UDN-DEBUG] PERIODIC-CHECK: NO UDN-enabled service routes found in NBDB — KAPI access may be broken for UDN pods")
	} else {
		klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: ======== FOUND %d UDN SERVICE ROUTES IN NBDB ========", len(udnRoutes))

		// Log each route in detail
		kapiRouteFound := false
		var kapiRoutePrefix string
		for i, route := range udnRoutes {
			klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: UDN-ROUTE[%d] uuid=%s prefix=%s nexthop=%s network=%s topology=%s service=%s",
				i, route.UUID, route.IPPrefix, route.Nexthop,
				route.ExternalIDs[types.NetworkExternalID],
				route.ExternalIDs[types.TopologyExternalID],
				route.ExternalIDs[types.UDNEnabledServiceExternalID])

			// Check if this is a kubernetes.default (kapi) route
			if strings.Contains(route.ExternalIDs[types.UDNEnabledServiceExternalID], "default/kubernetes") {
				kapiRouteFound = true
				kapiRoutePrefix = route.IPPrefix
			}
		}

		// CRITICAL DEBUGGING: When kapi route exists, check if service has endpoints
		if kapiRouteFound {
			klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: ======== KAPI ROUTE EXISTS (prefix=%s) - CHECKING SERVICE HEALTH ========", kapiRoutePrefix)

			// Check kubernetes.default service endpoints using kubernetes API
			endpoints, endpointsErr := oc.client.CoreV1().Endpoints("default").Get(context.TODO(), "kubernetes", metav1.GetOptions{})
			if endpointsErr != nil {
				klog.Errorf("[UDN-DEBUG] PERIODIC-CHECK: CRITICAL - Failed to get kubernetes.default endpoints: %v", endpointsErr)
				klog.Errorf("[UDN-DEBUG] PERIODIC-CHECK: ROOT CAUSE: Cannot verify kapi service has healthy backends - API query failed")
			} else if len(endpoints.Subsets) == 0 {
				klog.Errorf("[UDN-DEBUG] PERIODIC-CHECK: CRITICAL - kubernetes.default service has NO endpoint subsets!")
				klog.Errorf("[UDN-DEBUG] PERIODIC-CHECK: ROOT CAUSE: KAPI service has no backends - this will cause connection timeouts")
			} else {
				readyCount := 0
				notReadyCount := 0
				for _, subset := range endpoints.Subsets {
					readyCount += len(subset.Addresses)
					notReadyCount += len(subset.NotReadyAddresses)
				}
				klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: kubernetes.default endpoints: ready=%d notReady=%d subsets=%d",
					readyCount, notReadyCount, len(endpoints.Subsets))

				if readyCount == 0 {
					klog.Errorf("[UDN-DEBUG] PERIODIC-CHECK: CRITICAL - kubernetes.default has %d endpoints but ZERO are ready!", notReadyCount)
					klog.Errorf("[UDN-DEBUG] PERIODIC-CHECK: ROOT CAUSE: KAPI service has no ready backends - connection will timeout")
				} else {
					// Endpoints exist and are ready - log first few for reference
					for i, subset := range endpoints.Subsets {
						for j, addr := range subset.Addresses {
							if i == 0 && j < 3 { // Log first 3 addresses from first subset
								targetRef := "nil"
								if addr.TargetRef != nil {
									targetRef = fmt.Sprintf("%s/%s", addr.TargetRef.Namespace, addr.TargetRef.Name)
								}
								klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: kubernetes.default ready endpoint[%d]: ip=%s targetRef=%s",
									j, addr.IP, targetRef)
							}
						}
					}
				}
			}

			// Check DNS service route (needed for kubernetes.default hostname resolution)
			dnsRouteFound := false
			for _, route := range udnRoutes {
				if strings.Contains(route.ExternalIDs[types.UDNEnabledServiceExternalID], "openshift-dns/dns-default") {
					dnsRouteFound = true
					klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: DNS route exists: prefix=%s nexthop=%s", route.IPPrefix, route.Nexthop)
					break
				}
			}
			if !dnsRouteFound {
				klog.Warningf("[UDN-DEBUG] PERIODIC-CHECK: WARNING - No DNS service route found - hostname resolution may fail")
				klog.Warningf("[UDN-DEBUG] PERIODIC-CHECK: POSSIBLE ROOT CAUSE: UDN pods cannot resolve 'kubernetes.default' to IP")
			}

			klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: ======== END KAPI ROUTE DIAGNOSTICS ========")
		}

		klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: ======== TROUBLESHOOTING CHECKLIST (if connectivity fails) ========")
		klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: 1. Routes in NBDB: VERIFIED ABOVE (%d routes found)", len(udnRoutes))
		klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: 2. Service endpoints: %s", func() string {
			if kapiRouteFound {
				return "CHECKED ABOVE"
			} else {
				return "N/A (no kapi route)"
			}
		}())
		klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: 3. Routes in SBDB: Check with 'ovn-sbctl --no-leader-only find Logical_Flow match~kubernetes'")
		klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: 4. OVS flows: Check with 'ovs-ofctl dump-flows br-int | grep kubernetes'")
		klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: 5. DNS resolution: Check with 'kubectl exec <pod> -- nslookup kubernetes.default'")
		klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: 6. Direct IP test: Check with 'kubectl exec <pod> -- curl -k https://<kapi-ip>/healthz'")
		klog.Infof("[UDN-DEBUG] PERIODIC-CHECK: ======== END TROUBLESHOOTING CHECKLIST ========")
	}
}

func (oc *DefaultNetworkController) syncUDNIsolation() error {
	klog.Infof("[UDN-DEBUG] syncUDNIsolation: starting legacy ACL rename sync")
	// Find ACLs with old "secondary" naming IDs, update them
	type aclUpdate struct {
		old *libovsdbops.DbObjectIDs
		new *libovsdbops.DbObjectIDs
	}
	updates := []*aclUpdate{
		{oc.getUDNACLDbIDs(denySecondaryACL, libovsdbutil.ACLEgress), oc.getUDNACLDbIDs(denyPrimaryUDNACL, libovsdbutil.ACLEgress)},
		{oc.getUDNACLDbIDs(legacyAllowHostARPACL, libovsdbutil.ACLEgress), oc.getUDNACLDbIDs(allowHostARPACL, libovsdbutil.ACLEgress)},
		{oc.getUDNACLDbIDs(denySecondaryACL, libovsdbutil.ACLIngress), oc.getUDNACLDbIDs(denyPrimaryUDNACL, libovsdbutil.ACLIngress)},
		{oc.getUDNACLDbIDs(legacyAllowHostARPACL, libovsdbutil.ACLIngress), oc.getUDNACLDbIDs(allowHostARPACL, libovsdbutil.ACLIngress)},
		{oc.getUDNACLDbIDs(allowHostSecondaryACL, libovsdbutil.ACLIngress), oc.getUDNACLDbIDs(allowHostPrimaryUDNACL, libovsdbutil.ACLIngress)},
	}

	aclsToUpdate := make([]*nbdb.ACL, 0)
	for _, update := range updates {
		legacyACLs, err := libovsdbops.FindACLsWithPredicate(oc.nbClient, libovsdbops.GetPredicate[*nbdb.ACL](update.old, nil))
		if err != nil {
			return fmt.Errorf("unable to find ACLs for UDN Isolation sync: %w", err)
		}
		for _, acl := range legacyACLs {
			externalIDs := update.new.GetExternalIDs()
			acl.ExternalIDs = externalIDs
			aclName := libovsdbutil.GetACLName(update.new)
			acl.Name = &aclName
			aclsToUpdate = append(aclsToUpdate, acl)
		}
	}
	if len(aclsToUpdate) > 0 {
		err := batching.Batch[*nbdb.ACL](20000, aclsToUpdate, func(batchACLs []*nbdb.ACL) error {
			return libovsdbops.CreateOrUpdateACLs(oc.nbClient, oc.GetSamplingConfig(), batchACLs...)
		})
		if err != nil {
			return fmt.Errorf("failed to create or update UDN ACLs: %w", err)
		}
	}

	return nil
}
