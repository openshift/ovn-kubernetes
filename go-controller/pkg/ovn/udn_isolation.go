package ovn

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"
	"github.com/ovn-kubernetes/libovsdb/ovsdb"

	libovsdbops "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	libovsdbutil "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/util"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	addressset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/address_set"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	utilerrors "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util/errors"
)

const (
	// UDN ACL names, should be unique across all controllers
	// Default network-only ACLs:
	AllowHostARPACL       = "AllowHostARPSecondary"
	AllowHostSecondaryACL = "AllowHostSecondary"
	DenySecondaryACL      = "DenySecondary"
	// OpenPortACLPrefix is used to build per-pod ACLs, pod name should be added to the prefix to build a unique name
	OpenPortACLPrefix = "OpenPort-"
)

// setupUDNACLs should be called after the node's management port was configured
// Only used on default network switches.
func (oc *DefaultNetworkController) setupUDNACLs(mgmtPortIPs []net.IP) error {
	if !util.IsNetworkSegmentationSupportEnabled() {
		return nil
	}
	// add port group to track secondary pods
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
	egressDenyIDs := oc.getUDNACLDbIDs(DenySecondaryACL, libovsdbutil.ACLEgress)
	match := libovsdbutil.GetACLMatch(pgName, "", libovsdbutil.ACLEgress)
	egressDenyACL := libovsdbutil.BuildACL(egressDenyIDs, types.PrimaryUDNDenyPriority, match, nbdb.ACLActionDrop, nil, libovsdbutil.LportEgress)

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

	egressARPIDs := oc.getUDNACLDbIDs(AllowHostARPACL, libovsdbutil.ACLEgress)
	match = libovsdbutil.GetACLMatch(pgName, getARPMatch(libovsdbutil.ACLEgress), libovsdbutil.ACLEgress)
	egressARPACL := libovsdbutil.BuildACL(egressARPIDs, types.PrimaryUDNAllowPriority, match, nbdb.ACLActionAllow, nil, libovsdbutil.LportEgress)

	ingressDenyIDs := oc.getUDNACLDbIDs(DenySecondaryACL, libovsdbutil.ACLIngress)
	match = libovsdbutil.GetACLMatch(pgName, "", libovsdbutil.ACLIngress)
	ingressDenyACL := libovsdbutil.BuildACL(ingressDenyIDs, types.PrimaryUDNDenyPriority, match, nbdb.ACLActionDrop, nil, libovsdbutil.LportIngress)

	ingressARPIDs := oc.getUDNACLDbIDs(AllowHostARPACL, libovsdbutil.ACLIngress)
	match = libovsdbutil.GetACLMatch(pgName, getARPMatch(libovsdbutil.ACLIngress), libovsdbutil.ACLIngress)
	ingressARPACL := libovsdbutil.BuildACL(ingressARPIDs, types.PrimaryUDNAllowPriority, match, nbdb.ACLActionAllow, nil, libovsdbutil.LportIngress)

	ingressAllowIDs := oc.getUDNACLDbIDs(AllowHostSecondaryACL, libovsdbutil.ACLIngress)
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
	ingressAllowACL := libovsdbutil.BuildACL(ingressAllowIDs, types.PrimaryUDNAllowPriority, match, nbdb.ACLActionAllowRelated, nil, libovsdbutil.LportIngress)

	ops, err := libovsdbops.CreateOrUpdateACLsOps(oc.nbClient, nil, oc.GetSamplingConfig(), egressDenyACL, egressARPACL, ingressARPACL, ingressDenyACL, ingressAllowACL)
	if err != nil {
		return fmt.Errorf("failed to create or update UDN ACLs: %v", err)
	}

	ops, err = libovsdbops.AddACLsToPortGroupOps(oc.nbClient, ops, pgName, egressDenyACL, egressARPACL, ingressARPACL, ingressDenyACL, ingressAllowACL)
	if err != nil {
		return fmt.Errorf("failed to add UDN ACLs to portGroup %s: %v", pgName, err)
	}

	_, err = libovsdbops.TransactAndCheck(oc.nbClient, ops)
	return err
}

func (oc *DefaultNetworkController) getSecondaryPodsPortGroupDbIDs() *libovsdbops.DbObjectIDs {
	return libovsdbops.NewDbObjectIDs(libovsdbops.PortGroupUDN, oc.controllerName,
		map[libovsdbops.ExternalIDKey]string{
			libovsdbops.ObjectNameKey: "SecondaryPods",
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
	// don't return on parseErr, as we need to cleanup potentially present ACLs from the previous config
	ingressIDs := oc.getUDNOpenPortDbIDs(podNamespacedName, libovsdbutil.ACLIngress)
	ingressACL := libovsdbutil.BuildACL(ingressIDs, types.PrimaryUDNAllowPriority,
		ingressMatch, nbdb.ACLActionAllowRelated, nil, libovsdbutil.LportIngress)

	egressIDs := oc.getUDNOpenPortDbIDs(podNamespacedName, libovsdbutil.ACLEgress)
	egressACL := libovsdbutil.BuildACL(egressIDs, types.PrimaryUDNAllowPriority,
		egressMatch, nbdb.ACLActionAllow, nil, libovsdbutil.LportEgress)

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
	return libovsdbops.NewDbObjectIDs(libovsdbops.AddressSetAdvertisedNetwork, DefaultNetworkControllerName, map[libovsdbops.ExternalIDKey]string{
		libovsdbops.ObjectNameKey: advertisedNetworkSubnetsKey,
	})
}

// GetAdvertisedNetworkSubnetsDropACLdbIDs returns the DB IDs for the advertised network subnets drop ACL
func GetAdvertisedNetworkSubnetsDropACLdbIDs() *libovsdbops.DbObjectIDs {
	return libovsdbops.NewDbObjectIDs(libovsdbops.ACLAdvertisedNetwork, DefaultNetworkControllerName,
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
		libovsdbutil.LportEgressAfterLB)
	dropACL.Tier = types.PrimaryACLTier
	return dropACL
}

// addAdvertisedNetworkIsolation adds advertised network isolation rules to the given node.
// It adds the following ACLs to the node switch:
// action match                                                                       priority
// ------ --------------------------------------------------------------------------- --------
// pass   "(ip[4|6].src == <UDN_SUBNET> && ip[4|6].dst == <UDN_SUBNET>)"                1100
// drop   "(ip[4|6].src == $<ALL_ADV_SUBNETS> && ip[4|6].dst == $<ALL_ADV_SUBNETS>)"    1050
func (bnc *BaseNetworkController) addAdvertisedNetworkIsolation(nodeName string) error {
	var passMatches, cidrs []string
	var ops []ovsdb.Operation

	addrSet, err := bnc.addressSetFactory.GetAddressSet(GetAdvertisedNetworkSubnetsAddressSetDBIDs())
	if err != nil {
		return fmt.Errorf("failed to get advertised subnets addresset %s for network %s: %w", GetAdvertisedNetworkSubnetsAddressSetDBIDs(), bnc.GetNetworkName(), err)
	}

	for _, subnet := range bnc.Subnets() {
		ipPrefix := "ip4"
		if utilnet.IsIPv6CIDR(subnet.CIDR) {
			ipPrefix = "ip6"
		}
		passMatches = append(passMatches, fmt.Sprintf("(%s.src == %s && %s.dst == %s)", ipPrefix, subnet.CIDR, ipPrefix, subnet.CIDR))
		cidrs = append(cidrs, subnet.CIDR.String())

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
			libovsdbutil.LportEgressAfterLB)
		passACL.Tier = types.PrimaryACLTier

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

	if _, err = libovsdbops.TransactAndCheck(bnc.nbClient, ops); err != nil {
		return fmt.Errorf("failed to configure network isolation OVN rules for network %s: %w", bnc.GetNetworkName(), err)
	}
	return nil
}

// deleteAdvertisedNetworkIsolation deletes advertised network isolation rules from the given node switch.
// It removes the network CIDRs from the global advertised networks addresset together with the ACLs on the node switch.
func (bnc *BaseNetworkController) deleteAdvertisedNetworkIsolation(nodeName string) error {
	addrSet, err := bnc.addressSetFactory.GetAddressSet(GetAdvertisedNetworkSubnetsAddressSetDBIDs())
	if err != nil {
		return fmt.Errorf("failed to get advertised subnets addresset %s for network %s: %w", GetAdvertisedNetworkSubnetsAddressSetDBIDs(), bnc.GetNetworkName(), err)
	}

	var cidrs []string
	for _, subnet := range bnc.Subnets() {
		cidrs = append(cidrs, subnet.CIDR.String())
	}
	ops, err := addrSet.DeleteAddressesReturnOps(cidrs)
	if err != nil {
		return fmt.Errorf("failed to create ovsdb ops for deleting the addresses from %s addresset for network %s: %w", GetAdvertisedNetworkSubnetsAddressSetDBIDs(), bnc.GetNetworkName(), err)
	}

	passACLIDs := GetAdvertisedNetworkSubnetsPassACLdbIDs(bnc.controllerName, bnc.GetNetworkName(), bnc.GetNetworkID())
	passACLPredicate := libovsdbops.GetPredicate[*nbdb.ACL](passACLIDs, nil)
	passACLs, err := libovsdbops.FindACLsWithPredicate(bnc.nbClient, passACLPredicate)
	if err != nil {
		return fmt.Errorf("unable to find the pass ACL for advertised network %s: %w", bnc.GetNetworkName(), err)
	}

	dropACLIDs := GetAdvertisedNetworkSubnetsDropACLdbIDs()
	dropACLPredicate := libovsdbops.GetPredicate[*nbdb.ACL](dropACLIDs, nil)
	dropACLs, err := libovsdbops.FindACLsWithPredicate(bnc.nbClient, dropACLPredicate)
	if err != nil {
		return fmt.Errorf("unable to find the drop ACL for advertised network %s: %w", bnc.GetNetworkName(), err)
	}

	// ACLs referenced by the switch will be deleted by db if there are no other references
	p := func(sw *nbdb.LogicalSwitch) bool { return sw.Name == bnc.GetNetworkScopedSwitchName(nodeName) }
	ops, err = libovsdbops.RemoveACLsFromLogicalSwitchesWithPredicateOps(bnc.nbClient, ops, p, append(passACLs, dropACLs...)...)
	if err != nil {
		return fmt.Errorf("failed to create ovsdb ops for removing network isolation ACLs from the %s switch for network %s: %w", bnc.GetNetworkScopedSwitchName(nodeName), bnc.GetNetworkName(), err)
	}

	_, err = libovsdbops.TransactAndCheck(bnc.nbClient, ops)
	return err
}
