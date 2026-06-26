package ovn

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"
	"github.com/ovn-kubernetes/libovsdb/ovsdb"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
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
	// the same tier is used for all UDN isolation ACLs
	isolationTier = types.PrimaryACLTier
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

	egressARPIDs := oc.getUDNACLDbIDs(AllowHostARPACL, libovsdbutil.ACLEgress)
	match = libovsdbutil.GetACLMatch(pgName, getARPMatch(libovsdbutil.ACLEgress), libovsdbutil.ACLEgress)
	egressARPACL := libovsdbutil.BuildACL(egressARPIDs, types.PrimaryUDNAllowPriority, match, nbdb.ACLActionAllow,
		nil, libovsdbutil.LportEgress, isolationTier)

	ingressDenyIDs := oc.getUDNACLDbIDs(DenySecondaryACL, libovsdbutil.ACLIngress)
	match = libovsdbutil.GetACLMatch(pgName, "", libovsdbutil.ACLIngress)
	ingressDenyACL := libovsdbutil.BuildACL(ingressDenyIDs, types.PrimaryUDNDenyPriority, match, nbdb.ACLActionDrop,
		nil, libovsdbutil.LportIngress, isolationTier)

	ingressARPIDs := oc.getUDNACLDbIDs(AllowHostARPACL, libovsdbutil.ACLIngress)
	match = libovsdbutil.GetACLMatch(pgName, getARPMatch(libovsdbutil.ACLIngress), libovsdbutil.ACLIngress)
	ingressARPACL := libovsdbutil.BuildACL(ingressARPIDs, types.PrimaryUDNAllowPriority, match, nbdb.ACLActionAllow,
		nil, libovsdbutil.LportIngress, isolationTier)

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
	ingressAllowACL := libovsdbutil.BuildACL(ingressAllowIDs, types.PrimaryUDNAllowPriority, match, nbdb.ACLActionAllowRelated,
		nil, libovsdbutil.LportIngress, isolationTier)

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

// advertisedNetworkSubnetsKey is the object name key for the global advertised
// networks addressset, the global deny ACL and the port group hosting the deny
// ACL.
const advertisedNetworkSubnetsKey = "advertised-network-subnets"

// GetAdvertisedNetworkSubnetsAddressSetDBIDs returns the DB IDs for the advertised network subnets addressset
func GetAdvertisedNetworkSubnetsAddressSetDBIDs() *libovsdbops.DbObjectIDs {
	return libovsdbops.NewDbObjectIDs(libovsdbops.AddressSetAdvertisedNetwork, DefaultNetworkControllerName, map[libovsdbops.ExternalIDKey]string{
		libovsdbops.ObjectNameKey: advertisedNetworkSubnetsKey,
	})
}

// GetAdvertisedNetworkSubnetsDropPGdbIDs returns the DB IDs for the advertised network subnets drop port group
func GetAdvertisedNetworkSubnetsDropPGdbIDs() *libovsdbops.DbObjectIDs {
	return libovsdbops.NewDbObjectIDs(libovsdbops.PortGroupAdvertisedNetwork, DefaultNetworkControllerName,
		map[libovsdbops.ExternalIDKey]string{
			libovsdbops.ObjectNameKey: advertisedNetworkSubnetsKey,
		})
}

// GetAdvertisedNetworkSubnetsDropPGName returns the hashed name for the advertised network subnets drop port group
func GetAdvertisedNetworkSubnetsDropPGName() string {
	return libovsdbutil.GetPortGroupName(GetAdvertisedNetworkSubnetsDropPGdbIDs())
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

// ConfigureAdvertisedNetworkIsolation ensures the global resources for advertised network isolation exist.
func ConfigureAdvertisedNetworkIsolation(nbClient libovsdbclient.Client) error {
	addressSetFactory := addressset.NewOvnAddressSetFactory(nbClient, config.IPv4Mode, config.IPv6Mode)
	addrSet, ops, err := addressSetFactory.EnsureAddressSetOps(GetAdvertisedNetworkSubnetsAddressSetDBIDs())
	if err != nil {
		return fmt.Errorf("failed to ensure advertised subnets address set: %w", err)
	}

	dropACL := BuildAdvertisedNetworkSubnetsDropACL(addrSet)
	pg := libovsdbutil.BuildPortGroup(GetAdvertisedNetworkSubnetsDropPGdbIDs(), nil, nil)

	ops, err = libovsdbops.CreateOrUpdateACLsOps(nbClient, nil, nil, dropACL)
	if err != nil {
		return fmt.Errorf("failed to create or update advertised network isolation drop ACL: %w", err)
	}

	pg.ACLs = []string{dropACL.UUID}

	ops, err = libovsdbops.CreatePortGroupOps(nbClient, ops, pg)
	if err != nil {
		return fmt.Errorf("failed to create advertised network isolation port group: %w", err)
	}

	if _, err = libovsdbops.TransactAndCheck(nbClient, ops); err != nil {
		return fmt.Errorf("failed to configure advertised network isolation: %w", err)
	}
	return nil
}

// CleanupStaleAdvertisedNetworkSubnets removes subnets from the advertised network subnets address set
// that are not in validSubnets.
func CleanupStaleAdvertisedNetworkSubnets(nbClient libovsdbclient.Client, validSubnets sets.Set[string]) error {
	addressSetFactory := addressset.NewOvnAddressSetFactory(nbClient, config.IPv4Mode, config.IPv6Mode)
	addrSet, err := addressSetFactory.GetAddressSet(GetAdvertisedNetworkSubnetsAddressSetDBIDs())
	if err != nil && !errors.Is(err, libovsdbclient.ErrNotFound) {
		return fmt.Errorf("failed to get advertised subnets address set: %w", err)
	}
	if addrSet == nil {
		return nil
	}
	v4Addrs, v6Addrs := addrSet.GetAddresses()
	var stale []string
	for _, addr := range append(v4Addrs, v6Addrs...) {
		if !validSubnets.Has(addr) {
			stale = append(stale, addr)
		}
	}
	if len(stale) > 0 {
		if err := addrSet.DeleteAddresses(stale); err != nil {
			return fmt.Errorf("failed to delete stale addresses %q from advertised network subnets address set: %w", stale, err)
		}
	}
	return nil
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
// We end up with the following ACLs:
// action match                                                                       priority
// ------ --------------------------------------------------------------------------- --------
// pass   "(ip[4|6].src == <UDN_SUBNET> && ip[4|6].dst == <UDN_SUBNET>)"                1100
// drop   "(ip[4|6].src == $<ALL_ADV_SUBNETS> && ip[4|6].dst == $<ALL_ADV_SUBNETS>)"    1050
// The pass ACL is added to the node switch. The drop ACL is on a port group shared by all
// advertised networks. The stor port of this network's switch is added to that port group
// so the drop ACL applies to the whole switch.
// On upgrade from switch-based drop ACL, stale switch references are removed in the same transaction.
func (bnc *BaseNetworkController) addAdvertisedNetworkIsolation(nodeName string) error {
	var passMatches, cidrs []string
	var ops []ovsdb.Operation

	addrSet, err := bnc.addressSetFactory.GetAddressSet(GetAdvertisedNetworkSubnetsAddressSetDBIDs())
	if err != nil {
		return fmt.Errorf("failed to get advertised subnets address set for network %s: %w", bnc.GetNetworkName(), err)
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

	switchName := bnc.GetNetworkScopedSwitchName(nodeName)

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
			return fmt.Errorf("failed to create or update network isolation pass ACL for network %s: %w", bnc.GetNetworkName(), err)
		}
		ops, err = libovsdbops.AddACLsToLogicalSwitchOps(bnc.nbClient, ops, switchName, passACL)
		if err != nil {
			return fmt.Errorf("failed to add network isolation pass ACL to switch %s for network %s: %w", switchName, bnc.GetNetworkName(), err)
		}
	}

	// Add the stor port to the port group
	pgName := GetAdvertisedNetworkSubnetsDropPGName()
	storPortName := bnc.GetNetworkScopedSwitchToRouterPortName(nodeName)
	storLSP, err := libovsdbops.GetLogicalSwitchPort(bnc.nbClient, &nbdb.LogicalSwitchPort{Name: storPortName})
	if err != nil {
		return fmt.Errorf("failed to get stor port %s: %w", storPortName, err)
	}
	ops, err = libovsdbops.AddPortsToPortGroupOps(bnc.nbClient, ops, pgName, storLSP.UUID)
	if err != nil {
		return fmt.Errorf("failed to add stor port %s to advertised network isolation port group: %w", storPortName, err)
	}

	if _, err = libovsdbops.TransactAndCheck(bnc.nbClient, ops); err != nil {
		return fmt.Errorf("failed to configure network isolation OVN rules for network %s: %w", bnc.GetNetworkName(), err)
	}
	return nil
}

// deleteAdvertisedNetworkIsolation deletes advertised network isolation rules from the given node switch.
// It removes the network CIDRs from the global advertised networks address set, removes the pass ACL from
// the node switch, and removes the stor port from the advertised network drop port group.
func (bnc *BaseNetworkController) deleteAdvertisedNetworkIsolation(nodeName string) error {
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

	switchName := bnc.GetNetworkScopedSwitchName(nodeName)

	// Remove the pass ACL from the switch
	passACLIDs := GetAdvertisedNetworkSubnetsPassACLdbIDs(bnc.controllerName, bnc.GetNetworkName(), bnc.GetNetworkID())
	passACL, err := libovsdbops.GetACL(bnc.nbClient, &nbdb.ACL{ExternalIDs: passACLIDs.GetExternalIDs()})
	if err != nil && !errors.Is(err, libovsdbclient.ErrNotFound) {
		return fmt.Errorf("unable to find pass ACL for advertised network %s: %w", bnc.GetNetworkName(), err)
	}
	if passACL != nil {
		ops, err = libovsdbops.RemoveACLsFromLogicalSwitchOps(bnc.nbClient, ops, switchName, passACL)
		if err != nil {
			return fmt.Errorf("failed to remove pass ACL from switch %s for network %s: %w", switchName, bnc.GetNetworkName(), err)
		}
	}

	// Remove the stor port from the port group
	storPortName := bnc.GetNetworkScopedSwitchToRouterPortName(nodeName)
	storLSP, err := libovsdbops.GetLogicalSwitchPort(bnc.nbClient, &nbdb.LogicalSwitchPort{Name: storPortName})
	if err != nil && !errors.Is(err, libovsdbclient.ErrNotFound) {
		return fmt.Errorf("failed to get stor port %s: %w", storPortName, err)
	}
	if storLSP != nil {
		ops, err = libovsdbops.DeletePortsFromPortGroupOps(bnc.nbClient, ops, GetAdvertisedNetworkSubnetsDropPGName(), storLSP.UUID)
		if err != nil {
			return fmt.Errorf("failed to remove stor port %s from advertised network isolation port group: %w", storPortName, err)
		}
	}

	_, err = libovsdbops.TransactAndCheck(bnc.nbClient, ops)
	return err
}
