package ovn

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	egressfirewallapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	addressset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/address_set"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util/batching"

	kapi "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

const (
	egressFirewallAppliedCorrectly = "EgressFirewall Rules applied"
	egressFirewallAddError         = "EgressFirewall Rules not correctly added"
	// egressFirewallACLExtIdKey external ID key for egress firewall ACLs
	egressFirewallACLExtIdKey = "egressFirewall"
	aclDeleteBatchSize        = 1000
)

type egressFirewall struct {
	sync.Mutex
	name        string
	namespace   string
	egressRules []*egressFirewallRule
}

type egressFirewallRule struct {
	id     int
	access egressfirewallapi.EgressFirewallRuleType
	ports  []egressfirewallapi.EgressFirewallPort
	to     destination
}

type destination struct {
	cidrSelector string
	dnsName      string
	// clusterSubnetIntersection is true, if egress firewall rule CIDRSelector intersects with clusterSubnet.
	// Based on this flag we can omit clusterSubnet exclusion from the related ACL.
	// For dns-based rules, EgressDNS won't add ips from clusterSubnet to the address set.
	clusterSubnetIntersection bool
}

// cloneEgressFirewall shallow copies the egressfirewallapi.EgressFirewall object provided.
// This concretely means that it create a new egressfirewallapi.EgressFirewall with the name and
// namespace set, but without any rules specified.
func cloneEgressFirewall(originalEgressfirewall *egressfirewallapi.EgressFirewall) *egressFirewall {
	ef := &egressFirewall{
		name:        originalEgressfirewall.Name,
		namespace:   originalEgressfirewall.Namespace,
		egressRules: make([]*egressFirewallRule, 0),
	}
	return ef
}

func newEgressFirewallRule(rawEgressFirewallRule egressfirewallapi.EgressFirewallRule, id int) (*egressFirewallRule, error) {
	efr := &egressFirewallRule{
		id:     id,
		access: rawEgressFirewallRule.Type,
	}

	if rawEgressFirewallRule.To.DNSName != "" {
		efr.to.dnsName = rawEgressFirewallRule.To.DNSName
	} else {

		_, ipNet, err := net.ParseCIDR(rawEgressFirewallRule.To.CIDRSelector)
		if err != nil {
			return nil, err
		}
		efr.to.cidrSelector = rawEgressFirewallRule.To.CIDRSelector
		intersect := false
		for _, clusterSubnet := range config.Default.ClusterSubnets {
			if clusterSubnet.CIDR.Contains(ipNet.IP) || ipNet.Contains(clusterSubnet.CIDR.IP) {
				intersect = true
				break
			}
		}
		efr.to.clusterSubnetIntersection = intersect
	}
	efr.ports = rawEgressFirewallRule.Ports

	return efr, nil
}

// This function is used to sync egress firewall setup. Egress firewall implementation had many versions,
// the latest one makes no difference for gateway modes, and creates ACLs on types.ClusterPortGroupName.
// The following cleanups are needed from the previous versions:
// - 	Cleanup the old implementation (using LRP) in local GW mode
//  	For this it just deletes all LRP setup done for egress firewall
//  	And also convert all old ACLs which specifed from-lport to specifying to-lport

// -	Cleanup the old implementation (using ACLs on the join and node switches)
//  	For this it deletes all the ACLs on the join and node switches, they will be created from scratch later.

// NOTE: Utilize the fact that we know that all egress firewall related setup must have a priority: types.MinimumReservedEgressFirewallPriority <= priority <= types.EgressFirewallStartPriority
// Upon failure, it may be invoked multiple times in order to avoid a pod restart.
func (oc *Controller) syncEgressFirewall(egressFirewalls []interface{}) error {
	// Lookup all ACLs used for egress Firewalls
	aclPred := func(item *nbdb.ACL) bool {
		return item.Priority >= types.MinimumReservedEgressFirewallPriority && item.Priority <= types.EgressFirewallStartPriority
	}
	egressFirewallACLs, err := libovsdbops.FindACLsWithPredicate(oc.nbClient, aclPred)
	if err != nil {
		return fmt.Errorf("unable to list egress firewall ACLs, cannot cleanup old stale data, err: %v", err)
	}

	// update the direction of each egressFirewallACL if needed
	for i := range egressFirewallACLs {
		egressFirewallACLs[i].Direction = types.DirectionToLPort
		err = libovsdbops.UpdateACLsDirection(oc.nbClient, egressFirewallACLs[i])
		if err != nil {
			return fmt.Errorf("unable to set ACL direction on egress firewall acls, cannot convert old ACL data err: %v", err)
		}
	}

	// In any gateway mode, make sure to delete all LRPs on ovn_cluster_router.
	p := func(item *nbdb.LogicalRouterPolicy) bool {
		return item.Priority <= types.EgressFirewallStartPriority && item.Priority >= types.MinimumReservedEgressFirewallPriority
	}
	err = libovsdbops.DeleteLogicalRouterPoliciesWithPredicate(oc.nbClient, types.OVNClusterRouter, p)
	if err != nil {
		return fmt.Errorf("error deleting egress firewall policies on router %s: %v", types.OVNClusterRouter, err)
	}

	// delete acls from all switches, they reside on the port group now
	if len(egressFirewallACLs) != 0 {
		err = batching.Batch[*nbdb.ACL](aclDeleteBatchSize, egressFirewallACLs, func(batchACLs []*nbdb.ACL) error {
			// optimize the predicate to exclude switches that don't reference deleting acls.
			aclsToDelete := sets.String{}
			for _, acl := range batchACLs {
				aclsToDelete.Insert(acl.UUID)
			}
			swWithACLsPred := func(sw *nbdb.LogicalSwitch) bool {
				return aclsToDelete.HasAny(sw.ACLs...)
			}
			return libovsdbops.RemoveACLsFromLogicalSwitchesWithPredicate(oc.nbClient, swWithACLsPred, batchACLs...)
		})
		if err != nil {
			return fmt.Errorf("failed to remove egress firewall acls from node logical switches: %v", err)
		}
	}

	// sync the ovn and k8s egressFirewall states
	// represents the namespaces that have firewalls according to  ovn
	ovnEgressFirewalls := make(map[string]struct{})

	for _, egressFirewallACL := range egressFirewallACLs {
		if ns, ok := egressFirewallACL.ExternalIDs[egressFirewallACLExtIdKey]; ok {
			// Most egressFirewalls will have more then one ACL but we only need to know if there is one for the namespace
			// so a map is fine and we will add an entry every iteration but because it is a map will overwrite the previous
			// entry if it already existed
			ovnEgressFirewalls[ns] = struct{}{}
		}
	}

	// get all the k8s EgressFirewall Objects
	egressFirewallList, err := oc.kube.GetEgressFirewalls()
	if err != nil {
		return fmt.Errorf("cannot reconcile the state of egressfirewalls in ovn database and k8s. err: %v", err)
	}
	// delete entries from the map that exist in k8s and ovn
	for _, egressFirewall := range egressFirewallList.Items {
		delete(ovnEgressFirewalls, egressFirewall.Namespace)
	}
	// any that are left are spurious and should be cleaned up
	for spuriousEF := range ovnEgressFirewalls {
		err := oc.deleteEgressFirewallRules(spuriousEF)
		if err != nil {
			return fmt.Errorf("cannot fully reconcile the state of egressfirewalls ACLs for namespace %s still exist in ovn db: %v", spuriousEF, err)
		}
	}
	return nil
}

func (oc *Controller) addEgressFirewall(egressFirewall *egressfirewallapi.EgressFirewall) error {
	klog.Infof("Adding egressFirewall %s in namespace %s", egressFirewall.Name, egressFirewall.Namespace)

	ef := cloneEgressFirewall(egressFirewall)
	ef.Lock()
	defer ef.Unlock()
	// there should not be an item already in egressFirewall map for the given Namespace
	if _, loaded := oc.egressFirewalls.Load(egressFirewall.Namespace); loaded {
		return fmt.Errorf("error attempting to add egressFirewall %s to namespace %s when it already has an egressFirewall",
			egressFirewall.Name, egressFirewall.Namespace)
	}

	var errorList []error
	for i, egressFirewallRule := range egressFirewall.Spec.Egress {
		// process Rules into egressFirewallRules for egressFirewall struct
		if i > types.EgressFirewallStartPriority-types.MinimumReservedEgressFirewallPriority {
			klog.Warningf("egressFirewall for namespace %s has too many rules, the rest will be ignored",
				egressFirewall.Namespace)
			break
		}
		efr, err := newEgressFirewallRule(egressFirewallRule, i)
		if err != nil {
			errorList = append(errorList, fmt.Errorf("cannot create EgressFirewall Rule to destination %s for namespace %s: %w",
				egressFirewallRule.To.CIDRSelector, egressFirewall.Namespace, err))
			continue

		}
		ef.egressRules = append(ef.egressRules, efr)
	}
	if len(errorList) > 0 {
		return errors.NewAggregate(errorList)
	}

	// EgressFirewall needs to make sure that the address_set for the namespace exists independently of the namespace object
	// so that OVN doesn't get unresolved references to the address_set.
	// TODO: This should go away once we do something like refcounting for address_sets.
	_, err := oc.addressSetFactory.EnsureAddressSet(egressFirewall.Namespace)
	if err != nil {
		return fmt.Errorf("cannot Ensure that addressSet for namespace %s exists %v", egressFirewall.Namespace, err)
	}
	ipv4HashedAS, ipv6HashedAS := addressset.MakeAddressSetHashNames(egressFirewall.Namespace)
	if err := oc.addEgressFirewallRules(ef, ipv4HashedAS, ipv6HashedAS, types.EgressFirewallStartPriority); err != nil {
		return err
	}
	oc.egressFirewalls.Store(egressFirewall.Namespace, ef)
	return nil
}

func (oc *Controller) deleteEgressFirewall(egressFirewallObj *egressfirewallapi.EgressFirewall) error {
	klog.Infof("Deleting egress Firewall %s in namespace %s", egressFirewallObj.Name, egressFirewallObj.Namespace)
	deleteDNS := false
	obj, loaded := oc.egressFirewalls.Load(egressFirewallObj.Namespace)
	if !loaded {
		return fmt.Errorf("there is no egressFirewall found in namespace %s",
			egressFirewallObj.Namespace)
	}

	ef, ok := obj.(*egressFirewall)
	if !ok {
		return fmt.Errorf("deleteEgressFirewall failed: type assertion to *egressFirewall"+
			" failed for EgressFirewall %s of type %T in namespace %s",
			egressFirewallObj.Name, obj, egressFirewallObj.Namespace)
	}

	ef.Lock()
	defer ef.Unlock()
	for _, rule := range ef.egressRules {
		if len(rule.to.dnsName) > 0 {
			deleteDNS = true
			break
		}
	}
	// delete acls first, then dns address set that is referenced in these acls
	if err := oc.deleteEgressFirewallRules(egressFirewallObj.Namespace); err != nil {
		return err
	}
	if deleteDNS {
		if err := oc.egressFirewallDNS.Delete(egressFirewallObj.Namespace); err != nil {
			return err
		}
	}
	oc.egressFirewalls.Delete(egressFirewallObj.Namespace)
	return nil
}

func (oc *Controller) updateEgressFirewallStatusWithRetry(egressfirewall *egressfirewallapi.EgressFirewall) error {
	retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		return oc.kube.UpdateEgressFirewall(egressfirewall)
	})
	if retryErr != nil {
		return fmt.Errorf("error in updating status on EgressFirewall %s/%s: %v",
			egressfirewall.Namespace, egressfirewall.Name, retryErr)
	}
	return nil
}

func (oc *Controller) addEgressFirewallRules(ef *egressFirewall, hashedAddressSetNameIPv4, hashedAddressSetNameIPv6 string, efStartPriority int) error {
	for _, rule := range ef.egressRules {
		var action string
		var matchTargets []matchTarget
		if rule.access == egressfirewallapi.EgressFirewallRuleAllow {
			action = "allow"
		} else {
			action = "drop"
		}
		if rule.to.cidrSelector != "" {
			if utilnet.IsIPv6CIDRString(rule.to.cidrSelector) {
				matchTargets = []matchTarget{{matchKindV6CIDR, rule.to.cidrSelector, rule.to.clusterSubnetIntersection}}
			} else {
				matchTargets = []matchTarget{{matchKindV4CIDR, rule.to.cidrSelector, rule.to.clusterSubnetIntersection}}
			}
		} else {
			// rule based on DNS NAME
			dnsNameAddressSets, err := oc.egressFirewallDNS.Add(ef.namespace, rule.to.dnsName)
			if err != nil {
				return fmt.Errorf("error with EgressFirewallDNS - %v", err)
			}
			dnsNameIPv4ASHashName, dnsNameIPv6ASHashName := dnsNameAddressSets.GetASHashNames()
			if dnsNameIPv4ASHashName != "" {
				matchTargets = append(matchTargets, matchTarget{matchKindV4AddressSet, dnsNameIPv4ASHashName, rule.to.clusterSubnetIntersection})
			}
			if dnsNameIPv6ASHashName != "" {
				matchTargets = append(matchTargets, matchTarget{matchKindV6AddressSet, dnsNameIPv6ASHashName, rule.to.clusterSubnetIntersection})
			}
		}
		match := generateMatch(hashedAddressSetNameIPv4, hashedAddressSetNameIPv6, matchTargets, rule.ports)
		err := oc.createEgressFirewallRules(efStartPriority-rule.id, match, action, ef.namespace)
		if err != nil {
			return err
		}
	}
	return nil
}

// createEgressFirewallRules uses the previously generated elements and creates the
// acls for all node switches
func (oc *Controller) createEgressFirewallRules(priority int, match, action, externalID string) error {
	egressFirewallACL := &nbdb.ACL{
		Priority:    priority,
		Direction:   types.DirectionToLPort,
		Match:       match,
		Action:      action,
		ExternalIDs: map[string]string{egressFirewallACLExtIdKey: externalID},
	}

	ops, err := libovsdbops.CreateOrUpdateACLsOps(oc.nbClient, nil, egressFirewallACL)
	if err != nil {
		return fmt.Errorf("failed to create egressFirewall ACL %v: %v", egressFirewallACL, err)
	}

	// Applying ACLs on types.ClusterPortGroupName is equivalent to applying on every node switch, since
	// types.ClusterPortGroupName contains management port from every switch.
	ops, err = libovsdbops.AddACLsToPortGroupOps(oc.nbClient, ops, types.ClusterPortGroupName, egressFirewallACL)
	if err != nil {
		return fmt.Errorf("failed to add egressFirewall ACL %v to port group %s: %v",
			egressFirewallACL, types.ClusterPortGroupName, err)
	}
	_, err = libovsdbops.TransactAndCheck(oc.nbClient, ops)
	if err != nil {
		return fmt.Errorf("failed to transact egressFirewall ACL: %v", err)
	}

	return nil
}

// deleteEgressFirewallRules delete egress firewall Acls
func (oc *Controller) deleteEgressFirewallRules(externalID string) error {
	// Find ACLs for a given egressFirewall
	pACL := func(item *nbdb.ACL) bool {
		return item.ExternalIDs[egressFirewallACLExtIdKey] == externalID
	}
	egressFirewallACLs, err := libovsdbops.FindACLsWithPredicate(oc.nbClient, pACL)
	if err != nil {
		return fmt.Errorf("unable to list egress firewall ACLs, cannot cleanup old stale data, err: %v", err)
	}

	if len(egressFirewallACLs) == 0 {
		klog.Warningf("No egressFirewall ACLs to delete in ns: %s", externalID)
		return nil
	}

	err = libovsdbops.DeleteACLsFromPortGroups(oc.nbClient, []string{types.ClusterPortGroupName}, egressFirewallACLs...)
	if err != nil {
		return err
	}

	return nil
}

type matchTarget struct {
	kind  matchKind
	value string
	// clusterSubnetIntersection is inherited from the egressFirewallRule destination.
	// clusterSubnetIntersection is true, if egress firewall rule CIDRSelector intersects with clusterSubnet.
	// Based on this flag we can omit clusterSubnet exclusion from the related ACL.
	// For dns-based rules, EgressDNS won't add ips from clusterSubnet to the address set.
	clusterSubnetIntersection bool
}

type matchKind int

const (
	matchKindV4CIDR matchKind = iota
	matchKindV6CIDR
	matchKindV4AddressSet
	matchKindV6AddressSet
)

func (m *matchTarget) toExpr() (string, error) {
	var match string
	switch m.kind {
	case matchKindV4CIDR:
		match = fmt.Sprintf("ip4.dst == %s", m.value)
		if m.clusterSubnetIntersection {
			match = fmt.Sprintf("%s && %s", match, getV4ClusterSubnetsExclusion())
		}
	case matchKindV6CIDR:
		match = fmt.Sprintf("ip6.dst == %s", m.value)
		if m.clusterSubnetIntersection {
			match = fmt.Sprintf("%s && %s", match, getV6ClusterSubnetsExclusion())
		}
	case matchKindV4AddressSet:
		if m.value != "" {
			match = fmt.Sprintf("ip4.dst == $%s", m.value)
		}
	case matchKindV6AddressSet:
		if m.value != "" {
			match = fmt.Sprintf("ip6.dst == $%s", m.value)
		}
	default:
		return "", fmt.Errorf("invalid MatchKind")
	}
	return match, nil
}

// generateMatch generates the "match" section of ACL generation for egressFirewallRules.
// It is referentially transparent as all the elements have been validated before this function is called
// sample output:
// match=\"(ip4.dst == 1.2.3.4/32) && ip4.src == $testv4 && ip4.dst != 10.128.0.0/14\
func generateMatch(ipv4Source, ipv6Source string, destinations []matchTarget, dstPorts []egressfirewallapi.EgressFirewallPort) string {
	var src string
	var dst string
	switch {
	case config.IPv4Mode && config.IPv6Mode:
		// if any destination contains both IP family v4 and v6, add v4 and v6 src, otherwise just add a src for the IP family.
		var v4SrcReq, v6SrcReq bool
		for _, d := range destinations {
			if d.kind == matchKindV4CIDR || d.kind == matchKindV4AddressSet {
				v4SrcReq = true
			}
			if d.kind == matchKindV6CIDR || d.kind == matchKindV6AddressSet {
				v6SrcReq = true
			}
		}
		if v4SrcReq && v6SrcReq {
			src = fmt.Sprintf("(ip4.src == $%s || ip6.src == $%s)", ipv4Source, ipv6Source)
		} else if v4SrcReq {
			src = fmt.Sprintf("ip4.src == $%s", ipv4Source)
		} else {
			src = fmt.Sprintf("ip6.src == $%s", ipv6Source)
		}
	case config.IPv4Mode:
		src = fmt.Sprintf("ip4.src == $%s", ipv4Source)
	case config.IPv6Mode:
		src = fmt.Sprintf("ip6.src == $%s", ipv6Source)
	}

	for _, entry := range destinations {
		if entry.value == "" {
			continue
		}
		ipDst, err := entry.toExpr()
		if err != nil {
			klog.Error(err)
			continue
		}
		if dst == "" {
			dst = ipDst
		} else {
			dst = strings.Join([]string{dst, ipDst}, " || ")
		}
	}
	match := fmt.Sprintf("(%s) && %s", dst, src)
	if len(dstPorts) > 0 {
		match = fmt.Sprintf("%s && %s", match, egressGetL4Match(dstPorts))
	}
	return match
}

// egressGetL4Match generates the rules for when ports are specified in an egressFirewall Rule
// since the ports can be specified in any order in an egressFirewallRule the best way to build up
// a single rule is to build up each protocol as you walk through the list and place the appropriate logic
// between the elements.
func egressGetL4Match(ports []egressfirewallapi.EgressFirewallPort) string {
	var udpString string
	var tcpString string
	var sctpString string
	for _, port := range ports {
		if kapi.Protocol(port.Protocol) == kapi.ProtocolUDP && udpString != "udp" {
			if port.Port == 0 {
				udpString = "udp"
			} else {
				udpString = fmt.Sprintf("%s udp.dst == %d ||", udpString, port.Port)
			}
		} else if kapi.Protocol(port.Protocol) == kapi.ProtocolTCP && tcpString != "tcp" {
			if port.Port == 0 {
				tcpString = "tcp"
			} else {
				tcpString = fmt.Sprintf("%s tcp.dst == %d ||", tcpString, port.Port)
			}
		} else if kapi.Protocol(port.Protocol) == kapi.ProtocolSCTP && sctpString != "sctp" {
			if port.Port == 0 {
				sctpString = "sctp"
			} else {
				sctpString = fmt.Sprintf("%s sctp.dst == %d ||", sctpString, port.Port)
			}
		}
	}
	// build the l4 match
	var l4Match string
	type tuple struct {
		protocolName     string
		protocolFormated string
	}
	list := []tuple{
		{
			protocolName:     "udp",
			protocolFormated: udpString,
		},
		{
			protocolName:     "tcp",
			protocolFormated: tcpString,
		},
		{
			protocolName:     "sctp",
			protocolFormated: sctpString,
		},
	}
	for _, entry := range list {
		if entry.protocolName == entry.protocolFormated {
			if l4Match == "" {
				l4Match = fmt.Sprintf("(%s)", entry.protocolName)
			} else {
				l4Match = fmt.Sprintf("%s || (%s)", l4Match, entry.protocolName)
			}
		} else {
			if l4Match == "" && entry.protocolFormated != "" {
				l4Match = fmt.Sprintf("(%s && (%s))", entry.protocolName, entry.protocolFormated[:len(entry.protocolFormated)-2])
			} else if entry.protocolFormated != "" {
				l4Match = fmt.Sprintf("%s || (%s && (%s))", l4Match, entry.protocolName, entry.protocolFormated[:len(entry.protocolFormated)-2])
			}
		}
	}
	return fmt.Sprintf("(%s)", l4Match)
}

func getV4ClusterSubnetsExclusion() string {
	var exclusions []string
	for _, clusterSubnet := range config.Default.ClusterSubnets {
		if utilnet.IsIPv4CIDR(clusterSubnet.CIDR) {
			exclusions = append(exclusions, fmt.Sprintf("%s.dst != %s", "ip4", clusterSubnet.CIDR))
		}
	}
	return strings.Join(exclusions, "&&")
}

func getV6ClusterSubnetsExclusion() string {
	var exclusions []string
	for _, clusterSubnet := range config.Default.ClusterSubnets {
		if utilnet.IsIPv6CIDR(clusterSubnet.CIDR) {
			exclusions = append(exclusions, fmt.Sprintf("%s.dst != %s", "ip6", clusterSubnet.CIDR))
		}
	}
	return strings.Join(exclusions, "&&")
}

func getEgressFirewallNamespacedName(egressFirewall *egressfirewallapi.EgressFirewall) string {
	return fmt.Sprintf("%v/%v", egressFirewall.Namespace, egressFirewall.Name)
}
