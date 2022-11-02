package ovn

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	ovsdb "github.com/ovn-org/libovsdb/ovsdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/metrics"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	kapi "k8s.io/api/core/v1"
	knet "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	kerrorsutil "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

const (
	// defaultDenyPolicyTypeACLExtIdKey external ID key for default deny policy type
	defaultDenyPolicyTypeACLExtIdKey = "default-deny-policy-type"
	// l4MatchACLExtIdKey external ID key for L4 Match on 'gress policy ACLs
	l4MatchACLExtIdKey = "l4Match"
	// ipBlockCIDRACLExtIdKey external ID key for IP block CIDR on 'gress policy ACLs
	ipBlockCIDRACLExtIdKey = "ipblock_cidr"
	// namespaceACLExtIdKey external ID key for namespace on 'gress policy ACLs
	namespaceACLExtIdKey = "namespace"
	// policyACLExtIdKey external ID key for policy name on 'gress policy ACLs
	policyACLExtIdKey = "policy"
	// policyACLExtKey external ID key for policy type on 'gress policy ACLs
	policyTypeACLExtIdKey = "policy_type"
	// policyTypeNumACLExtIdKey external ID key for policy index by type on 'gress policy ACLs
	policyTypeNumACLExtIdKey = "%s_num"
	// ingressDefaultDenySuffix is the suffix used when creating the ingress port group for a namespace
	ingressDefaultDenySuffix = "ingressDefaultDeny"
	// egressDefaultDenySuffix is the suffix used when creating the ingress port group for a namespace
	egressDefaultDenySuffix = "egressDefaultDeny"
	// arpAllowPolicySuffix is the suffix used when creating default ACLs for a namespace
	arpAllowPolicySuffix = "ARPallowPolicy"
	// arpAllowPolicyMatch is the match used when creating default allow ARP ACLs for a namespace
	arpAllowPolicyMatch = "(arp || nd)"
	// staleArpAllowPolicyMatch "was" the old match used when creating default allow ARP ACLs for a namespace
	// NOTE: This is succeed by arpAllowPolicyMatch to allow support for IPV6. This is currently only
	// used when removing stale ACLs from the syncNetworkPolicy function and should NOT be used in any main logic.
	staleArpAllowPolicyMatch = "arp"
)

type networkPolicy struct {
	// RWMutex synchronizes operations on the policy.
	// Operations that change local and peer pods take a RLock,
	// whereas operations that affect the policy take a Lock.
	sync.RWMutex
	name            string
	namespace       string
	policy          *knet.NetworkPolicy
	ingressPolicies []*gressPolicy
	egressPolicies  []*gressPolicy
	podHandlerList  []*factory.Handler
	svcHandlerList  []*factory.Handler
	nsHandlerList   []*factory.Handler

	// localPods is a list of pods affected by this policy
	// this is a sync map so we can handle multiple pods at once
	// map of string -> *lpInfo
	localPods sync.Map

	portGroupName string
	deleted       bool //deleted policy
}

func NewNetworkPolicy(policy *knet.NetworkPolicy) *networkPolicy {
	np := &networkPolicy{
		name:            policy.Name,
		namespace:       policy.Namespace,
		policy:          policy,
		ingressPolicies: make([]*gressPolicy, 0),
		egressPolicies:  make([]*gressPolicy, 0),
		podHandlerList:  make([]*factory.Handler, 0),
		svcHandlerList:  make([]*factory.Handler, 0),
		nsHandlerList:   make([]*factory.Handler, 0),
		localPods:       sync.Map{},
	}
	return np
}

const (
	noneMatch = "None"
	// IPv6 multicast traffic destined to dynamic groups must have the "T" bit
	// set to 1: https://tools.ietf.org/html/rfc3307#section-4.3
	ipv6DynamicMulticastMatch = "(ip6.dst[120..127] == 0xff && ip6.dst[116] == 1)"
	// Legacy multicastDefaultDeny port group removed by commit 40a90f0
	legacyMulticastDefaultDenyPortGroup = "mcastPortGroupDeny"
)

// hash the provided input to make it a valid portGroup name.
func hashedPortGroup(s string) string {
	return util.HashForOVN(s)
}

// updateStaleDefaultDenyACLNames updates the naming of the default ingress and egress deny ACLs per namespace
// oldName: <namespace>_<policyname> (lucky winner will be first policy created in the namespace)
// newName: <namespace>_egressDefaultDeny OR <namespace>_ingressDefaultDeny
func (oc *Controller) updateStaleDefaultDenyACLNames(npType knet.PolicyType, gressSuffix string) error {
	cleanUpDefaultDeny := make(map[string][]*nbdb.ACL)
	p := func(item *nbdb.ACL) bool {
		if item.Name != nil { // we don't care about node ACLs
			aclNameSuffix := strings.Split(*item.Name, "_")
			if len(aclNameSuffix) == 1 {
				// doesn't have suffix; no update required; append the actual suffix since this ACL can be skipped
				aclNameSuffix = append(aclNameSuffix, gressSuffix)
			}
			return item.ExternalIDs[defaultDenyPolicyTypeACLExtIdKey] == string(npType) && // default-deny-policy-type:Egress or default-deny-policy-type:Ingress
				strings.Contains(item.Match, gressSuffix) && // Match:inport ==	@ablah80448_egressDefaultDeny or Match:inport == @ablah80448_ingressDefaultDeny
				!strings.Contains(item.Match, arpAllowPolicyMatch) && // != match: (arp || nd)
				!strings.HasPrefix(gressSuffix, aclNameSuffix[1]) // filter out already converted ACLs or ones that are a no-op
		}
		return false
	}
	gressACLs, err := libovsdbops.FindACLsWithPredicate(oc.nbClient, p)
	if err != nil {
		return fmt.Errorf("cannot find NetworkPolicy default deny ACLs: %v", err)
	}
	for _, acl := range gressACLs {
		acl := acl
		// parse the namespace.Name from the ACL name (if ACL name is 63 chars, then it will fully be namespace.Name)
		namespace := strings.Split(*acl.Name, "_")[0]
		cleanUpDefaultDeny[namespace] = append(cleanUpDefaultDeny[namespace], acl)
	}
	// loop through the cleanUp map and per namespace update the first ACL's name and delete the rest
	for namespace, aclList := range cleanUpDefaultDeny {
		newName := namespacePortGroupACLName(namespace, "", gressSuffix)
		if len(aclList) > 1 {
			// this should never be the case but delete everything except 1st ACL
			ingressPGName := defaultDenyPortGroup(namespace, ingressDefaultDenySuffix)
			egressPGName := defaultDenyPortGroup(namespace, egressDefaultDenySuffix)
			err := libovsdbops.DeleteACLs(oc.nbClient, []string{ingressPGName, egressPGName}, nil, aclList[1:]...)
			if err != nil {
				return err
			}
		}
		newACL := BuildACL(
			newName, // this is the only thing we need to change, keep the rest same
			aclList[0].Direction,
			aclList[0].Priority,
			aclList[0].Match,
			aclList[0].Action,
			oc.GetNamespaceACLLogging(namespace),
			aclList[0].ExternalIDs,
			aclList[0].Options,
		)
		newACL.UUID = aclList[0].UUID // for performance
		err := libovsdbops.CreateOrUpdateACLs(oc.nbClient, newACL)
		if err != nil {
			return fmt.Errorf("cannot update old NetworkPolicy ACLs for namespace %s: %v", namespace, err)
		}
	}
	return nil
}

func (oc *Controller) syncNetworkPolicies(networkPolicies []interface{}) error {
	expectedPolicies := make(map[string]map[string]bool)
	for _, npInterface := range networkPolicies {
		policy, ok := npInterface.(*knet.NetworkPolicy)
		if !ok {
			return fmt.Errorf("spurious object in syncNetworkPolicies: %v", npInterface)
		}

		if nsMap, ok := expectedPolicies[policy.Namespace]; ok {
			nsMap[policy.Name] = true
		} else {
			expectedPolicies[policy.Namespace] = map[string]bool{
				policy.Name: true,
			}
		}
	}

	stalePGs := []string{}
	err := oc.addressSetFactory.ProcessEachAddressSet(func(addrSetName, namespaceName, policyName string) error {
		if policyName != "" && !expectedPolicies[namespaceName][policyName] {
			// policy doesn't exist on k8s. Delete the port group
			portGroupName := fmt.Sprintf("%s_%s", namespaceName, policyName)
			hashedLocalPortGroup := hashedPortGroup(portGroupName)
			stalePGs = append(stalePGs, hashedLocalPortGroup)
			// delete the address sets for this old policy from OVN
			if err := oc.addressSetFactory.DestroyAddressSetInBackingStore(addrSetName); err != nil {
				klog.Errorf(err.Error())
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("error in syncing network policies: %v", err)
	}

	if len(stalePGs) > 0 {
		err = libovsdbops.DeletePortGroups(oc.nbClient, stalePGs...)
		if err != nil {
			return fmt.Errorf("error removing stale port groups %v: %v", stalePGs, err)
		}
	}

	// Update existing egress network policies to use the updated ACLs
	// Note that the default multicast egress acls were created with the correct direction, but
	// we'd still need to update its apply-after-lb=true option, so that the ACL priorities can apply properly;
	// If acl's option["apply-after-lb"] is already set to true, then its direction should be also correct.
	p := func(item *nbdb.ACL) bool {
		return (item.ExternalIDs[policyTypeACLExtIdKey] == string(knet.PolicyTypeEgress) ||
			item.ExternalIDs[defaultDenyPolicyTypeACLExtIdKey] == string(knet.PolicyTypeEgress)) &&
			item.Options["apply-after-lb"] != "true"
	}
	egressACLs, err := libovsdbops.FindACLsWithPredicate(oc.nbClient, p)
	if err != nil {
		return fmt.Errorf("cannot find NetworkPolicy Egress ACLs: %v", err)
	}

	if len(egressACLs) > 0 {
		for _, acl := range egressACLs {
			acl.Direction = nbdb.ACLDirectionFromLport
			if acl.Options == nil {
				acl.Options = map[string]string{"apply-after-lb": "true"}
			} else {
				acl.Options["apply-after-lb"] = "true"
			}
		}
		ops, err := libovsdbops.CreateOrUpdateACLsOps(oc.nbClient, nil, egressACLs...)
		if err != nil {
			return fmt.Errorf("cannot create ops to update old Egress NetworkPolicy ACLs: %v", err)
		}
		_, err = libovsdbops.TransactAndCheck(oc.nbClient, ops)
		if err != nil {
			return fmt.Errorf("cannot update old Egress NetworkPolicy ACLs: %v", err)
		}
	}

	// remove stale egress and ingress allow arp ACLs that were leftover as a result
	// of ACL migration for "ARPallowPolicy" when the match changed from "arp" to "(arp || nd)"
	p = func(item *nbdb.ACL) bool {
		return strings.Contains(item.Match, " && "+staleArpAllowPolicyMatch) &&
			// default-deny-policy-type:Egress or default-deny-policy-type:Ingress
			(item.ExternalIDs[defaultDenyPolicyTypeACLExtIdKey] == string(knet.PolicyTypeEgress) ||
				item.ExternalIDs[defaultDenyPolicyTypeACLExtIdKey] == string(knet.PolicyTypeIngress))
	}
	gressACLs, err := libovsdbops.FindACLsWithPredicate(oc.nbClient, p)
	if err != nil {
		return fmt.Errorf("cannot find stale arp allow ACLs: %v", err)
	}
	// Remove these stale ACLs from port groups and then delete them
	var ops []ovsdb.Operation
	for _, gressACL := range gressACLs {
		gressACL := gressACL
		pgName := ""
		if strings.Contains(gressACL.Match, "inport") {
			// egress default ARP allow policy ("inport == @a16323395479447859119_egressDefaultDeny && arp")
			pgName = strings.TrimPrefix(gressACL.Match, "inport == @")
		} else if strings.Contains(gressACL.Match, "outport") {
			// ingress default ARP allow policy ("outport == @a16323395479447859119_ingressDefaultDeny && arp")
			pgName = strings.TrimPrefix(gressACL.Match, "outport == @")
		}
		pgName = strings.TrimSuffix(pgName, " && "+staleArpAllowPolicyMatch)
		ops, err = libovsdbops.DeleteACLsOps(oc.nbClient, ops, []string{pgName}, nil, gressACL)
		if err != nil {
			return fmt.Errorf("failed getting delete acl ops: %v", err)
		}
	}
	_, err = libovsdbops.TransactAndCheck(oc.nbClient, ops)
	if err != nil {
		return fmt.Errorf("cannot delete stale arp allow ACLs: %v", err)
	}

	if err := oc.updateStaleDefaultDenyACLNames(knet.PolicyTypeEgress, egressDefaultDenySuffix); err != nil {
		return fmt.Errorf("cannot clean up egress default deny ACL name: %v", err)
	}
	if err := oc.updateStaleDefaultDenyACLNames(knet.PolicyTypeIngress, ingressDefaultDenySuffix); err != nil {
		return fmt.Errorf("cannot clean up ingress default deny ACL name: %v", err)
	}

	return nil
}

func addAllowACLFromNode(nodeName string, mgmtPortIP net.IP, nbClient libovsdbclient.Client) error {
	ipFamily := "ip4"
	if utilnet.IsIPv6(mgmtPortIP) {
		ipFamily = "ip6"
	}
	match := fmt.Sprintf("%s.src==%s", ipFamily, mgmtPortIP.String())

	nodeACL := BuildACL("", nbdb.ACLDirectionToLport, types.DefaultAllowPriority, match, "allow-related", nil, nil, nil)

	ops, err := libovsdbops.CreateOrUpdateACLsOps(nbClient, nil, nodeACL)
	if err != nil {
		return fmt.Errorf("failed to create or update ACL %v: %v", nodeACL, err)
	}

	ops, err = libovsdbops.AddACLsToLogicalSwitchOps(nbClient, ops, nodeName, nodeACL)
	if err != nil {
		return fmt.Errorf("failed to add ACL %v to switch %s: %v", nodeACL, nodeName, err)
	}

	_, err = libovsdbops.TransactAndCheck(nbClient, ops)
	if err != nil {
		return err
	}

	return nil
}

func getACLMatch(portGroupName, match string, policyType knet.PolicyType) string {
	var aclMatch string
	if policyType == knet.PolicyTypeIngress {
		aclMatch = "outport == @" + portGroupName
	} else {
		aclMatch = "inport == @" + portGroupName
	}

	if match != "" {
		aclMatch += " && " + match
	}

	return aclMatch
}

func namespacePortGroupACLName(namespace, portGroup, name string) string {
	policyNamespace := namespace
	if policyNamespace == "" {
		policyNamespace = portGroup
	}
	if name == "" {
		return policyNamespace

	}
	return fmt.Sprintf("%s_%s", policyNamespace, name)
}

func buildACL(namespace, portGroup, name, direction string, priority int, match, action string,
	logLevels *ACLLoggingLevels, policyType knet.PolicyType) *nbdb.ACL {
	var options map[string]string
	aclName := namespacePortGroupACLName(namespace, portGroup, name)
	var externalIds map[string]string
	if policyType != "" {
		externalIds = map[string]string{
			defaultDenyPolicyTypeACLExtIdKey: string(policyType),
		}
	}
	if policyType == knet.PolicyTypeEgress {
		options = map[string]string{
			"apply-after-lb": "true",
		}
	}

	return BuildACL(aclName, direction, priority, match, action, logLevels, externalIds, options)
}

func defaultDenyPortGroup(namespace, gressSuffix string) string {
	return hashedPortGroup(namespace) + "_" + gressSuffix
}

func buildDenyACLs(namespace, policy, pg string, aclLogging *ACLLoggingLevels, policyType knet.PolicyType) (denyACL, allowACL *nbdb.ACL) {
	denyMatch := getACLMatch(pg, "", policyType)
	allowMatch := getACLMatch(pg, arpAllowPolicyMatch, policyType)
	if policyType == knet.PolicyTypeIngress {
		denyACL = buildACL(namespace, pg, ingressDefaultDenySuffix, nbdb.ACLDirectionToLport,
			types.DefaultDenyPriority, denyMatch, nbdb.ACLActionDrop, aclLogging, policyType)
		allowACL = buildACL(namespace, pg, arpAllowPolicySuffix, nbdb.ACLDirectionToLport,
			types.DefaultAllowPriority, allowMatch, nbdb.ACLActionAllow, nil, policyType)
	} else {
		denyACL = buildACL(namespace, pg, egressDefaultDenySuffix, nbdb.ACLDirectionFromLport,
			types.DefaultDenyPriority, denyMatch, nbdb.ACLActionDrop, aclLogging, policyType)
		allowACL = buildACL(namespace, pg, arpAllowPolicySuffix, nbdb.ACLDirectionFromLport,
			types.DefaultAllowPriority, allowMatch, nbdb.ACLActionAllow, nil, policyType)
	}
	return
}

// must be called with a write lock on nsInfo
func (oc *Controller) createDefaultDenyPGAndACLs(namespace, policy string, nsInfo *namespaceInfo) error {
	aclLogging := nsInfo.aclLogging

	ingressPGName := defaultDenyPortGroup(namespace, ingressDefaultDenySuffix)
	ingressDenyACL, ingressAllowACL := buildDenyACLs(namespace, policy, ingressPGName, &aclLogging, knet.PolicyTypeIngress)
	egressPGName := defaultDenyPortGroup(namespace, egressDefaultDenySuffix)
	egressDenyACL, egressAllowACL := buildDenyACLs(namespace, policy, egressPGName, &aclLogging, knet.PolicyTypeEgress)
	ops, err := libovsdbops.CreateOrUpdateACLsOps(oc.nbClient, nil, ingressDenyACL, ingressAllowACL, egressDenyACL, egressAllowACL)
	if err != nil {
		return err
	}

	ingressPG := libovsdbops.BuildPortGroup(ingressPGName, ingressPGName, nil, []*nbdb.ACL{ingressDenyACL, ingressAllowACL})
	egressPG := libovsdbops.BuildPortGroup(egressPGName, egressPGName, nil, []*nbdb.ACL{egressDenyACL, egressAllowACL})
	ops, err = libovsdbops.CreateOrUpdatePortGroupsOps(oc.nbClient, ops, ingressPG, egressPG)
	if err != nil {
		return err
	}

	recordOps, txOkCallBack, _, err := metrics.GetConfigDurationRecorder().AddOVN(oc.nbClient, "networkpolicy",
		namespace, policy)
	if err != nil {
		klog.Errorf("Failed to record config duration: %v", err)
	}
	ops = append(ops, recordOps...)
	_, err = libovsdbops.TransactAndCheck(oc.nbClient, ops)
	if err != nil {
		return err
	}
	txOkCallBack()

	nsInfo.portGroupEgressDenyName = egressPGName
	nsInfo.portGroupIngressDenyName = ingressPGName

	return nil
}

// deleteDefaultDenyPGAndACLs deletes the default port groups and acls for a ns/policy
// must be called with a write lock on nsInfo
func (oc *Controller) deleteDefaultDenyPGAndACLs(namespace, policy string, nsInfo *namespaceInfo) error {
	aclLogging := nsInfo.aclLogging
	var aclsToBeDeleted []*nbdb.ACL

	ingressPGName := defaultDenyPortGroup(namespace, ingressDefaultDenySuffix)
	ingressDenyACL, ingressAllowACL := buildDenyACLs(namespace, policy, ingressPGName, &aclLogging, knet.PolicyTypeIngress)
	aclsToBeDeleted = append(aclsToBeDeleted, ingressDenyACL, ingressAllowACL)
	egressPGName := defaultDenyPortGroup(namespace, egressDefaultDenySuffix)
	egressDenyACL, egressAllowACL := buildDenyACLs(namespace, policy, egressPGName, &aclLogging, knet.PolicyTypeEgress)
	aclsToBeDeleted = append(aclsToBeDeleted, egressDenyACL, egressAllowACL)

	ops, err := libovsdbops.DeletePortGroupsOps(oc.nbClient, nil, ingressPGName, egressPGName)
	if err != nil {
		return err
	}
	// Manually remove the default ACLs instead of relying on ovsdb garbage collection to do so
	// don't delete ACL references because port group is completely deleted in the same tnx
	ops, err = libovsdbops.DeleteACLsOps(oc.nbClient, ops, nil, nil, aclsToBeDeleted...)
	if err != nil {
		return err
	}
	_, err = libovsdbops.TransactAndCheck(oc.nbClient, ops)
	if err != nil {
		return fmt.Errorf("failed to transact deleteDefaultDenyPGAndACLs: %v", err)
	}
	nsInfo.portGroupEgressDenyName = ""
	nsInfo.portGroupIngressDenyName = ""

	return nil
}

func (oc *Controller) updateACLLoggingForPolicy(np *networkPolicy, aclLogging *ACLLoggingLevels) error {
	np.Lock()
	defer np.Unlock()

	if np.deleted {
		return nil
	}

	// Predicate for given network policy ACLs
	p := func(item *nbdb.ACL) bool {
		return item.ExternalIDs[namespaceACLExtIdKey] == np.namespace && item.ExternalIDs[policyACLExtIdKey] == np.name
	}
	return UpdateACLLoggingWithPredicate(oc.nbClient, p, aclLogging)
}

func (oc *Controller) updateACLLoggingForDefaultACLs(ns string, nsInfo *namespaceInfo) error {
	// update namespace-scoped default deny ACLs
	denyEgressACL, _ := buildDenyACLs(ns, "", defaultDenyPortGroup(ns, egressDefaultDenySuffix),
		&nsInfo.aclLogging, knet.PolicyTypeEgress)
	denyIngressACL, _ := buildDenyACLs(ns, "", defaultDenyPortGroup(ns, ingressDefaultDenySuffix),
		&nsInfo.aclLogging, knet.PolicyTypeIngress)
	if err := UpdateACLLogging(oc.nbClient, []*nbdb.ACL{denyIngressACL, denyEgressACL}, &nsInfo.aclLogging); err != nil {
		return fmt.Errorf("unable to update ACL logging for namespace %s: %w", ns, err)
	}
	return nil
}

func (oc *Controller) setNetworkPolicyACLLoggingForNamespace(ns string, nsInfo *namespaceInfo) error {
	if err := oc.updateACLLoggingForDefaultACLs(ns, nsInfo); err != nil {
		return err
	}

	// now update network policy specific ACLs
	klog.V(5).Infof("Setting network policy ACLs for ns: %s", ns)
	for name, policy := range nsInfo.networkPolicies {
		if err := oc.updateACLLoggingForPolicy(policy, &nsInfo.aclLogging); err != nil {
			return fmt.Errorf("unable to update ACL for network policy: %v", err)
		}
		klog.Infof("ACL for network policy: %s, updated to new log level: %s", name, nsInfo.aclLogging.Allow)
	}
	return nil
}

func getACLMatchAF(ipv4Match, ipv6Match string) string {
	if config.IPv4Mode && config.IPv6Mode {
		return "(" + ipv4Match + " || " + ipv6Match + ")"
	} else if config.IPv4Mode {
		return ipv4Match
	} else {
		return ipv6Match
	}
}

// Creates the match string used for ACLs matching on multicast traffic.
func getMulticastACLMatch() string {
	return "(ip4.mcast || mldv1 || mldv2 || " + ipv6DynamicMulticastMatch + ")"
}

// Allow IGMP traffic (e.g., IGMP queries) and namespace multicast traffic
// towards pods.
func getMulticastACLIgrMatchV4(addrSetName string) string {
	return "(igmp || (ip4.src == $" + addrSetName + " && ip4.mcast))"
}

// Allow MLD traffic (e.g., MLD queries) and namespace multicast traffic
// towards pods.
func getMulticastACLIgrMatchV6(addrSetName string) string {
	return "(mldv1 || mldv2 || (ip6.src == $" + addrSetName + " && " + ipv6DynamicMulticastMatch + "))"
}

// Creates the match string used for ACLs allowing incoming multicast into a
// namespace, that is, from IPs that are in the namespace's address set.
func getMulticastACLIgrMatch(nsInfo *namespaceInfo) string {
	var ipv4Match, ipv6Match string
	addrSetNameV4, addrSetNameV6 := nsInfo.addressSet.GetASHashNames()
	if config.IPv4Mode {
		ipv4Match = getMulticastACLIgrMatchV4(addrSetNameV4)
	}
	if config.IPv6Mode {
		ipv6Match = getMulticastACLIgrMatchV6(addrSetNameV6)
	}
	return getACLMatchAF(ipv4Match, ipv6Match)
}

// Creates the match string used for ACLs allowing outgoing multicast from a
// namespace.
func getMulticastACLEgrMatch() string {
	var ipv4Match, ipv6Match string
	if config.IPv4Mode {
		ipv4Match = "ip4.mcast"
	}
	if config.IPv6Mode {
		ipv6Match = "(mldv1 || mldv2 || " + ipv6DynamicMulticastMatch + ")"
	}
	return getACLMatchAF(ipv4Match, ipv6Match)
}

// Creates a policy to allow multicast traffic within 'ns':
// - a port group containing all logical ports associated with 'ns'
// - one "from-lport" ACL allowing egress multicast traffic from the pods
//   in 'ns'
// - one "to-lport" ACL allowing ingress multicast traffic to pods in 'ns'.
//   This matches only traffic originated by pods in 'ns' (based on the
//   namespace address set).
func (oc *Controller) createMulticastAllowPolicy(ns string, nsInfo *namespaceInfo) error {
	portGroupName := hashedPortGroup(ns)

	egressMatch := getACLMatch(portGroupName, getMulticastACLEgrMatch(), knet.PolicyTypeEgress)
	egressACL := buildACL(ns, portGroupName, "MulticastAllowEgress", nbdb.ACLDirectionFromLport,
		types.DefaultMcastAllowPriority, egressMatch, nbdb.ACLActionAllow, nil, knet.PolicyTypeEgress)
	ingressMatch := getACLMatch(portGroupName, getMulticastACLIgrMatch(nsInfo), knet.PolicyTypeIngress)
	ingressACL := buildACL(ns, portGroupName, "MulticastAllowIngress", nbdb.ACLDirectionToLport,
		types.DefaultMcastAllowPriority, ingressMatch, nbdb.ACLActionAllow, nil, knet.PolicyTypeIngress)
	acls := []*nbdb.ACL{egressACL, ingressACL}
	ops, err := libovsdbops.CreateOrUpdateACLsOps(oc.nbClient, nil, acls...)
	if err != nil {
		return err
	}

	// Add all ports from this namespace to the multicast allow group.
	ports := []*nbdb.LogicalSwitchPort{}
	pods, err := oc.watchFactory.GetPods(ns)
	if err != nil {
		klog.Warningf("Failed to get pods for namespace %q: %v", ns, err)
	}
	for _, pod := range pods {
		if util.PodCompleted(pod) {
			continue
		}
		portName := util.GetLogicalPortName(pod.Namespace, pod.Name)
		if portInfo, err := oc.logicalPortCache.get(portName); err != nil {
			klog.Errorf(err.Error())
		} else {
			ports = append(ports, &nbdb.LogicalSwitchPort{UUID: portInfo.uuid})
		}
	}

	pg := libovsdbops.BuildPortGroup(portGroupName, ns, ports, acls)
	ops, err = libovsdbops.CreateOrUpdatePortGroupsOps(oc.nbClient, ops, pg)
	if err != nil {
		return err
	}

	_, err = libovsdbops.TransactAndCheck(oc.nbClient, ops)
	if err != nil {
		return err
	}

	return nil
}

func deleteMulticastAllowPolicy(nbClient libovsdbclient.Client, ns string) error {
	portGroupName := hashedPortGroup(ns)
	// ACLs referenced by the port group wil be deleted by db if there are no other references
	err := libovsdbops.DeletePortGroups(nbClient, portGroupName)
	if err != nil {
		return fmt.Errorf("failed deleting port group %s: %v", portGroupName, err)
	}

	return nil
}

// Creates a global default deny multicast policy:
// - one ACL dropping egress multicast traffic from all pods: this is to
//   protect OVN controller from processing IP multicast reports from nodes
//   that are not allowed to receive multicast traffic.
// - one ACL dropping ingress multicast traffic to all pods.
// Caller must hold the namespace's namespaceInfo object lock.
func (oc *Controller) createDefaultDenyMulticastPolicy() error {
	match := getMulticastACLMatch()

	// By default deny any egress multicast traffic from any pod. This drops
	// IP multicast membership reports therefore denying any multicast traffic
	// to be forwarded to pods.
	egressACL := buildACL("", types.ClusterPortGroupName, "DefaultDenyMulticastEgress",
		nbdb.ACLDirectionFromLport, types.DefaultMcastDenyPriority, match, nbdb.ACLActionDrop, nil,
		knet.PolicyTypeEgress)

	// By default deny any ingress multicast traffic to any pod.
	ingressACL := buildACL("", types.ClusterPortGroupName, "DefaultDenyMulticastIngress",
		nbdb.ACLDirectionToLport, types.DefaultMcastDenyPriority, match, nbdb.ACLActionDrop, nil,
		knet.PolicyTypeIngress)

	ops, err := libovsdbops.CreateOrUpdateACLsOps(oc.nbClient, nil, egressACL, ingressACL)
	if err != nil {
		return err
	}

	ops, err = libovsdbops.AddACLsToPortGroupOps(oc.nbClient, ops, types.ClusterPortGroupName, egressACL, ingressACL)
	if err != nil {
		return err
	}

	// Remove old multicastDefaultDeny port group now that all ports
	// have been added to the clusterPortGroup by WatchPods()
	ops, err = libovsdbops.DeletePortGroupsOps(oc.nbClient, ops, legacyMulticastDefaultDenyPortGroup)
	if err != nil {
		return err
	}

	_, err = libovsdbops.TransactAndCheck(oc.nbClient, ops)
	if err != nil {
		return err
	}

	return nil
}

// Creates a global default allow multicast policy:
// - one ACL allowing multicast traffic from cluster router ports
// - one ACL allowing multicast traffic to cluster router ports.
// Caller must hold the namespace's namespaceInfo object lock.
func (oc *Controller) createDefaultAllowMulticastPolicy() error {
	mcastMatch := getMulticastACLMatch()

	egressMatch := getACLMatch(types.ClusterRtrPortGroupName, mcastMatch, knet.PolicyTypeEgress)
	egressACL := buildACL("", types.ClusterRtrPortGroupName, "DefaultAllowMulticastEgress",
		nbdb.ACLDirectionFromLport, types.DefaultMcastAllowPriority, egressMatch, nbdb.ACLActionAllow, nil,
		knet.PolicyTypeEgress)

	ingressMatch := getACLMatch(types.ClusterRtrPortGroupName, mcastMatch, knet.PolicyTypeIngress)
	ingressACL := buildACL("", types.ClusterRtrPortGroupName, "DefaultAllowMulticastIngress",
		nbdb.ACLDirectionToLport, types.DefaultMcastAllowPriority, ingressMatch, nbdb.ACLActionAllow, nil,
		knet.PolicyTypeIngress)

	ops, err := libovsdbops.CreateOrUpdateACLsOps(oc.nbClient, nil, egressACL, ingressACL)
	if err != nil {
		return err
	}

	ops, err = libovsdbops.AddACLsToPortGroupOps(oc.nbClient, ops, types.ClusterRtrPortGroupName, egressACL, ingressACL)
	if err != nil {
		return err
	}

	_, err = libovsdbops.TransactAndCheck(oc.nbClient, ops)
	if err != nil {
		return err
	}

	return nil
}

// podAddAllowMulticastPolicy adds the pod's logical switch port to the namespace's
// multicast port group. Caller must hold the namespace's namespaceInfo object
// lock.
func podAddAllowMulticastPolicy(nbClient libovsdbclient.Client, ns string, portInfo *lpInfo) error {
	return libovsdbops.AddPortsToPortGroup(nbClient, hashedPortGroup(ns), portInfo.uuid)
}

// podDeleteAllowMulticastPolicy removes the pod's logical switch port from the
// namespace's multicast port group. Caller must hold the namespace's
// namespaceInfo object lock.
func podDeleteAllowMulticastPolicy(nbClient libovsdbclient.Client, ns string, portUUID string) error {
	return libovsdbops.DeletePortsFromPortGroup(nbClient, hashedPortGroup(ns), portUUID)
}

// policyType returns whether the policy is of type ingress and/or egress
func policyType(policy *knet.NetworkPolicy) (bool, bool) {
	var policyTypeIngress bool
	var policyTypeEgress bool

	for _, policyType := range policy.Spec.PolicyTypes {
		if policyType == knet.PolicyTypeIngress {
			policyTypeIngress = true
		} else if policyType == knet.PolicyTypeEgress {
			policyTypeEgress = true
		}
	}

	return policyTypeIngress, policyTypeEgress
}

// localPodAddDefaultDeny ensures ports (i.e. pods) are in the correct
// default-deny portgroups. Whether or not pods are in default-deny depends
// on whether or not any policies select this pod, so there is a reference
// count to ensure we don't accidentally open up a pod.
func (oc *Controller) localPodAddDefaultDeny(policy *knet.NetworkPolicy,
	ports ...*lpInfo) (ingressDenyPorts, egressDenyPorts []string) {
	oc.lspMutex.Lock()

	ingressDenyPorts = []string{}
	egressDenyPorts = []string{}

	policyTypeIngress, policyTypeEgress := policyType(policy)

	if policyTypeIngress {
		for _, portInfo := range ports {
			// if this is the first NP referencing this pod, then we
			// need to add it to the port group.
			if oc.lspIngressDenyCache[portInfo.name] == 0 {
				ingressDenyPorts = append(ingressDenyPorts, portInfo.uuid)
			}

			// increment the reference count.
			oc.lspIngressDenyCache[portInfo.name]++
		}
	}

	// Handle condition 2 above.
	if policyTypeEgress {
		for _, portInfo := range ports {
			if oc.lspEgressDenyCache[portInfo.name] == 0 {
				// again, reference count is 0, so add to port
				egressDenyPorts = append(egressDenyPorts, portInfo.uuid)
			}

			// bump reference count
			oc.lspEgressDenyCache[portInfo.name]++
		}
	}
	oc.lspMutex.Unlock()

	return
}

// localPodDelDefaultDeny decrements a pod's policy reference count and removes a pod
// from the default-deny portgroups if the reference count for the pod is 0
func (oc *Controller) localPodDelDefaultDeny(
	np *networkPolicy, ports ...*lpInfo) (ingressDenyPorts, egressDenyPorts []string) {
	oc.lspMutex.Lock()

	ingressDenyPorts = []string{}
	egressDenyPorts = []string{}

	policyTypeIngress, policyTypeEgress := policyType(np.policy)

	// Remove port from ingress deny port-group for [Ingress] and [ingress,egress] PolicyTypes
	// If NOT [egress] PolicyType
	if policyTypeIngress {
		for _, portInfo := range ports {
			if oc.lspIngressDenyCache[portInfo.name] > 0 {
				oc.lspIngressDenyCache[portInfo.name]--
				if oc.lspIngressDenyCache[portInfo.name] == 0 {
					ingressDenyPorts = append(ingressDenyPorts, portInfo.uuid)
					delete(oc.lspIngressDenyCache, portInfo.name)
				}
			}
		}
	}

	// Remove port from egress deny port group for [egress] and [ingress,egress] PolicyTypes
	// if [egress] PolicyType OR there are any egress rules OR [ingress,egress] PolicyType
	if policyTypeEgress {
		for _, portInfo := range ports {
			if oc.lspEgressDenyCache[portInfo.name] > 0 {
				oc.lspEgressDenyCache[portInfo.name]--
				if oc.lspEgressDenyCache[portInfo.name] == 0 {
					egressDenyPorts = append(egressDenyPorts, portInfo.uuid)
					delete(oc.lspEgressDenyCache, portInfo.name)
				}
			}
		}
	}
	oc.lspMutex.Unlock()

	return
}

func (oc *Controller) processLocalPodSelectorSetPods(policy *knet.NetworkPolicy,
	np *networkPolicy, objs ...interface{}) (policyPorts, ingressDenyPorts, egressDenyPorts []string) {
	klog.Infof("Processing NetworkPolicy %s/%s to have %d local pods...", np.namespace, np.name, len(objs))

	// get list of pods and their logical ports to add
	// theoretically this should never filter any pods but it's always good to be
	// paranoid.
	policyPorts = make([]string, 0, len(objs))
	policyPortsInfo := make([]*lpInfo, 0, len(objs))

	// thread safe helper vars used by the `getPortInfo` go-routine
	getPortsInfoMap := sync.Map{}
	getPolicyPortsWg := &sync.WaitGroup{}

	getPortInfo := func(pod *kapi.Pod) {
		defer getPolicyPortsWg.Done()

		if pod.Spec.NodeName == "" {
			return
		}

		logicalPort := util.GetLogicalPortName(pod.Namespace, pod.Name)
		var portInfo *lpInfo

		// Get the logical port info from the cache, if that fails, retry.
		// If the gotten LSP is scheduled for removal, retry (stateful-sets).
		//
		// 24ms is chosen because gomega.Eventually default timeout is 50ms
		// libovsdb transactions take less than 50ms usually as well so pod create
		// should be done within a couple iterations
		retryErr := wait.PollImmediate(24*time.Millisecond, 1*time.Second, func() (bool, error) {
			var err error

			// Retry if getting pod LSP from the cache fails
			portInfo, err = oc.logicalPortCache.get(logicalPort)
			if err != nil {
				klog.Warningf("Failed to get LSP for pod %s/%s for networkPolicy %s refetching err: %v",
					pod.Namespace, pod.Name, policy.Name, err)
				return false, nil
			}

			// Retry if LSP is scheduled for deletion
			if !portInfo.expires.IsZero() {
				klog.Warningf("Stale LSP %s for network policy %s found in cache refetching",
					portInfo.name, policy.Name)
				return false, nil
			}

			// LSP get succeeded and LSP is up to fresh, exit and continue
			klog.V(5).Infof("Fresh LSP %s for network policy %s found in cache",
				portInfo.name, policy.Name)
			return true, nil

		})
		if retryErr != nil {
			// Failed to get an up to date version of the LSP from the cache
			klog.Warningf("Failed to get LSP after multiple retries for pod %s/%s for networkPolicy %s err: %v",
				pod.Namespace, pod.Name, policy.Name, retryErr)
			return
		}

		// if this pod is somehow already added to this policy, then skip
		if _, ok := np.localPods.LoadOrStore(portInfo.name, portInfo); ok {
			return
		}

		getPortsInfoMap.Store(portInfo.uuid, portInfo)
	}

	for _, obj := range objs {
		pod := obj.(*kapi.Pod)

		if util.PodCompleted(pod) {
			// if pod is completed, do not add it to NP port group
			continue
		}

		getPolicyPortsWg.Add(1)
		go getPortInfo(pod)
	}

	getPolicyPortsWg.Wait()

	// build usable atomic structures from the sync.Map() populated by the getPortInfo threads
	// add to backup policyPorts array
	getPortsInfoMap.Range(func(key interface{}, value interface{}) bool {
		policyPorts = append(policyPorts, key.(string))
		policyPortsInfo = append(policyPortsInfo, value.(*lpInfo))
		return true
	})

	ingressDenyPorts, egressDenyPorts = oc.localPodAddDefaultDeny(policy, policyPortsInfo...)

	return
}

func (oc *Controller) processLocalPodSelectorDelPods(np *networkPolicy,
	objs ...interface{}) (policyPorts, ingressDenyPorts, egressDenyPorts []string) {
	klog.Infof("Processing NetworkPolicy %s/%s to delete %d local pods...", np.namespace, np.name, len(objs))

	policyPorts = make([]string, 0, len(objs))
	policyPortsInfo := make([]*lpInfo, 0, len(objs))
	for _, obj := range objs {
		pod := obj.(*kapi.Pod)

		if pod.Spec.NodeName == "" {
			continue
		}

		logicalPort := util.GetLogicalPortName(pod.Namespace, pod.Name)
		portInfo, err := oc.logicalPortCache.get(logicalPort)
		if err != nil {
			klog.Errorf(err.Error())
			return
		}

		// If we never saw this pod, short-circuit
		if _, ok := np.localPods.LoadAndDelete(logicalPort); !ok {
			continue
		}

		policyPortsInfo = append(policyPortsInfo, portInfo)
		policyPorts = append(policyPorts, portInfo.uuid)
	}

	ingressDenyPorts, egressDenyPorts = oc.localPodDelDefaultDeny(np, policyPortsInfo...)

	return
}

// handleLocalPodSelectorAddFunc adds a new pod to an existing NetworkPolicy
func (oc *Controller) handleLocalPodSelectorAddFunc(policy *knet.NetworkPolicy, np *networkPolicy,
	portGroupIngressDenyName, portGroupEgressDenyName string, obj interface{}) error {
	np.RLock()
	defer np.RUnlock()
	if np.deleted {
		return nil
	}

	policyPorts, ingressDenyPorts, egressDenyPorts := oc.processLocalPodSelectorSetPods(policy, np, obj)

	var errs []error

	ops, err := libovsdbops.AddPortsToPortGroupOps(oc.nbClient, nil, portGroupIngressDenyName, ingressDenyPorts...)
	if err != nil {
		oc.processLocalPodSelectorDelPods(np, obj)
		errs = append(errs, err)
	}

	ops, err = libovsdbops.AddPortsToPortGroupOps(oc.nbClient, ops, portGroupEgressDenyName, egressDenyPorts...)
	if err != nil {
		oc.processLocalPodSelectorDelPods(np, obj)
		errs = append(errs, err)
	}

	ops, err = libovsdbops.AddPortsToPortGroupOps(oc.nbClient, ops, np.portGroupName, policyPorts...)
	if err != nil {
		oc.processLocalPodSelectorDelPods(np, obj)
		errs = append(errs, err)
	}

	_, err = libovsdbops.TransactAndCheck(oc.nbClient, ops)
	if err != nil {
		oc.processLocalPodSelectorDelPods(np, obj)
		errs = append(errs, err)
	}
	return kerrorsutil.NewAggregate(errs)
}

func (oc *Controller) handleLocalPodSelectorDelFunc(policy *knet.NetworkPolicy, np *networkPolicy,
	portGroupIngressDenyName, portGroupEgressDenyName string, obj interface{}) error {
	np.RLock()
	defer np.RUnlock()
	if np.deleted {
		return nil
	}

	policyPorts, ingressDenyPorts, egressDenyPorts := oc.processLocalPodSelectorDelPods(np, obj)

	ops, err := libovsdbops.DeletePortsFromPortGroupOps(oc.nbClient, nil, portGroupIngressDenyName, ingressDenyPorts...)
	if err != nil {
		oc.processLocalPodSelectorSetPods(policy, np, obj)
		return err
	}

	ops, err = libovsdbops.DeletePortsFromPortGroupOps(oc.nbClient, ops, portGroupEgressDenyName, egressDenyPorts...)
	if err != nil {
		oc.processLocalPodSelectorSetPods(policy, np, obj)
		return err
	}

	var errs []error

	ops, err = libovsdbops.DeletePortsFromPortGroupOps(oc.nbClient, ops, np.portGroupName, policyPorts...)
	if err != nil {
		oc.processLocalPodSelectorSetPods(policy, np, obj)
		errs = append(errs, err)
	}

	_, err = libovsdbops.TransactAndCheck(oc.nbClient, ops)
	if err != nil {
		oc.processLocalPodSelectorSetPods(policy, np, obj)
		errs = append(errs, err)
	}

	return kerrorsutil.NewAggregate(errs)
}

func (oc *Controller) addLocalPodHandler(
	policy *knet.NetworkPolicy, np *networkPolicy, portGroupIngressDenyName, portGroupEgressDenyName string,
	handleInitialItems func([]interface{}) error) error {

	// NetworkPolicy is validated by the apiserver
	sel, err := metav1.LabelSelectorAsSelector(&policy.Spec.PodSelector)
	if err != nil {
		klog.Errorf("Could not set up watcher for local pods: %v", err)
		return err
	}

	retryLocalPods := NewRetryObjs(
		factory.LocalPodSelectorType,
		policy.Namespace,
		sel,
		handleInitialItems,
		&NetworkPolicyExtraParameters{
			policy:                   policy,
			np:                       np,
			portGroupIngressDenyName: portGroupIngressDenyName,
			portGroupEgressDenyName:  portGroupEgressDenyName,
		})

	podHandler, err := oc.WatchResource(retryLocalPods)
	if err != nil {
		klog.Errorf("Failed WatchResource for addLocalPodHandler: %v", err)
		return err
	}

	np.Lock()
	defer np.Unlock()
	np.podHandlerList = append(np.podHandlerList, podHandler)
	return nil
}

// we only need to create an address set if there is a podSelector or namespaceSelector
func hasAnyLabelSelector(peers []knet.NetworkPolicyPeer) bool {
	for _, peer := range peers {
		if peer.PodSelector != nil || peer.NamespaceSelector != nil {
			return true
		}
	}
	return false
}

// createNetworkPolicy creates a network policy
func (oc *Controller) createNetworkPolicy(np *networkPolicy, policy *knet.NetworkPolicy, aclLogging *ACLLoggingLevels,
	portGroupIngressDenyName, portGroupEgressDenyName string) error {

	np.Lock()

	if aclLogging.Deny != "" || aclLogging.Allow != "" {
		klog.Infof("ACL logging for network policy %s in namespace %s set to deny=%s, allow=%s",
			policy.Name, policy.Namespace, aclLogging.Deny, aclLogging.Allow)
	}

	type policyHandler struct {
		gress             *gressPolicy
		namespaceSelector *metav1.LabelSelector
		podSelector       *metav1.LabelSelector
	}
	var policyHandlers []policyHandler

	// Consider both ingress and egress rules of the policy regardless of this
	// policy type. A pod is isolated as long as as it is selected by any
	// namespace policy. Since we don't process all namespace policies on a
	// given policy update that might change the isolation status of a selected
	// pod, we have create the allow ACLs derived from the policy rules in case
	// the selected pods become isolated in the future even if that is not their
	// current status.

	// Go through each ingress rule.  For each ingress rule, create an
	// addressSet for the peer pods.
	for i, ingressJSON := range policy.Spec.Ingress {
		klog.V(5).Infof("Network policy ingress is %+v", ingressJSON)

		ingress := newGressPolicy(knet.PolicyTypeIngress, i, policy.Namespace, policy.Name)

		// Each ingress rule can have multiple ports to which we allow traffic.
		for _, portJSON := range ingressJSON.Ports {
			ingress.addPortPolicy(&portJSON)
		}

		if hasAnyLabelSelector(ingressJSON.From) {
			klog.V(5).Infof("Network policy %s with ingress rule %s has a selector", policy.Name, ingress.policyName)
			if err := ingress.ensurePeerAddressSet(oc.addressSetFactory); err != nil {
				np.Unlock()
				return err
			}
			// Start service handlers ONLY if there's an ingress Address Set
			if err := oc.addPeerServiceHandler(policy, ingress, np); err != nil {
				np.Unlock()
				return err
			}
		}

		for _, fromJSON := range ingressJSON.From {
			// Add IPBlock to ingress network policy
			if fromJSON.IPBlock != nil {
				ingress.addIPBlock(fromJSON.IPBlock)
			}

			policyHandlers = append(policyHandlers, policyHandler{
				gress:             ingress,
				namespaceSelector: fromJSON.NamespaceSelector,
				podSelector:       fromJSON.PodSelector,
			})
		}
		np.ingressPolicies = append(np.ingressPolicies, ingress)
	}

	// Go through each egress rule.  For each egress rule, create an
	// addressSet for the peer pods.
	for i, egressJSON := range policy.Spec.Egress {
		klog.V(5).Infof("Network policy egress is %+v", egressJSON)

		egress := newGressPolicy(knet.PolicyTypeEgress, i, policy.Namespace, policy.Name)

		// Each egress rule can have multiple ports to which we allow traffic.
		for _, portJSON := range egressJSON.Ports {
			egress.addPortPolicy(&portJSON)
		}

		if hasAnyLabelSelector(egressJSON.To) {
			klog.V(5).Infof("Network policy %s with egress rule %s has a selector", policy.Name, egress.policyName)
			if err := egress.ensurePeerAddressSet(oc.addressSetFactory); err != nil {
				np.Unlock()
				return err
			}
		}

		for _, toJSON := range egressJSON.To {
			// Add IPBlock to egress network policy
			if toJSON.IPBlock != nil {
				egress.addIPBlock(toJSON.IPBlock)
			}

			policyHandlers = append(policyHandlers, policyHandler{
				gress:             egress,
				namespaceSelector: toJSON.NamespaceSelector,
				podSelector:       toJSON.PodSelector,
			})
		}
		np.egressPolicies = append(np.egressPolicies, egress)
	}

	np.Unlock()

	for _, handler := range policyHandlers {
		var err error
		if handler.namespaceSelector != nil && handler.podSelector != nil {
			// For each rule that contains both peer namespace selector and
			// peer pod selector, we create a watcher for each matching namespace
			// that populates the addressSet
			err = oc.addPeerNamespaceAndPodHandler(handler.namespaceSelector, handler.podSelector, handler.gress, np)
		} else if handler.namespaceSelector != nil {
			// For each peer namespace selector, we create a watcher that
			// populates ingress.peerAddressSets
			err = oc.addPeerNamespaceHandler(handler.namespaceSelector, handler.gress, np)
		} else if handler.podSelector != nil {
			// For each peer pod selector, we create a watcher that
			// populates the addressSet
			err = oc.addPeerPodHandler(policy, handler.podSelector,
				handler.gress, np)
		}
		if err != nil {
			return fmt.Errorf("failed to handle policy handler selector: %v", err)
		}
	}

	readableGroupName := fmt.Sprintf("%s_%s", policy.Namespace, policy.Name)
	np.portGroupName = hashedPortGroup(readableGroupName)
	ops := []ovsdb.Operation{}

	// Build policy ACLs
	acls := oc.buildNetworkPolicyACLs(np, aclLogging)
	ops, err := libovsdbops.CreateOrUpdateACLsOps(oc.nbClient, ops, acls...)
	if err != nil {
		return fmt.Errorf("failed to create ACL ops: %v", err)
	}

	// Build a port group for the policy. All the pods that this policy
	// selects will be eventually added to this port group.
	pg := libovsdbops.BuildPortGroup(np.portGroupName, readableGroupName, nil, acls)

	// Add a handler to update the policy and deny port groups with the pods
	// this policy applies to.
	// Handle initial items locally to minimize DB ops.
	var selectedPods []interface{}
	handleInitialSelectedPods := func(objs []interface{}) error {
		var errs []error
		selectedPods = objs
		policyPorts, ingressDenyPorts, egressDenyPorts := oc.processLocalPodSelectorSetPods(policy, np, selectedPods...)
		pg.Ports = append(pg.Ports, policyPorts...)
		ops, err = libovsdbops.AddPortsToPortGroupOps(oc.nbClient, ops, portGroupIngressDenyName, ingressDenyPorts...)
		if err != nil {
			oc.processLocalPodSelectorDelPods(np, selectedPods...)
			errs = append(errs, err)
		}
		ops, err = libovsdbops.AddPortsToPortGroupOps(oc.nbClient, ops, portGroupEgressDenyName, egressDenyPorts...)
		if err != nil {
			oc.processLocalPodSelectorDelPods(np, selectedPods...)
			errs = append(errs, err)
		}
		return kerrorsutil.NewAggregate(errs)
	}
	err = oc.addLocalPodHandler(policy, np, portGroupIngressDenyName, portGroupEgressDenyName, handleInitialSelectedPods)
	if err != nil {
		return fmt.Errorf("failed to handle local pod selector: %v", err)
	}

	np.Lock()
	defer np.Unlock()
	if np.deleted {
		oc.processLocalPodSelectorDelPods(np, selectedPods...)
		return nil
	}

	ops, err = libovsdbops.CreateOrUpdatePortGroupsOps(oc.nbClient, ops, pg)
	if err != nil {
		oc.processLocalPodSelectorDelPods(np, selectedPods...)
		return fmt.Errorf("failed to create ops to add port to a port group: %v", err)
	}

	recordOps, txOkCallBack, _, err := metrics.GetConfigDurationRecorder().AddOVN(oc.nbClient, "networkpolicy",
		policy.Namespace, policy.Name)
	if err != nil {
		klog.Errorf("Failed to record config duration: %v", err)
	}
	ops = append(ops, recordOps...)

	_, err = libovsdbops.TransactAndCheck(oc.nbClient, ops)
	if err != nil {
		oc.processLocalPodSelectorDelPods(np, selectedPods...)
		return fmt.Errorf("failed to run ovsdb txn to add ports to port group: %v", err)
	}
	txOkCallBack()
	return nil
}

// addNetworkPolicy creates and applies OVN ACLs to pod logical switch
// ports from Kubernetes NetworkPolicy objects using OVN Port Groups
func (oc *Controller) addNetworkPolicy(policy *knet.NetworkPolicy) error {
	klog.Infof("Adding network policy %s in namespace %s", policy.Name,
		policy.Namespace)

	nsInfo, nsUnlock, err := oc.ensureNamespaceLocked(policy.Namespace, false, nil)
	if err != nil {
		return fmt.Errorf("unable to ensure namespace for network policy: %s, namespace: %s, error: %v",
			policy.Name, policy.Namespace, err)
	}
	_, alreadyExists := nsInfo.networkPolicies[policy.Name]
	if alreadyExists {
		nsUnlock()
		// If this scenario happens something is wrong in our code, however if we return error here
		// the NP will be retried infinitely to be added. Another option would be to fatal out here
		// but that seems too aggressive
		klog.Errorf("During add network policy, policy already found for %s/%s, this should not happen!",
			policy.Namespace, policy.Name)
		return nil
	}
	np := NewNetworkPolicy(policy)

	if len(nsInfo.networkPolicies) == 0 {
		err = oc.createDefaultDenyPGAndACLs(policy.Namespace, policy.Name, nsInfo)
		if err != nil {
			nsUnlock()
			return fmt.Errorf("failed to create default port groups and acls for policy: %s/%s, error: %v",
				policy.Namespace, policy.Name, err)
		}
		defer func() {
			if err != nil {
				nsInfo, nsUnlock, errDelete := oc.ensureNamespaceLocked(policy.Namespace, false, nil)
				// rollback failed, best effort cleanup; won't add to retry mechanism since item doesn't exist in cache yet.
				if errDelete != nil {
					klog.Warningf("Rollback of default port groups and acls for policy: %s/%s failed, Unable to ensure namespace for network policy: error %v", policy.Namespace, policy.Name, errDelete)
					return
				}
				if len(nsInfo.networkPolicies) == 0 {
					// try rolling-back since creation of default acls/pgs failed
					errDelete = oc.deleteDefaultDenyPGAndACLs(policy.Namespace, policy.Name, nsInfo)
					nsUnlock()
					if errDelete != nil {
						// rollback failed, best effort cleanup; won't add to retry mechanism since item doesn't exist in cache yet.
						klog.Warningf("Rollback of default port groups and acls for policy: %s/%s failed: error %v", policy.Namespace, policy.Name, errDelete)
					}
				} else {
					nsUnlock()
				}
			}
		}()
	}
	aclLogging := nsInfo.aclLogging
	portGroupIngressDenyName := nsInfo.portGroupIngressDenyName
	portGroupEgressDenyName := nsInfo.portGroupEgressDenyName
	nsUnlock()
	if err := oc.createNetworkPolicy(np, policy, &aclLogging,
		portGroupIngressDenyName, portGroupEgressDenyName); err != nil {
		return fmt.Errorf("failed to create Network Policy: %s/%s, error: %v",
			policy.Namespace, policy.Name, err)
	}

	// Now do nsinfo operations to set the policy
	nsInfo, nsUnlock, err = oc.ensureNamespaceLocked(policy.Namespace, false, nil)
	if err != nil {
		// rollback network policy
		if err := oc.deleteNetworkPolicy(policy, np); err != nil {
			// rollback failed, add to retry to cleanup
			key := getPolicyNamespacedName(policy)
			oc.retryNetworkPolicies.DoWithLock(key, func(key string) {
				oc.retryNetworkPolicies.initRetryObjWithDelete(policy, key, np, false)
			})
		}
		return fmt.Errorf("unable to ensure namespace for network policy: %s, namespace: %s, error: %v",
			policy.Name, policy.Namespace, err)
	}
	defer nsUnlock()
	// Update default ACL log level, since namespace update will only affect namespace-wide ACLs if
	// len(nsInfo.networkPolicies) > 0, which is not the case at this point
	if nsInfo.aclLogging.Deny != aclLogging.Deny && len(nsInfo.networkPolicies) == 0 {
		if err := oc.updateACLLoggingForDefaultACLs(policy.Namespace, nsInfo); err != nil {
			klog.Warningf(err.Error())
		} else {
			klog.Infof("Policy %s: ACL logging setting updated to deny=%s allow=%s",
				getPolicyNamespacedName(policy), nsInfo.aclLogging.Deny, nsInfo.aclLogging.Allow)
		}
	}
	// The allow logging level was updated while we were creating the policy if
	// the current allow logging level is different than the one we have from
	// the first time we locked the namespace.
	// namespace update handler couldn't update this netpol, since it's not in the nsInfo.networkPolicies map yet.
	if nsInfo.aclLogging.Allow != aclLogging.Allow {
		if err := oc.updateACLLoggingForPolicy(np, &nsInfo.aclLogging); err != nil {
			klog.Warningf(err.Error())
		} else {
			klog.Infof("Policy %s: ACL logging setting updated to deny=%s allow=%s",
				getPolicyNamespacedName(policy), nsInfo.aclLogging.Deny, nsInfo.aclLogging.Allow)
		}
	}
	nsInfo.networkPolicies[policy.Name] = np
	return nil
}

// buildNetworkPolicyACLs builds the ACLS associated with the 'gress policies
// of the provided network policy.
func (oc *Controller) buildNetworkPolicyACLs(np *networkPolicy, aclLogging *ACLLoggingLevels) []*nbdb.ACL {
	acls := []*nbdb.ACL{}
	for _, gp := range np.ingressPolicies {
		acl := gp.buildLocalPodACLs(np.portGroupName, aclLogging)
		acls = append(acls, acl...)
	}
	for _, gp := range np.egressPolicies {
		acl := gp.buildLocalPodACLs(np.portGroupName, aclLogging)
		acls = append(acls, acl...)
	}

	return acls
}

// deleteNetworkPolicy removes a network policy
// If np is provided, then deletion may still occur without a lock on nsInfo
func (oc *Controller) deleteNetworkPolicy(policy *knet.NetworkPolicy, np *networkPolicy) error {
	klog.Infof("Deleting network policy %s in namespace %s, np is nil: %v",
		policy.Name, policy.Namespace, np == nil)

	nsInfo, nsUnlock := oc.getNamespaceLocked(policy.Namespace, false)
	if nsInfo == nil {
		// if we didn't get nsInfo and np is nil, we cannot proceed
		if np == nil {
			klog.Warningf("Failed to get namespace lock when deleting policy %s in namespace %s",
				policy.Name, policy.Namespace)
			return nil
		}

		if err := oc.destroyNetworkPolicy(np, false); err != nil {
			return fmt.Errorf("failed to destroy network policy: %s/%s", policy.Namespace, policy.Name)
		}
		return nil
	}

	defer nsUnlock()

	// try to use the more official np found in nsInfo
	// also, if this is called during the process of the policy creation, the current network policy
	// may not be added to nsInfo.networkPolicies yet.
	expectedLastPolicyNum := 0
	foundNp, ok := nsInfo.networkPolicies[policy.Name]
	if ok {
		expectedLastPolicyNum = 1
		np = foundNp
	}
	if np == nil {
		klog.Warningf("Unable to delete network policy: %s/%s since its not found in cache", policy.Namespace, policy.Name)
		return nil
	}
	isLastPolicyInNamespace := len(nsInfo.networkPolicies) == expectedLastPolicyNum
	if err := oc.destroyNetworkPolicy(np, isLastPolicyInNamespace); err != nil {
		return fmt.Errorf("failed to destroy network policy: %s/%s", policy.Namespace, policy.Name)
	}

	delete(nsInfo.networkPolicies, policy.Name)
	return nil
}

// destroys a particular network policy
// if nsInfo is provided, the entire port group will be deleted for ingress/egress directions
// lastPolicy indicates if no other policies are using the respective portgroup anymore
func (oc *Controller) destroyNetworkPolicy(np *networkPolicy, lastPolicy bool) error {
	np.Lock()
	defer np.Unlock()
	np.deleted = true
	oc.shutdownHandlers(np)

	ports := []*lpInfo{}
	np.localPods.Range(func(_, value interface{}) bool {
		portInfo := value.(*lpInfo)
		ports = append(ports, portInfo)
		return true
	})

	var err error
	ingressPGName := defaultDenyPortGroup(np.namespace, ingressDefaultDenySuffix)
	egressPGName := defaultDenyPortGroup(np.namespace, egressDefaultDenySuffix)

	ingressDenyPorts, egressDenyPorts := oc.localPodDelDefaultDeny(np, ports...)
	defer func() {
		// In case of error, undo localPodDelDefaultDeny() and restore lspIngressDenyCache/lspEgressDenyCache refcnt.
		// Deletion will be retried.
		if err != nil {
			oc.localPodAddDefaultDeny(np.policy, ports...)
		}
	}()

	ops := []ovsdb.Operation{}
	// we haven't deleted our np from the namespace yet so there should be 1 policy
	// if there are no more policies left on the namespace
	if lastPolicy {
		ops, err = libovsdbops.DeletePortGroupsOps(oc.nbClient, ops, ingressPGName)
		if err != nil {
			return fmt.Errorf("failed to make ops for delete ingress port group: %s, for policy: %s/%s, error: %v",
				ingressPGName, np.namespace, np.name, err)
		}
		ops, err = libovsdbops.DeletePortGroupsOps(oc.nbClient, ops, egressPGName)
		if err != nil {
			return fmt.Errorf("failed to make ops for delete egress port group: %s, for policy: %s/%s, error: %v",
				egressPGName, np.namespace, np.name, err)
		}
	} else {
		ops, err = libovsdbops.DeletePortsFromPortGroupOps(oc.nbClient, ops, ingressPGName, ingressDenyPorts...)
		if err != nil {
			return fmt.Errorf("failed to make ops for ingress port group: %s, for policy: %s/%s, to remove ports: %#v,"+
				" error: %v", ingressPGName, np.namespace, np.name, ingressDenyPorts, err)
		}
		ops, err = libovsdbops.DeletePortsFromPortGroupOps(oc.nbClient, ops, egressPGName, egressDenyPorts...)
		if err != nil {
			return fmt.Errorf("failed to make ops for egress port group: %s, for policy: %s/%s, to remove ports: %#v,"+
				" error: %v", egressPGName, np.namespace, np.name, egressDenyPorts, err)
		}
	}

	// Delete the port group
	ops, err = libovsdbops.DeletePortGroupsOps(oc.nbClient, ops, np.portGroupName)
	if err != nil {
		return fmt.Errorf("failed to make delete network policy port group ops, policy: %s/%s, group name: %s,"+
			" error: %v", np.namespace, np.name, np.portGroupName, err)
	}

	recordOps, txOkCallBack, _, err := metrics.GetConfigDurationRecorder().AddOVN(oc.nbClient, "networkpolicy",
		np.policy.Namespace, np.policy.Name)
	if err != nil {
		klog.Errorf("Failed to record config duration: %v", err)
	}
	ops = append(ops, recordOps...)

	_, err = libovsdbops.TransactAndCheck(oc.nbClient, ops)
	if err != nil {
		return fmt.Errorf("failed to execute ovsdb txn to delete network policy: %s/%s, error: %v",
			np.namespace, np.name, err)
	}
	txOkCallBack()

	// Delete ingress/egress address sets
	for _, policy := range np.ingressPolicies {
		err = policy.destroy()
		if err != nil {
			return fmt.Errorf("failed to delete network policy ingress address sets, policy: %s/%s, error: %v",
				np.namespace, np.name, err)
		}
	}
	for _, policy := range np.egressPolicies {
		err = policy.destroy()
		if err != nil {
			return fmt.Errorf("failed to delete network policy egress address sets, policy: %s/%s, error: %v",
				np.namespace, np.name, err)
		}
	}
	return nil
}

// handlePeerPodSelectorAddUpdate adds the IP address of a pod that has been
// selected as a peer by a NetworkPolicy's ingress/egress section to that
// ingress/egress address set
func (oc *Controller) handlePeerPodSelectorAddUpdate(gp *gressPolicy, objs ...interface{}) error {
	pods := make([]*kapi.Pod, 0, len(objs))
	for _, obj := range objs {
		pod := obj.(*kapi.Pod)
		if pod.Spec.NodeName == "" {
			continue
		}
		pods = append(pods, pod)
	}
	// If no IP is found, the pod handler may not have added it by the time the network policy handler
	// processed this pod event. It will grab it during the pod update event to add the annotation,
	// so don't log an error here.
	if err := gp.addPeerPods(pods...); err != nil && !errors.Is(err, util.ErrNoPodIPFound) {
		return err
	}
	return nil
}

// handlePeerPodSelectorDelete removes the IP address of a pod that no longer
// matches a NetworkPolicy ingress/egress section's selectors from that
// ingress/egress address set
func (oc *Controller) handlePeerPodSelectorDelete(gp *gressPolicy, obj interface{}) error {
	pod := obj.(*kapi.Pod)
	if pod.Spec.NodeName == "" {
		klog.Infof("Pod %s/%s not scheduled on any node, skipping it", pod.Namespace, pod.Name)
		return nil
	}
	if err := gp.deletePeerPod(pod); err != nil {
		return err
	}
	return nil
}

// handlePeerServiceSelectorAddUpdate adds the VIP of a service that selects
// pods that are selected by the Network Policy
func (oc *Controller) handlePeerServiceAdd(gp *gressPolicy, service *kapi.Service) error {
	klog.V(5).Infof("A Service: %s matches the namespace as the gress policy: %s", service.Name, gp.policyName)
	return gp.addPeerSvcVip(oc.nbClient, service)
}

// handlePeerServiceDelete removes the VIP of a service that selects
// pods that are selected by the Network Policy
func (oc *Controller) handlePeerServiceDelete(gp *gressPolicy, service *kapi.Service) error {
	return gp.deletePeerSvcVip(oc.nbClient, service)
}

type NetworkPolicyExtraParameters struct {
	policy                   *knet.NetworkPolicy
	np                       *networkPolicy
	gp                       *gressPolicy
	podSelector              labels.Selector
	portGroupIngressDenyName string
	portGroupEgressDenyName  string
}

// Watch services that are in the same Namespace as the NP
// To account for hairpined traffic
func (oc *Controller) addPeerServiceHandler(
	policy *knet.NetworkPolicy, gp *gressPolicy, np *networkPolicy) error {
	// start watching services in the same namespace as the network policy
	retryPeerServices := NewRetryObjs(
		factory.PeerServiceType,
		policy.Namespace,
		nil, nil,
		&NetworkPolicyExtraParameters{gp: gp})

	serviceHandler, err := oc.WatchResource(retryPeerServices)
	if err != nil {
		klog.Errorf("Failed WatchResource for addPeerServiceHandler: %v", err)
		return err
	}

	np.svcHandlerList = append(np.svcHandlerList, serviceHandler)
	return nil
}

func (oc *Controller) addPeerPodHandler(
	policy *knet.NetworkPolicy, podSelector *metav1.LabelSelector,
	gp *gressPolicy, np *networkPolicy) error {

	// NetworkPolicy is validated by the apiserver; this can't fail.
	sel, _ := metav1.LabelSelectorAsSelector(podSelector)

	// start watching pods in the same namespace as the network policy and selected by the
	// label selector
	syncFunc := func(objs []interface{}) error {
		return oc.handlePeerPodSelectorAddUpdate(gp, objs...)
	}
	retryPeerPods := NewRetryObjs(
		factory.PeerPodSelectorType,
		policy.Namespace,
		sel, syncFunc,
		&NetworkPolicyExtraParameters{gp: gp})

	podHandler, err := oc.WatchResource(retryPeerPods)
	if err != nil {
		klog.Errorf("Failed WatchResource for addPeerPodHandler: %v", err)
		return err
	}

	np.podHandlerList = append(np.podHandlerList, podHandler)
	return nil
}

func (oc *Controller) addPeerNamespaceAndPodHandler(
	namespaceSelector *metav1.LabelSelector,
	podSelector *metav1.LabelSelector,
	gp *gressPolicy,
	np *networkPolicy) error {

	// NetworkPolicy is validated by the apiserver; this can't fail.
	nsSel, _ := metav1.LabelSelectorAsSelector(namespaceSelector)
	podSel, _ := metav1.LabelSelectorAsSelector(podSelector)

	// start watching namespaces selected by the namespace selector nsSel;
	// upon namespace add event, start watching pods in that namespace selected
	// by the label selector podSel
	retryPeerNamespaces := NewRetryObjs(
		factory.PeerNamespaceAndPodSelectorType,
		"", nsSel, nil,
		&NetworkPolicyExtraParameters{
			gp:          gp,
			np:          np,
			podSelector: podSel}, // will be used in the addFunc to create a pod handler
	)

	namespaceHandler, err := oc.WatchResource(retryPeerNamespaces)
	if err != nil {
		klog.Errorf("Failed WatchResource for addPeerNamespaceAndPodHandler: %v", err)
		return err
	}

	np.nsHandlerList = append(np.nsHandlerList, namespaceHandler)
	return nil
}

func (oc *Controller) handlePeerNamespaceSelectorOnUpdate(np *networkPolicy, gp *gressPolicy, doUpdate func() bool) error {
	aclLoggingLevels := oc.GetNamespaceACLLogging(np.namespace)
	np.Lock()
	defer np.Unlock()
	// This needs to be a write lock because there's no locking around 'gress policies
	if !np.deleted && doUpdate() {
		acls := gp.buildLocalPodACLs(np.portGroupName, aclLoggingLevels)
		ops, err := libovsdbops.CreateOrUpdateACLsOps(oc.nbClient, nil, acls...)
		if err != nil {
			return err
		}
		ops, err = libovsdbops.AddACLsToPortGroupOps(oc.nbClient, ops, np.portGroupName, acls...)
		if err != nil {
			return err
		}
		_, err = libovsdbops.TransactAndCheck(oc.nbClient, ops)
		if err != nil {
			return err
		}
	}
	return nil
}

func (oc *Controller) addPeerNamespaceHandler(
	namespaceSelector *metav1.LabelSelector,
	gress *gressPolicy, np *networkPolicy) error {

	// NetworkPolicy is validated by the apiserver; this can't fail.
	sel, _ := metav1.LabelSelectorAsSelector(namespaceSelector)

	// start watching namespaces selected by the namespace selector
	syncFunc := func(i []interface{}) error {
		// This needs to be a write lock because there's no locking around 'gress policies
		np.Lock()
		defer np.Unlock()
		// We load the existing address set into the 'gress policy.
		// Notice that this will make the AddFunc for this initial
		// address set a noop.
		// The ACL must be set explicitly after setting up this handler
		// for the address set to be considered.
		gress.addNamespaceAddressSets(i)
		return nil
	}
	retryPeerNamespaces := NewRetryObjs(
		factory.PeerNamespaceSelectorType,
		"", sel, syncFunc,
		&NetworkPolicyExtraParameters{gp: gress, np: np},
	)

	namespaceHandler, err := oc.WatchResource(retryPeerNamespaces)
	if err != nil {
		klog.Errorf("Failed WatchResource for addPeerNamespaceHandler: %v", err)
		return err
	}

	np.nsHandlerList = append(np.nsHandlerList, namespaceHandler)
	return nil
}

func (oc *Controller) shutdownHandlers(np *networkPolicy) {
	for _, handler := range np.podHandlerList {
		oc.watchFactory.RemovePodHandler(handler)
	}
	for _, handler := range np.nsHandlerList {
		oc.watchFactory.RemoveNamespaceHandler(handler)
	}
	for _, handler := range np.svcHandlerList {
		oc.watchFactory.RemoveServiceHandler(handler)
	}
}

func getPolicyNamespacedName(policy *knet.NetworkPolicy) string {
	return fmt.Sprintf("%v/%v", policy.Namespace, policy.Name)
}
