package ovn

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

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
	"k8s.io/apimachinery/pkg/util/sets"
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

// defaultDenyPortGroups is a shared object and should be used by only 1 thread at a time
type defaultDenyPortGroups struct {
	// portName: map[portName]sets.String(policyNames)
	// store policies that are using every port in the map
	// these maps should be atomically updated with db operations
	// if adding a port to db for a policy fails, map shouldn't be changed
	ingressPortToPolicies map[string]sets.String
	egressPortToPolicies  map[string]sets.String
	// policies is a map of policies that use this port group
	// policy keys must be unique, and it can be retrieved with (np *networkPolicy) getKey()
	policies map[string]bool
}

// addPortsForPolicy adds port-policy association for default deny port groups and
// returns lists of new ports to add to the default deny port groups.
// If port should be added to ingress and/or egress default deny port group depends on policy spec.
func (sharedPGs *defaultDenyPortGroups) addPortsForPolicy(np *networkPolicy,
	portNamesToUUIDs map[string]string) (ingressDenyPorts, egressDenyPorts []string) {
	ingressDenyPorts = []string{}
	egressDenyPorts = []string{}

	if np.isIngress {
		for portName, portUUID := range portNamesToUUIDs {
			// if this is the first NP referencing this pod, then we
			// need to add it to the port group.
			if sharedPGs.ingressPortToPolicies[portName].Len() == 0 {
				ingressDenyPorts = append(ingressDenyPorts, portUUID)
				sharedPGs.ingressPortToPolicies[portName] = sets.String{}
			}
			// increment the reference count.
			sharedPGs.ingressPortToPolicies[portName].Insert(np.getKey())
		}
	}
	if np.isEgress {
		for portName, portUUID := range portNamesToUUIDs {
			if sharedPGs.egressPortToPolicies[portName].Len() == 0 {
				// again, reference count is 0, so add to port
				egressDenyPorts = append(egressDenyPorts, portUUID)
				sharedPGs.egressPortToPolicies[portName] = sets.String{}
			}
			// bump reference count
			sharedPGs.egressPortToPolicies[portName].Insert(np.getKey())
		}
	}
	return
}

// deletePortsForPolicy deletes port-policy association for default deny port groups,
// and returns lists of port UUIDs to delete from the default deny port groups.
// If port should be deleted from ingress and/or egress default deny port group depends on policy spec.
func (sharedPGs *defaultDenyPortGroups) deletePortsForPolicy(np *networkPolicy,
	portNamesToUUIDs map[string]string) (ingressDenyPorts, egressDenyPorts []string) {
	ingressDenyPorts = []string{}
	egressDenyPorts = []string{}

	if np.isIngress {
		for portName, portUUID := range portNamesToUUIDs {
			// Delete and Len can be used for zero-value nil set
			sharedPGs.ingressPortToPolicies[portName].Delete(np.getKey())
			if sharedPGs.ingressPortToPolicies[portName].Len() == 0 {
				ingressDenyPorts = append(ingressDenyPorts, portUUID)
				delete(sharedPGs.ingressPortToPolicies, portName)
			}
		}
	}
	if np.isEgress {
		for portName, portUUID := range portNamesToUUIDs {
			sharedPGs.egressPortToPolicies[portName].Delete(np.getKey())
			if sharedPGs.egressPortToPolicies[portName].Len() == 0 {
				egressDenyPorts = append(egressDenyPorts, portUUID)
				delete(sharedPGs.egressPortToPolicies, portName)
			}
		}
	}
	return
}

type networkPolicy struct {
	// RWMutex synchronizes operations on the policy.
	// Operations that change local and peer pods take a RLock,
	// whereas operations that affect the policy take a Lock.
	sync.RWMutex
	name            string
	namespace       string
	ingressPolicies []*gressPolicy
	egressPolicies  []*gressPolicy
	isIngress       bool
	isEgress        bool
	podHandlerList  []*factory.Handler
	svcHandlerList  []*factory.Handler
	nsHandlerList   []*factory.Handler

	// localPods is a map of pods affected by this policy.
	// It is used to update defaultDeny port group port counters, when deleting network policy.
	// Port should only be added here if it was successfully added to default deny port group,
	// and local port group in db.
	// localPods may be updated by multiple pod handlers at the same time,
	// therefore it uses a sync map to handle simultaneous access.
	// map of portName(string): portUUID(string)
	localPods sync.Map

	portGroupName string
	deleted       bool //deleted policy
}

func NewNetworkPolicy(policy *knet.NetworkPolicy) *networkPolicy {
	policyTypeIngress, policyTypeEgress := getPolicyType(policy)
	np := &networkPolicy{
		name:            policy.Name,
		namespace:       policy.Namespace,
		ingressPolicies: make([]*gressPolicy, 0),
		egressPolicies:  make([]*gressPolicy, 0),
		isIngress:       policyTypeIngress,
		isEgress:        policyTypeEgress,
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
			ingressPGName := defaultDenyPortGroupName(namespace, ingressDefaultDenySuffix)
			egressPGName := defaultDenyPortGroupName(namespace, egressDefaultDenySuffix)
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

func defaultDenyPortGroupName(namespace, gressSuffix string) string {
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

func (oc *Controller) addPolicyToDefaultPortGroups(np *networkPolicy, aclLogging *ACLLoggingLevels) error {
	return oc.sharedNetpolPortGroups.DoWithLock(np.namespace, func(pgKey string) error {
		sharedPGs, loaded := oc.sharedNetpolPortGroups.LoadOrStore(pgKey, &defaultDenyPortGroups{
			ingressPortToPolicies: map[string]sets.String{},
			egressPortToPolicies:  map[string]sets.String{},
			policies:              map[string]bool{},
		})
		if !loaded {
			// create port groups with acls
			err := oc.createDefaultDenyPGAndACLs(np.namespace, np.name, aclLogging)
			if err != nil {
				oc.sharedNetpolPortGroups.Delete(pgKey)
				return fmt.Errorf("failed to create default deny port groups: %v", err)
			}
		}
		sharedPGs.policies[np.getKey()] = true
		return nil
	})
}

func (oc *Controller) delPolicyFromDefaultPortGroups(np *networkPolicy) error {
	return oc.sharedNetpolPortGroups.DoWithLock(np.namespace, func(pgKey string) error {
		sharedPGs, found := oc.sharedNetpolPortGroups.Load(pgKey)
		if !found {
			return nil
		}
		delete(sharedPGs.policies, np.getKey())
		if len(sharedPGs.policies) == 0 {
			// last policy was deleted, delete port group
			err := oc.deleteDefaultDenyPGAndACLs(np.namespace, np.name)
			if err != nil {
				return fmt.Errorf("failed to delete defaul deny port group: %v", err)
			}
			oc.sharedNetpolPortGroups.Delete(pgKey)
		}
		return nil
	})
}

func (oc *Controller) createDefaultDenyPGAndACLs(namespace, policy string, aclLogging *ACLLoggingLevels) error {
	ingressPGName := defaultDenyPortGroupName(namespace, ingressDefaultDenySuffix)
	ingressDenyACL, ingressAllowACL := buildDenyACLs(namespace, policy, ingressPGName, aclLogging, knet.PolicyTypeIngress)
	egressPGName := defaultDenyPortGroupName(namespace, egressDefaultDenySuffix)
	egressDenyACL, egressAllowACL := buildDenyACLs(namespace, policy, egressPGName, aclLogging, knet.PolicyTypeEgress)
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

	return nil
}

// deleteDefaultDenyPGAndACLs deletes the default port groups and acls for a ns/policy
func (oc *Controller) deleteDefaultDenyPGAndACLs(namespace, policy string) error {
	var aclsToBeDeleted []*nbdb.ACL

	ingressPGName := defaultDenyPortGroupName(namespace, ingressDefaultDenySuffix)
	ingressDenyACL, ingressAllowACL := buildDenyACLs(namespace, policy, ingressPGName, nil, knet.PolicyTypeIngress)
	aclsToBeDeleted = append(aclsToBeDeleted, ingressDenyACL, ingressAllowACL)
	egressPGName := defaultDenyPortGroupName(namespace, egressDefaultDenySuffix)
	egressDenyACL, egressAllowACL := buildDenyACLs(namespace, policy, egressPGName, nil, knet.PolicyTypeEgress)
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
	return oc.sharedNetpolPortGroups.DoWithLock(ns, func(pgKey string) error {
		_, loaded := oc.sharedNetpolPortGroups.Load(pgKey)
		if !loaded {
			// shared port group doesn't exist, nothing to update
			return nil
		}
		denyEgressACL, _ := buildDenyACLs(ns, "", defaultDenyPortGroupName(ns, egressDefaultDenySuffix),
			&nsInfo.aclLogging, knet.PolicyTypeEgress)
		denyIngressACL, _ := buildDenyACLs(ns, "", defaultDenyPortGroupName(ns, ingressDefaultDenySuffix),
			&nsInfo.aclLogging, knet.PolicyTypeIngress)
		if err := UpdateACLLogging(oc.nbClient, []*nbdb.ACL{denyIngressACL, denyEgressACL}, &nsInfo.aclLogging); err != nil {
			return fmt.Errorf("unable to update ACL logging for namespace %s: %w", ns, err)
		}
		return nil
	})
}

// handleNetPolNamespaceUpdate should update all network policies related to given namespace.
// Must be called with namespace Lock, should be retriable
func (oc *Controller) handleNetPolNamespaceUpdate(namespace string, nsInfo *namespaceInfo) error {
	// update shared port group ACLs
	if err := oc.updateACLLoggingForDefaultACLs(namespace, nsInfo); err != nil {
		return fmt.Errorf("failed to update default deny ACLs for namespace %s: %v", namespace, err)
	}
	// now update network policy specific ACLs
	klog.V(5).Infof("Setting network policy ACLs for ns: %s", namespace)
	for npKey := range nsInfo.relatedNetworkPolicies {
		err := oc.networkPolicies.DoWithLock(npKey, func(key string) error {
			np, found := oc.networkPolicies.Load(npKey)
			if !found {
				klog.Errorf("Netpol was deleted from cache, but not from namespace related objects")
				return nil
			}
			return oc.updateACLLoggingForPolicy(np, &nsInfo.aclLogging)
		})
		if err != nil {
			return fmt.Errorf("unable to update ACL for network policy %s: %v", npKey, err)
		}
		klog.Infof("ACL for network policy: %s, updated to new log level: %s", npKey, nsInfo.aclLogging.Allow)
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

// getPolicyType returns whether the policy is of type ingress and/or egress
func getPolicyType(policy *knet.NetworkPolicy) (bool, bool) {
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

// getNewLocalPolicyPorts will find and return port info for every given pod obj, that is not found in
// np.localPods.
// if there are problems with fetching port info from logicalPortCache, pod will be added to errObjs.
func (oc *Controller) getNewLocalPolicyPorts(np *networkPolicy,
	objs ...interface{}) (policyPortsToUUIDs map[string]string, policyPortUUIDs []string, errObjs []interface{}) {

	klog.Infof("Processing NetworkPolicy %s/%s to have %d local pods...", np.namespace, np.name, len(objs))
	policyPortUUIDs = make([]string, 0, len(objs))
	policyPortsToUUIDs = map[string]string{}

	for _, obj := range objs {
		pod := obj.(*kapi.Pod)

		if util.PodCompleted(pod) {
			// if pod is completed, do not add it to NP port group
			continue
		}
		if pod.Spec.NodeName == "" {
			// pod is not yet scheduled, will receive update event for it
			continue
		}

		logicalPortName := util.GetLogicalPortName(pod.Namespace, pod.Name)

		if _, ok := np.localPods.Load(logicalPortName); ok {
			// port is already added for this policy
			continue
		}

		// Add pod to errObjs for retry if
		// 1. getting pod LSP from the cache fails,
		// 2. the gotten LSP is scheduled for removal (stateful-sets).
		portInfo, err := oc.logicalPortCache.get(logicalPortName)
		if err != nil {
			klog.Warningf("Failed to get LSP for pod %s/%s for networkPolicy %s, err: %v",
				pod.Namespace, pod.Name, np.name, err)
			errObjs = append(errObjs, pod)
			continue
		}

		// Add pod to errObjs if LSP is scheduled for deletion
		if !portInfo.expires.IsZero() {
			klog.Warningf("Stale LSP %s for network policy %s found in cache",
				portInfo.name, np.name)
			errObjs = append(errObjs, pod)
			continue
		}

		// LSP get succeeded and LSP is up to fresh
		klog.V(5).Infof("Fresh LSP %s for network policy %s found in cache",
			portInfo.name, np.name)

		policyPortUUIDs = append(policyPortUUIDs, portInfo.uuid)
		policyPortsToUUIDs[portInfo.name] = portInfo.uuid
	}
	return
}

// getExistingLocalPolicyPorts will find and return port info for every given pod obj, that is present in np.localPods.
// if there are problems with fetching port info from logicalPortCache, pod will be added to errObjs.
func (oc *Controller) getExistingLocalPolicyPorts(np *networkPolicy,
	objs ...interface{}) (policyPortsToUUIDs map[string]string, policyPortUUIDs []string, errObjs []interface{}) {
	klog.Infof("Processing NetworkPolicy %s/%s to delete %d local pods...", np.namespace, np.name, len(objs))

	policyPortUUIDs = make([]string, 0, len(objs))
	policyPortsToUUIDs = map[string]string{}
	for _, obj := range objs {
		pod := obj.(*kapi.Pod)

		logicalPortName := util.GetLogicalPortName(pod.Namespace, pod.Name)
		if _, ok := np.localPods.Load(logicalPortName); !ok {
			// port is already deleted for this policy
			continue
		}

		portInfo, err := oc.logicalPortCache.get(logicalPortName)
		if err != nil {
			klog.Warningf("Failed to get LSP for pod %s/%s for networkPolicy %s refetching err: %v",
				pod.Namespace, pod.Name, np.name, err)
			errObjs = append(errObjs, pod)
			return
		}

		policyPortsToUUIDs[portInfo.name] = portInfo.uuid
		policyPortUUIDs = append(policyPortUUIDs, portInfo.uuid)
	}
	return
}

// denyPGAddPorts adds ports to default deny port groups.
func (oc *Controller) denyPGAddPorts(np *networkPolicy, portNamesToUUIDs map[string]string) error {
	var err error
	var ops []ovsdb.Operation
	ingressDenyPGName := defaultDenyPortGroupName(np.namespace, ingressDefaultDenySuffix)
	egressDenyPGName := defaultDenyPortGroupName(np.namespace, egressDefaultDenySuffix)

	pgKey := np.namespace
	// this lock guarantees that sharedPortGroup counters will be updated atomically
	// with adding port to port group in db.
	oc.sharedNetpolPortGroups.LockKey(pgKey)
	defer oc.sharedNetpolPortGroups.UnlockKey(pgKey)
	sharedPGs, ok := oc.sharedNetpolPortGroups.Load(pgKey)
	if !ok {
		// Port group doesn't exist
		return fmt.Errorf("port groups for ns %s don't exist", np.namespace)
	}

	ingressDenyPorts, egressDenyPorts := sharedPGs.addPortsForPolicy(np, portNamesToUUIDs)
	// counters were updated, update back to initial values on error
	defer func() {
		if err != nil {
			sharedPGs.deletePortsForPolicy(np, portNamesToUUIDs)
		}
	}()

	if len(ingressDenyPorts) != 0 || len(egressDenyPorts) != 0 {
		// db changes required
		ops, err = libovsdbops.AddPortsToPortGroupOps(oc.nbClient, ops, ingressDenyPGName, ingressDenyPorts...)
		if err != nil {
			return fmt.Errorf("unable to get add ports to %s port group ops: %v", ingressDenyPGName, err)
		}

		ops, err = libovsdbops.AddPortsToPortGroupOps(oc.nbClient, ops, egressDenyPGName, egressDenyPorts...)
		if err != nil {
			return fmt.Errorf("unable to get add ports to %s port group ops: %v", egressDenyPGName, err)
		}

		_, err = libovsdbops.TransactAndCheck(oc.nbClient, ops)
		if err != nil {
			return fmt.Errorf("unable to transact add ports to default deny port groups: %v", err)
		}
	}
	return nil
}

// denyPGDeletePorts deletes ports from default deny port groups.
// Set useLocalPods = true, when deleting networkPolicy to remove all its ports from defaultDeny port groups.
func (oc *Controller) denyPGDeletePorts(np *networkPolicy, portNamesToUUIDs map[string]string, useLocalPods bool) error {
	var err error
	var ops []ovsdb.Operation
	if useLocalPods {
		portNamesToUUIDs = map[string]string{}
		np.localPods.Range(func(key, value interface{}) bool {
			portNamesToUUIDs[key.(string)] = value.(string)
			return true
		})
	}
	if len(portNamesToUUIDs) == 0 {
		return nil
	}

	ingressDenyPGName := defaultDenyPortGroupName(np.namespace, ingressDefaultDenySuffix)
	egressDenyPGName := defaultDenyPortGroupName(np.namespace, egressDefaultDenySuffix)

	pgKey := np.namespace
	// this lock guarantees that sharedPortGroup counters will be updated atomically
	// with adding port to port group in db.
	oc.sharedNetpolPortGroups.LockKey(pgKey)
	defer oc.sharedNetpolPortGroups.UnlockKey(pgKey)
	sharedPGs, ok := oc.sharedNetpolPortGroups.Load(pgKey)
	if !ok {
		// Port group doesn't exist, nothing to clean up
		klog.Infof("Skip delete ports from default deny port group: port group doesn't exist")
		return nil
	}

	ingressDenyPorts, egressDenyPorts := sharedPGs.deletePortsForPolicy(np, portNamesToUUIDs)
	// counters were updated, update back to initial values on error
	defer func() {
		if err != nil {
			sharedPGs.addPortsForPolicy(np, portNamesToUUIDs)
		}
	}()

	if len(ingressDenyPorts) != 0 || len(egressDenyPorts) != 0 {
		// db changes required
		ops, err = libovsdbops.DeletePortsFromPortGroupOps(oc.nbClient, ops, ingressDenyPGName, ingressDenyPorts...)
		if err != nil {
			return fmt.Errorf("unable to get del ports from %s port group ops: %v", ingressDenyPGName, err)
		}

		ops, err = libovsdbops.DeletePortsFromPortGroupOps(oc.nbClient, ops, egressDenyPGName, egressDenyPorts...)
		if err != nil {
			return fmt.Errorf("unable to get del ports from %s port group ops: %v", egressDenyPGName, err)
		}
		_, err = libovsdbops.TransactAndCheck(oc.nbClient, ops)
		if err != nil {
			return fmt.Errorf("unable to transact del ports from default deny port groups: %v", err)
		}
	}
	return nil
}

// handleLocalPodSelectorAddFunc adds a new pod to an existing NetworkPolicy, should be retriable.
// ignoreErr=true should only be used for initial objects handling, relying on per-object handlers to retry.
func (oc *Controller) handleLocalPodSelectorAddFunc(np *networkPolicy, ignoreErr bool, objs ...interface{}) error {
	np.RLock()
	defer np.RUnlock()
	if np.deleted {
		return nil
	}
	// get info for new pods that are not listed in np.localPods
	portNamesToUUIDs, policyPortUUIDs, errPods := oc.getNewLocalPolicyPorts(np, objs...)

	if len(portNamesToUUIDs) > 0 {
		var err error
		// add pods to policy port group
		var ops []ovsdb.Operation
		ops, err = libovsdbops.AddPortsToPortGroupOps(oc.nbClient, nil, np.portGroupName, policyPortUUIDs...)
		if err != nil {
			return fmt.Errorf("unable to get ops to add new pod to policy port group: %v", err)
		}
		_, err = libovsdbops.TransactAndCheck(oc.nbClient, ops)
		if err != nil {
			return fmt.Errorf("unable to transact add new pod to policy port group: %v", err)
		}
		// add pods to default deny port group
		// make sure to only pass newly added pods
		if err = oc.denyPGAddPorts(np, portNamesToUUIDs); err != nil {
			// we don't need to delete policy ports from policy port group,
			// because adding ports to port group is idempotent and can be retried
			return fmt.Errorf("unable to add new pod to default deny port group: %v", err)
		}
		// all operations were successful, update np.localPods
		for portName, portUUID := range portNamesToUUIDs {
			np.localPods.Store(portName, portUUID)
		}
	}

	if !ignoreErr && len(errPods) > 0 {
		pod := errPods[0].(*kapi.Pod)
		return fmt.Errorf("unable to get port info for pod %s/%s", pod.Namespace, pod.Name)
	}

	return nil
}

// handleLocalPodSelectorDelFunc handles delete event for local pod, should be retriable
func (oc *Controller) handleLocalPodSelectorDelFunc(np *networkPolicy, objs ...interface{}) error {
	np.RLock()
	defer np.RUnlock()
	if np.deleted {
		return nil
	}

	portNamesToUUIDs, policyPortUUIDs, errPods := oc.getExistingLocalPolicyPorts(np, objs...)

	if len(portNamesToUUIDs) > 0 {
		var err error
		// del pods from policy port group
		var ops []ovsdb.Operation
		ops, err = libovsdbops.DeletePortsFromPortGroupOps(oc.nbClient, nil, np.portGroupName, policyPortUUIDs...)
		if err != nil {
			return fmt.Errorf("unable to get ops to add new pod to policy port group: %v", err)
		}
		_, err = libovsdbops.TransactAndCheck(oc.nbClient, ops)
		if err != nil {
			return fmt.Errorf("unable to transact add new pod to policy port group: %v", err)
		}
		// delete pods from default deny port group
		if err = oc.denyPGDeletePorts(np, portNamesToUUIDs, false); err != nil {
			// we don't need to add policy ports back to policy port group,
			// because delete ports from port group is idempotent and can be retried
			return fmt.Errorf("unable to add new pod to default deny port group: %v", err)
		}
		// all operations were successful, update np.localPods
		for portName := range portNamesToUUIDs {
			np.localPods.Delete(portName)
		}
	}

	if len(errPods) > 0 {
		pod := errPods[0].(*kapi.Pod)
		return fmt.Errorf("unable to get port info for pod %s/%s", pod.Namespace, pod.Name)
	}
	return nil
}

func (oc *Controller) addLocalPodHandler(policy *knet.NetworkPolicy, np *networkPolicy,
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
			np: np,
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

type policyHandler struct {
	gress             *gressPolicy
	namespaceSelector *metav1.LabelSelector
	podSelector       *metav1.LabelSelector
}

// createNetworkPolicy creates a network policy, should be retriable
// if network policy with given key exists, it will try to clean it up first, and return an error if it fails
func (oc *Controller) createNetworkPolicy(policy *knet.NetworkPolicy, aclLogging *ACLLoggingLevels) (*networkPolicy, error) {
	npKey := getPolicyKey(policy)
	var np *networkPolicy

	err := oc.networkPolicies.DoWithLock(npKey, func(npKey string) error {
		oldNP, found := oc.networkPolicies.Load(npKey)
		if found {
			cleanupErr := oc.cleanupNetworkPolicy(oldNP)
			return fmt.Errorf("cleanup for retrying network policy create failed: %v", cleanupErr)
		}
		np, found = oc.networkPolicies.LoadOrStore(npKey, NewNetworkPolicy(policy))
		if found {
			// that should never happen, because successful cleanup will delete np from oc.networkPolicies
			return fmt.Errorf("network policy is found in the system, "+
				"while it should've been cleaned up, obj: %+v", np)
		}
		np.Lock()

		if aclLogging.Deny != "" || aclLogging.Allow != "" {
			klog.Infof("ACL logging for network policy %s in namespace %s set to deny=%s, allow=%s",
				policy.Name, policy.Namespace, aclLogging.Deny, aclLogging.Allow)
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

		// Add policy to defaultDeny port groups
		// Create port groups if they don't exist for given namespace
		err = oc.addPolicyToDefaultPortGroups(np, aclLogging)
		if err != nil {
			return err
		}

		// Add a handler to update the policy and deny port groups with the pods
		// this policy applies to.
		// Handle initial items locally to minimize DB ops.
		handleInitialSelectedPods := func(objs []interface{}) error {
			// get info for new pods that are not listed in np.localPods
			portNamesToUUIDs, policyPortUUIDs, _ := oc.getNewLocalPolicyPorts(np, objs...)
			pg.Ports = append(pg.Ports, policyPortUUIDs...)
			// add pods to default deny port group
			// make sure to only pass newly added pods
			if err = oc.denyPGAddPorts(np, portNamesToUUIDs); err != nil {
				// we don't need to delete policy ports from policy port group,
				// because adding ports to port group is idempotent and can be retried
				return fmt.Errorf("unable to add new pod to default deny port group: %v", err)
			}
			// all operations were successful, update np.localPods
			for portName, portUUID := range portNamesToUUIDs {
				np.localPods.Store(portName, portUUID)
			}
			return nil
		}
		err = oc.addLocalPodHandler(policy, np, handleInitialSelectedPods)
		if err != nil {
			return fmt.Errorf("failed to handle local pod selector: %v", err)
		}

		np.Lock()
		defer np.Unlock()
		if np.deleted {
			_ = oc.denyPGDeletePorts(np, nil, true)
			return nil
		}

		ops, err = libovsdbops.CreateOrUpdatePortGroupsOps(oc.nbClient, ops, pg)
		if err != nil {
			_ = oc.denyPGDeletePorts(np, nil, true)
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
			_ = oc.denyPGDeletePorts(np, nil, true)
			return fmt.Errorf("failed to run ovsdb txn to add ports to port group: %v", err)
		}
		txOkCallBack()
		return nil
	})
	return np, err
}

// addNetworkPolicy creates and applies OVN ACLs to pod logical switch
// ports from Kubernetes NetworkPolicy objects using OVN Port Groups
// if addNetworkPolicy fails, create or delete operation can be retried
func (oc *Controller) addNetworkPolicy(policy *knet.NetworkPolicy) error {
	klog.Infof("Adding network policy %s in namespace %s", policy.Name,
		policy.Namespace)

	// To not hold nsLock for the whole process on network policy creation, we do the following:
	// 1. save required namespace information to use for netpol create
	// 2. create network policy without ns Lock
	// 3. lock namespace
	// 4. check if namespace information related to network policy has changed, run the same function as on namespace update
	// 5. subscribe to namespace update events
	// 6. unlock namespace

	// 1. save required namespace information to use for netpol create,
	nsInfo, nsUnlock := oc.getNamespaceLocked(policy.Namespace, true)
	if nsInfo == nil {
		return fmt.Errorf("unable to get namespace %s for network policy %s: namespace doesn't exist",
			policy.Namespace, policy.Name)
	}
	aclLogging := nsInfo.aclLogging
	nsUnlock()

	// 2. create network policy without ns Lock, cleanup on failure
	npKey := getPolicyKey(policy)
	var np *networkPolicy
	var err error

	np, err = oc.createNetworkPolicy(policy, &aclLogging)
	defer func() {
		if err != nil {
			// try to cleanup network policy straight away
			// it will be retried later with add/delete network policy handlers if it fails
			cleanupErr := oc.networkPolicies.DoWithLock(npKey, func(npKey string) error {
				np, ok := oc.networkPolicies.Load(npKey)
				if !ok {
					klog.Infof("Deleting policy %s/%s that is already deleted", policy.Namespace, policy.Name)
					return nil
				}
				return oc.cleanupNetworkPolicy(np)
			})
			if cleanupErr != nil {
				klog.Infof("Cleanup for failed create network policy %s/%s returned an error: %v",
					policy.Namespace, policy.Name, cleanupErr)
			}
		}
	}()
	if err != nil {
		return fmt.Errorf("failed to create Network Policy %s/%s: %v",
			policy.Namespace, policy.Name, err)
	}

	// 3. lock namespace
	nsInfo, nsUnlock = oc.getNamespaceLocked(policy.Namespace, false)
	if nsInfo == nil {
		// namespace was deleted while we were adding network policy,
		// try to cleanup network policy
		// expect retry to be handled by delete event that should come
		err = fmt.Errorf("unable to get namespace %s at the end of network policy %s creation: %v",
			policy.Namespace, policy.Name, err)
		return err
	}
	// 6. defer unlock namespace
	defer nsUnlock()

	// 4. check if namespace information related to network policy has changed,
	// network policy only reacts to namespace update ACL log level.
	// Run handleNetPolNamespaceUpdate sequence, but only for 1 newly added policy.
	if nsInfo.aclLogging.Deny != aclLogging.Deny {
		if err := oc.updateACLLoggingForDefaultACLs(policy.Namespace, nsInfo); err != nil {
			klog.Warningf(err.Error())
		} else {
			klog.Infof("Policy %s: ACL logging setting updated to deny=%s allow=%s",
				getPolicyKey(policy), nsInfo.aclLogging.Deny, nsInfo.aclLogging.Allow)
		}
	}
	if nsInfo.aclLogging.Allow != aclLogging.Allow {
		if err := oc.updateACLLoggingForPolicy(np, &nsInfo.aclLogging); err != nil {
			klog.Warningf(err.Error())
		} else {
			klog.Infof("Policy %s: ACL logging setting updated to deny=%s allow=%s",
				getPolicyKey(policy), nsInfo.aclLogging.Deny, nsInfo.aclLogging.Allow)
		}
	}

	// 5. subscribe to namespace update events
	nsInfo.relatedNetworkPolicies[npKey] = true
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
// It only uses Namespace and Name from given network policy
func (oc *Controller) deleteNetworkPolicy(policy *knet.NetworkPolicy) error {
	klog.Infof("Deleting network policy %s in namespace %s", policy.Name, policy.Namespace)

	npKey := getPolicyKey(policy)
	// First lock and update namespace
	nsInfo, nsUnlock := oc.getNamespaceLocked(policy.Namespace, false)
	if nsInfo != nil {
		// unsubscribe from namespace events
		delete(nsInfo.relatedNetworkPolicies, npKey)
		nsUnlock()
	}
	// Next cleanup network policy
	err := oc.networkPolicies.DoWithLock(npKey, func(npKey string) error {
		np, ok := oc.networkPolicies.Load(npKey)
		if !ok {
			klog.Infof("Deleting policy that is already deleted")
			return nil
		}
		return oc.cleanupNetworkPolicy(np)
	})
	return err
}

// cleanupNetworkPolicy should be retriable
// it takes and releases networkPolicy lock
// it updates oc.networkPolicies on success, should be called with oc.networkPolicies key locked
func (oc *Controller) cleanupNetworkPolicy(np *networkPolicy) error {
	np.Lock()
	defer np.Unlock()
	np.deleted = true
	oc.shutdownHandlers(np)
	var err error

	err = oc.denyPGDeletePorts(np, nil, true)
	if err != nil {
		return fmt.Errorf("unable to delete ports from defaultDeny port group: %v", err)
	}

	err = oc.delPolicyFromDefaultPortGroups(np)
	if err != nil {
		return fmt.Errorf("unable to delete policy from default deny port groups: %v", err)
	}

	// Delete the port group, idempotent
	ops, err := libovsdbops.DeletePortGroupsOps(oc.nbClient, nil, np.portGroupName)
	if err != nil {
		return fmt.Errorf("failed to make delete network policy port group ops, policy: %s/%s, group name: %s,"+
			" error: %v", np.namespace, np.name, np.portGroupName, err)
	}
	recordOps, txOkCallBack, _, err := metrics.GetConfigDurationRecorder().AddOVN(oc.nbClient, "networkpolicy",
		np.namespace, np.name)
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

	// finally, delete netpol from existing networkPolicies
	// this is the signal that cleanup was successful
	oc.networkPolicies.Delete(np.getKey())
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
	np          *networkPolicy
	gp          *gressPolicy
	podSelector labels.Selector
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

// The following 2 function should return the same key for network policy based on k8s on internal networkPolicy object
func getPolicyKey(policy *knet.NetworkPolicy) string {
	return fmt.Sprintf("%v/%v", policy.Namespace, policy.Name)
}

func (np *networkPolicy) getKey() string {
	return fmt.Sprintf("%v/%v", np.namespace, np.name)
}
