package ovn

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	v1 "k8s.io/api/core/v1"
	knet "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog"
)

type gressPolicy struct {
	namespace  string
	name       string
	policyType knet.PolicyType
	idx        int

	// portGroupUUID is the UUID of the parent NetworkPolicy port group
	portGroupUUID string
	// portGroupName is the name of the parent NetworkPolicy port group
	portGroupName string

	// peerAddressSet points to the addressSet that holds all peer pod
	// IP addresess.
	peerAddressSet *addressSet

	// nsAddressSets holds the names of all namespace address sets
	nsAddressSets sets.String

	// sortedPeerAddressSets has the sorted peerAddressSets
	sortedPeerAddressSets []string

	// portPolicies represents all the ports to which traffic is allowed for
	// the rule in question.
	portPolicies []*portPolicy

	// ipBlockCidr represents the CIDR from which traffic is allowed
	// except the IP block in the except, which should be dropped.
	ipBlockCidr   []string
	ipBlockExcept []string
}

type portPolicy struct {
	protocol string
	port     int32
}

func (pp *portPolicy) getL4Match() (string, error) {
	if pp.protocol == TCP {
		return fmt.Sprintf("tcp && tcp.dst==%d", pp.port), nil
	} else if pp.protocol == UDP {
		return fmt.Sprintf("udp && udp.dst==%d", pp.port), nil
	} else if pp.protocol == SCTP {
		return fmt.Sprintf("sctp && sctp.dst==%d", pp.port), nil
	}
	return "", fmt.Errorf("unknown port protocol %v", pp.protocol)
}

func newGressPolicy(policyType knet.PolicyType, idx int, namespace, name, portGroupUUID, portGroupName string) *gressPolicy {
	return &gressPolicy{
		namespace:             namespace,
		name:                  name,
		policyType:            policyType,
		idx:                   idx,
		portGroupUUID:         portGroupUUID,
		portGroupName:         portGroupName,
		nsAddressSets:         sets.String{},
		sortedPeerAddressSets: make([]string, 0),
		portPolicies:          make([]*portPolicy, 0),
		ipBlockCidr:           make([]string, 0),
		ipBlockExcept:         make([]string, 0),
	}
}

func (gp *gressPolicy) ensurePeerAddressSet() error {
	if gp.peerAddressSet != nil {
		return nil
	}

	direction := strings.ToLower(string(gp.policyType))
	asName := fmt.Sprintf("%s.%s.%s.%d", gp.namespace, gp.name, direction, gp.idx)
	as, err := NewAddressSet(asName, nil)
	if err != nil {
		return err
	}

	gp.peerAddressSet = as
	gp.sortedPeerAddressSets = append(gp.sortedPeerAddressSets, as.hashName)
	sort.Strings(gp.sortedPeerAddressSets)
	return nil
}

func (gp *gressPolicy) addPortPolicy(portJSON *knet.NetworkPolicyPort) {
	protocol := v1.ProtocolTCP
	if portJSON.Protocol != nil {
		protocol = *portJSON.Protocol
	}
	gp.portPolicies = append(gp.portPolicies, &portPolicy{
		protocol: string(protocol),
		port:     portJSON.Port.IntVal,
	})
}

func (gp *gressPolicy) addIPBlock(ipblockJSON *knet.IPBlock) {
	gp.ipBlockCidr = append(gp.ipBlockCidr, ipblockJSON.CIDR)
	gp.ipBlockExcept = append(gp.ipBlockExcept, ipblockJSON.Except...)
}

func ipMatch() string {
	if config.IPv6Mode {
		return "ip6"
	}
	return "ip4"
}

func (gp *gressPolicy) getL3MatchFromAddressSet() string {
	addressSets := make([]string, 0, len(gp.sortedPeerAddressSets))
	for _, hashName := range gp.sortedPeerAddressSets {
		addressSets = append(addressSets, fmt.Sprintf("$%s", hashName))
	}

	var l3Match string
	if len(addressSets) == 0 {
		l3Match = ipMatch()
	} else {
		addresses := strings.Join(addressSets, ", ")
		if gp.policyType == knet.PolicyTypeIngress {
			l3Match = fmt.Sprintf("%s.src == {%s}", ipMatch(), addresses)
		} else {
			l3Match = fmt.Sprintf("%s.dst == {%s}", ipMatch(), addresses)
		}
	}
	return l3Match
}

func (gp *gressPolicy) getMatchFromIPBlock(lportMatch, l4Match string) string {
	var match string
	ipBlockCidr := fmt.Sprintf("{%s}", strings.Join(gp.ipBlockCidr, ", "))
	if gp.policyType == knet.PolicyTypeIngress {
		if l4Match == noneMatch {
			match = fmt.Sprintf("match=\"%s.src == %s && %s\"",
				ipMatch(), ipBlockCidr, lportMatch)
		} else {
			match = fmt.Sprintf("match=\"%s.src == %s && %s && %s\"",
				ipMatch(), ipBlockCidr, l4Match, lportMatch)
		}
	} else {
		if l4Match == noneMatch {
			match = fmt.Sprintf("match=\"%s.dst == %s && %s\"",
				ipMatch(), ipBlockCidr, lportMatch)
		} else {
			match = fmt.Sprintf("match=\"%s.dst == %s && %s && %s\"",
				ipMatch(), ipBlockCidr, l4Match, lportMatch)
		}
	}
	return match
}

func (gp *gressPolicy) addNamespaceAddressSet(name string) {
	hashName := hashedAddressSet(name)
	if gp.nsAddressSets.Has(hashName) {
		return
	}

	oldL3Match := gp.getL3MatchFromAddressSet()

	gp.nsAddressSets.Insert(hashName)
	gp.sortedPeerAddressSets = append(gp.sortedPeerAddressSets, hashName)
	sort.Strings(gp.sortedPeerAddressSets)

	gp.handlePeerNamespaceSelectorModify(oldL3Match, gp.getL3MatchFromAddressSet())
}

func (gp *gressPolicy) delNamespaceAddressSet(name string) {
	hashName := hashedAddressSet(name)
	if !gp.nsAddressSets.Has(hashName) {
		return
	}

	oldL3Match := gp.getL3MatchFromAddressSet()

	for i, addressSet := range gp.sortedPeerAddressSets {
		if addressSet == hashName {
			gp.sortedPeerAddressSets = append(
				gp.sortedPeerAddressSets[:i],
				gp.sortedPeerAddressSets[i+1:]...)
			break
		}
	}
	gp.nsAddressSets.Delete(hashName)

	gp.handlePeerNamespaceSelectorModify(oldL3Match, gp.getL3MatchFromAddressSet())
}

func (gp *gressPolicy) destroy() {
	gp.peerAddressSet.Destroy()
	gp.peerAddressSet = nil
}

func (gp *gressPolicy) localPodAddACL() {
	l3Match := gp.getL3MatchFromAddressSet()

	var lportMatch, cidrMatch string
	if gp.policyType == knet.PolicyTypeIngress {
		lportMatch = fmt.Sprintf("outport == @%s", gp.portGroupName)
	} else {
		lportMatch = fmt.Sprintf("inport == @%s", gp.portGroupName)
	}

	// If IPBlock CIDR is not empty and except string [] is not empty,
	// add deny acl rule with priority ipBlockDenyPriority (1010).
	if len(gp.ipBlockCidr) > 0 && len(gp.ipBlockExcept) > 0 {
		except := fmt.Sprintf("{%s}", strings.Join(gp.ipBlockExcept, ", "))
		gp.addIPBlockACLDeny(except, ipBlockDenyPriority)
	}

	if len(gp.portPolicies) == 0 {
		match := fmt.Sprintf("match=\"%s && %s\"", l3Match, lportMatch)
		l4Match := noneMatch

		if len(gp.ipBlockCidr) > 0 {
			// Add ACL allow rule for IPBlock CIDR
			cidrMatch = gp.getMatchFromIPBlock(lportMatch, l4Match)
			gp.addACLAllow(cidrMatch, l4Match, true)
		}
		// if there are pod/namespace selector, then allow packets from/to that address_set or
		// if the NetworkPolicyPeer is empty, then allow from all sources or to all destinations.
		if len(gp.sortedPeerAddressSets) > 0 || len(gp.ipBlockCidr) == 0 {
			gp.addACLAllow(match, l4Match, false)
		}
	}
	for _, port := range gp.portPolicies {
		l4Match, err := port.getL4Match()
		if err != nil {
			continue
		}
		match := fmt.Sprintf("match=\"%s && %s && %s\"", l3Match, l4Match, lportMatch)
		if len(gp.ipBlockCidr) > 0 {
			// Add ACL allow rule for IPBlock CIDR
			cidrMatch = gp.getMatchFromIPBlock(lportMatch, l4Match)
			gp.addACLAllow(cidrMatch, l4Match, true)
		}
		if len(gp.sortedPeerAddressSets) > 0 || len(gp.ipBlockCidr) == 0 {
			gp.addACLAllow(match, l4Match, false)
		}
	}
}

func (gp *gressPolicy) addACLAllow(match, l4Match string, ipBlockCidr bool) {
	var direction, action string
	direction = toLport
	if gp.policyType == knet.PolicyTypeIngress {
		action = "allow-related"
	} else {
		action = "allow"
	}

	uuid, stderr, err := util.RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=_uuid", "find", "ACL",
		fmt.Sprintf("external-ids:l4Match=\"%s\"", l4Match),
		fmt.Sprintf("external-ids:ipblock_cidr=%t", ipBlockCidr),
		fmt.Sprintf("external-ids:namespace=%s", gp.namespace),
		fmt.Sprintf("external-ids:policy=%s", gp.name),
		fmt.Sprintf("external-ids:%s_num=%d", gp.policyType, gp.idx),
		fmt.Sprintf("external-ids:policy_type=%s", gp.policyType))
	if err != nil {
		klog.Errorf("find failed to get the allow rule for "+
			"namespace=%s, policy=%s, stderr: %q (%v)",
			gp.namespace, gp.name, stderr, err)
		return
	}

	if uuid != "" {
		return
	}

	_, stderr, err = util.RunOVNNbctl("--id=@acl", "create",
		"acl", fmt.Sprintf("priority=%s", defaultAllowPriority),
		fmt.Sprintf("direction=%s", direction), match,
		fmt.Sprintf("action=%s", action),
		fmt.Sprintf("external-ids:l4Match=\"%s\"", l4Match),
		fmt.Sprintf("external-ids:ipblock_cidr=%t", ipBlockCidr),
		fmt.Sprintf("external-ids:namespace=%s", gp.namespace),
		fmt.Sprintf("external-ids:policy=%s", gp.name),
		fmt.Sprintf("external-ids:%s_num=%d", gp.policyType, gp.idx),
		fmt.Sprintf("external-ids:policy_type=%s", gp.policyType),
		"--", "add", "port_group", gp.portGroupUUID, "acls", "@acl")
	if err != nil {
		klog.Errorf("failed to create the acl allow rule for "+
			"namespace=%s, policy=%s, stderr: %q (%v)", gp.namespace,
			gp.name, stderr, err)
		return
	}
}

func (gp *gressPolicy) modifyACLAllow(oldMatch string, newMatch string) {
	uuid, stderr, err := util.RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=_uuid", "find", "ACL", oldMatch,
		fmt.Sprintf("external-ids:namespace=%s", gp.namespace),
		fmt.Sprintf("external-ids:policy=%s", gp.name),
		fmt.Sprintf("external-ids:%s_num=%d", gp.policyType, gp.idx),
		fmt.Sprintf("external-ids:policy_type=%s", gp.policyType))
	if err != nil {
		klog.Errorf("find failed to get the allow rule for "+
			"namespace=%s, policy=%s, stderr: %q (%v)",
			gp.namespace, gp.name, stderr, err)
		return
	}

	if uuid != "" {
		// We already have an ACL. We will update it.
		_, stderr, err = util.RunOVNNbctl("set", "acl", uuid, newMatch)
		if err != nil {
			klog.Errorf("failed to modify the allow-from rule for "+
				"namespace=%s, policy=%s, stderr: %q (%v)",
				gp.namespace, gp.name, stderr, err)
		}
		return
	}
}

func (gp *gressPolicy) addIPBlockACLDeny(except, priority string) {
	var match, l3Match, direction, lportMatch string
	direction = toLport
	if gp.policyType == knet.PolicyTypeIngress {
		lportMatch = fmt.Sprintf("outport == @%s", gp.portGroupName)
		l3Match = fmt.Sprintf("%s.src == %s", ipMatch(), except)
		match = fmt.Sprintf("match=\"%s && %s\"", lportMatch, l3Match)
	} else {
		lportMatch = fmt.Sprintf("inport == @%s", gp.portGroupName)
		l3Match = fmt.Sprintf("%s.dst == %s", ipMatch(), except)
		match = fmt.Sprintf("match=\"%s && %s\"", lportMatch, l3Match)
	}

	uuid, stderr, err := util.RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=_uuid", "find", "ACL", match, "action=drop",
		fmt.Sprintf("external-ids:ipblock-deny-policy-type=%s", gp.policyType),
		fmt.Sprintf("external-ids:namespace=%s", gp.namespace),
		fmt.Sprintf("external-ids:%s_num=%d", gp.policyType, gp.idx),
		fmt.Sprintf("external-ids:policy=%s", gp.name))
	if err != nil {
		klog.Errorf("find failed to get the ipblock default deny rule for "+
			"namespace=%s, policy=%s stderr: %q, (%v)",
			gp.namespace, gp.name, stderr, err)
		return
	}

	if uuid != "" {
		return
	}

	_, stderr, err = util.RunOVNNbctl("--id=@acl", "create", "acl",
		fmt.Sprintf("priority=%s", priority),
		fmt.Sprintf("direction=%s", direction), match, "action=drop",
		fmt.Sprintf("external-ids:ipblock-deny-policy-type=%s", gp.policyType),
		fmt.Sprintf("external-ids:%s_num=%d", gp.policyType, gp.idx),
		fmt.Sprintf("external-ids:namespace=%s", gp.namespace),
		fmt.Sprintf("external-ids:policy=%s", gp.name),
		"--", "add", "port_group", gp.portGroupUUID,
		"acls", "@acl")
	if err != nil {
		klog.Errorf("error executing create ACL command, stderr: %q, %+v",
			stderr, err)
	}
}

func (gp *gressPolicy) handlePeerNamespaceSelectorModify(oldl3Match, newl3Match string) {
	var lportMatch string
	if gp.policyType == knet.PolicyTypeIngress {
		lportMatch = fmt.Sprintf("outport == @%s", gp.portGroupName)
	} else {
		lportMatch = fmt.Sprintf("inport == @%s", gp.portGroupName)
	}
	if len(gp.portPolicies) == 0 {
		oldMatch := fmt.Sprintf("match=\"%s && %s\"", oldl3Match, lportMatch)
		newMatch := fmt.Sprintf("match=\"%s && %s\"", newl3Match, lportMatch)
		gp.modifyACLAllow(oldMatch, newMatch)
	}
	for _, port := range gp.portPolicies {
		l4Match, err := port.getL4Match()
		if err != nil {
			continue
		}
		oldMatch := fmt.Sprintf("match=\"%s && %s && %s\"", oldl3Match, l4Match, lportMatch)
		newMatch := fmt.Sprintf("match=\"%s && %s && %s\"", newl3Match, l4Match, lportMatch)
		gp.modifyACLAllow(oldMatch, newMatch)
	}
}
