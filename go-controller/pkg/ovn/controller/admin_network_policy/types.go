package adminnetworkpolicy

import (
	libovsdbutil "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/util"
	"github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	anpapi "sigs.k8s.io/network-policy-api/apis/v1alpha1"
)

// NOTE: Iteration v1 of ANP will only support upto 100 ANPs
// We will use priority range from 30000 (0) to 20000 (99) ACLs (both inclusive, note that these ACLs will be in tier1)
// In order to support more in the future, we will need to fix priority range in OVS
// See https://bugzilla.redhat.com/show_bug.cgi?id=2175752 for more details.
// NOTE: A cluster can have only BANP at a given time as defined by upstream KEP.
const (
	ANPFlowStartPriority            = 30000
	ANPMaxRulesPerObject            = 100
	ANPExternalIDKey                = "AdminNetworkPolicy"         // key set on port-groups to identify which ANP it belongs to
	ovnkSupportedPriorityUpperBound = 99                           // corresponds to 20100 ACL priority
	BANPFlowPriority                = 1750                         // down to 1651 (both inclusive, note that these ACLs will be in tier3)
	BANPExternalIDKey               = "BaselineAdminNetworkPolicy" // key set on port-groups to identify which BANP it belongs to
)

// TODO: Double check how empty selector means all labels match works
type adminNetworkPolicySubject struct {
	namespaceSelector labels.Selector
	podSelector       labels.Selector
	// map of namespaces matching the provided namespaceSelector
	// {K: namespace name; V: {set of pods matching the provided podSelector}}
	namespaces map[string]sets.Set[string]
	// all the LSP port UUIDs of the subject pods selected by this ANP
	// Since nbdb.PortGroup.LSP stores the UUIDs of the LSP's storing it
	// in the cache makes it easier to compute the difference between
	// current set of UUIDs and desired set of UUIDs and do one set of
	// transact ops calculation. If not, for every pod/namespace update
	// we would need to do a lookup in the libovsdb cache for the ns_name
	// LSP index. TODO(tssurya): Do performance runs to see if there is
	// effect on MEM footprint for storing this information.
	podPorts sets.Set[string]
}

// TODO: Implement sameLabels & notSameLabels
type adminNetworkPolicyPeer struct {
	namespaceSelector labels.Selector
	podSelector       labels.Selector
	// map of namespaces matching the provided namespaceSelector
	// {K: namespace name; V: {set of pods matching the provided podSelector}}
	namespaces map[string]sets.Set[string]
}

type adminNetworkPolicyPort struct {
	protocol string
	port     int32 // will store startPort if its a range
	endPort  int32
}

type gressRule struct {
	name string
	// priority is determined based on order in the list and calculated using adminNetworkPolicyState.priority
	priority int32
	// gressIndex tracks the index of this rule
	gressIndex  int32
	gressPrefix string
	// NOTE: Action here is the corresponding OVN action for
	// anpapi.AdminNetworkPolicyRuleAction
	action string
	peers  []*adminNetworkPolicyPeer
	ports  []*adminNetworkPolicyPort
	// all the podIPs of the peer pods selected by this ANP Rule
	podIPs sets.Set[string]
}

// adminNetworkPolicyState is the cache that keeps the state of a single
// admin network policy in the cluster with name being unique
type adminNetworkPolicyState struct {
	// name of the admin network policy (unique across cluster)
	name string
	// priority is the OVN priority equivalent of anp.Spec.Priority
	priority int32
	// subject stores the objects needed to track .Spec.Subject changes
	subject *adminNetworkPolicySubject
	// ingressRules stores the objects needed to track .Spec.Ingress changes
	ingressRules []*gressRule
	// egressRules stores the objects needed to track .Spec.Egress changes
	egressRules []*gressRule
}

// newAdminNetworkPolicyState takes the provided ANP API object and creates a new corresponding
// adminNetworkPolicyState cache object for that API object.
func newAdminNetworkPolicyState(raw *anpapi.AdminNetworkPolicy) (*adminNetworkPolicyState, error) {
	anp := &adminNetworkPolicyState{
		name:         raw.Name,
		priority:     (ANPFlowStartPriority - raw.Spec.Priority*ANPMaxRulesPerObject),
		ingressRules: make([]*gressRule, 0),
		egressRules:  make([]*gressRule, 0),
	}
	var err error
	anp.subject, err = newAdminNetworkPolicySubject(raw.Spec.Subject)
	if err != nil {
		return nil, err
	}

	addErrors := errors.New("")
	for i, rule := range raw.Spec.Ingress {
		anpRule, err := newAdminNetworkPolicyIngressRule(rule, int32(i), anp.priority-int32(i))
		if err != nil {
			addErrors = errors.Wrapf(addErrors, "error: cannot create anp ingress Rule %d in ANP %s - %v",
				i, raw.Name, err)
			continue
		}
		anp.ingressRules = append(anp.ingressRules, anpRule)
	}
	for i, rule := range raw.Spec.Egress {
		anpRule, err := newAdminNetworkPolicyEgressRule(rule, int32(i), anp.priority-int32(i))
		if err != nil {
			addErrors = errors.Wrapf(addErrors, "error: cannot create anp egress Rule %d in ANP %s - %v",
				i, raw.Name, err)
			continue
		}
		anp.egressRules = append(anp.egressRules, anpRule)
	}

	if addErrors.Error() == "" {
		addErrors = nil
	}
	return anp, addErrors
}

// newAdminNetworkPolicySubject takes the provided ANP API Subject and creates a new corresponding
// adminNetworkPolicySubject cache object for that Subject.
func newAdminNetworkPolicySubject(raw anpapi.AdminNetworkPolicySubject) (*adminNetworkPolicySubject, error) {
	var subject *adminNetworkPolicySubject

	if raw.Namespaces != nil {
		subjectNamespaceSelector, err := metav1.LabelSelectorAsSelector(raw.Namespaces)
		if err != nil {
			return nil, err
		}
		if !subjectNamespaceSelector.Empty() {
			subject = &adminNetworkPolicySubject{
				namespaceSelector: subjectNamespaceSelector,
				podSelector:       labels.Everything(), // it means match all pods within the provided namespaces
			}
		} else {
			subject = &adminNetworkPolicySubject{
				namespaceSelector: labels.Everything(), // it means match all namespaces in the cluster
				podSelector:       labels.Everything(), // it means match all pods within the provided namespaces
			}
		}
	} else if raw.Pods != nil {
		// anp.Spec.Subject.Namespaces is not set; anp.Spec.Subject.Pods is set instead
		subjectNamespaceSelector, err := metav1.LabelSelectorAsSelector(&raw.Pods.NamespaceSelector)
		if err != nil {
			return nil, err
		}
		subjectPodSelector, err := metav1.LabelSelectorAsSelector(&raw.Pods.PodSelector)
		if err != nil {
			return nil, err
		}
		subject = &adminNetworkPolicySubject{
			namespaceSelector: subjectNamespaceSelector,
			podSelector:       subjectPodSelector,
		}
	}
	return subject, nil
}

// newAdminNetworkPolicyPort takes the provided ANP API Port and creates a new corresponding
// adminNetworkPolicyPort cache object for that Port.
func newAdminNetworkPolicyPort(raw anpapi.AdminNetworkPolicyPort) *adminNetworkPolicyPort {
	anpPort := adminNetworkPolicyPort{}
	if raw.PortNumber != nil {
		anpPort.protocol = getPortProtocol(raw.PortNumber.Protocol)
		anpPort.port = raw.PortNumber.Port
	} else if raw.NamedPort != nil {
		// TODO: Add support for this
	} else {
		anpPort.protocol = getPortProtocol(raw.PortRange.Protocol)
		anpPort.port = raw.PortRange.Start
		anpPort.port = raw.PortRange.End
	}
	return &anpPort
}

// newAdminNetworkPolicyPeer takes the provided ANP API Peer and creates a new corresponding
// adminNetworkPolicyPeer cache object for that Peer.
func newAdminNetworkPolicyPeer(raw anpapi.AdminNetworkPolicyPeer) (*adminNetworkPolicyPeer, error) {
	var anpPeer *adminNetworkPolicyPeer
	if raw.Namespaces != nil {
		peerNamespaceSelector, err := metav1.LabelSelectorAsSelector(raw.Namespaces.NamespaceSelector)
		if err != nil {
			return nil, err
		}
		if !peerNamespaceSelector.Empty() {
			anpPeer = &adminNetworkPolicyPeer{
				namespaceSelector: peerNamespaceSelector,
				// TODO: See if it makes sense to just use the namespace address-sets we have in case the podselector is empty meaning all pods.
				podSelector: labels.Everything(), // it means match all pods within the provided namespaces
			}
		} else {
			anpPeer = &adminNetworkPolicyPeer{
				namespaceSelector: labels.Everything(), // it means match all namespaces in the cluster
				// TODO: See if it makes sense to just use the namespace address-sets we have in case the podselector is empty meaning all pods.
				podSelector: labels.Everything(), // it means match all pods within the provided namespaces
			}
		}
	} else if raw.Pods != nil {
		peerNamespaceSelector, err := metav1.LabelSelectorAsSelector(raw.Pods.Namespaces.NamespaceSelector)
		if err != nil {
			return nil, err
		}
		if peerNamespaceSelector.Empty() {
			peerNamespaceSelector = labels.Everything()
		}
		peerPodSelector, err := metav1.LabelSelectorAsSelector(&raw.Pods.PodSelector)
		if err != nil {
			return nil, err
		}
		if peerPodSelector.Empty() {
			peerPodSelector = labels.Everything()
		}
		anpPeer = &adminNetworkPolicyPeer{
			namespaceSelector: peerNamespaceSelector,
			podSelector:       peerPodSelector,
		}
	}
	return anpPeer, nil
}

// newAdminNetworkPolicyIngressRule takes the provided ANP API Ingres Rule and creates a new corresponding
// gressRule cache object for that Rule.
func newAdminNetworkPolicyIngressRule(raw anpapi.AdminNetworkPolicyIngressRule, index, priority int32) (*gressRule, error) {
	anpRule := &gressRule{
		name:        raw.Name,
		priority:    priority,
		gressIndex:  index,
		action:      GetACLActionForANPRule(raw.Action),
		gressPrefix: string(libovsdbutil.ACLIngress),
		peers:       make([]*adminNetworkPolicyPeer, 0),
		ports:       make([]*adminNetworkPolicyPort, 0),
	}
	for _, peer := range raw.From {
		anpPeer, err := newAdminNetworkPolicyPeer(peer)
		if err != nil {
			return nil, err
		}
		anpRule.peers = append(anpRule.peers, anpPeer)
	}
	if raw.Ports != nil {
		for _, port := range *raw.Ports {
			anpPort := newAdminNetworkPolicyPort(port)
			anpRule.ports = append(anpRule.ports, anpPort)
		}
	}

	return anpRule, nil
}

// newAdminNetworkPolicyEgressRule takes the provided ANP API Egres Rule and creates a new corresponding
// gressRule cache object for that Rule.
func newAdminNetworkPolicyEgressRule(raw anpapi.AdminNetworkPolicyEgressRule, index, priority int32) (*gressRule, error) {
	anpRule := &gressRule{
		name:        raw.Name,
		priority:    priority,
		gressIndex:  index,
		action:      GetACLActionForANPRule(raw.Action),
		gressPrefix: string(libovsdbutil.ACLEgress),
		peers:       make([]*adminNetworkPolicyPeer, 0),
		ports:       make([]*adminNetworkPolicyPort, 0),
	}
	for _, peer := range raw.To {
		anpPeer, err := newAdminNetworkPolicyPeer(peer)
		if err != nil {
			return nil, err
		}
		anpRule.peers = append(anpRule.peers, anpPeer)
	}
	if raw.Ports != nil {
		for _, port := range *raw.Ports {
			anpPort := newAdminNetworkPolicyPort(port)
			anpRule.ports = append(anpRule.ports, anpPort)
		}
	}
	return anpRule, nil
}

// newBaselineAdminNetworkPolicyState takes the provided BANP API object and creates a new corresponding
// adminNetworkPolicyState cache object for that API object.
func newBaselineAdminNetworkPolicyState(raw *anpapi.BaselineAdminNetworkPolicy) (*adminNetworkPolicyState, error) {
	banp := &adminNetworkPolicyState{
		name:         raw.Name,
		priority:     BANPFlowPriority,
		ingressRules: make([]*gressRule, 0),
		egressRules:  make([]*gressRule, 0),
	}
	var err error
	banp.subject, err = newAdminNetworkPolicySubject(raw.Spec.Subject)
	if err != nil {
		return nil, err
	}
	addErrors := errors.New("")
	for i, rule := range raw.Spec.Ingress {
		banpRule, err := newBaselineAdminNetworkPolicyIngressRule(rule, int32(i), BANPFlowPriority-int32(i))
		if err != nil {
			addErrors = errors.Wrapf(addErrors, "error: cannot create banp ingress Rule %d in ANP %s - %v",
				i, raw.Name, err)
			continue
		}
		banp.ingressRules = append(banp.ingressRules, banpRule)
	}
	for i, rule := range raw.Spec.Egress {
		banpRule, err := newBaselineAdminNetworkPolicyEgressRule(rule, int32(i), BANPFlowPriority-int32(i))
		if err != nil {
			addErrors = errors.Wrapf(addErrors, "error: cannot create banp egress Rule %d in ANP %s - %v",
				i, raw.Name, err)
			continue
		}
		banp.egressRules = append(banp.egressRules, banpRule)
	}

	if addErrors.Error() == "" {
		addErrors = nil
	}
	return banp, addErrors
}

// newBaselineAdminNetworkPolicyIngressRule takes the provided BANP API Ingress Rule and creates a new corresponding
// gressRule cache object for that Rule.
func newBaselineAdminNetworkPolicyIngressRule(raw anpapi.BaselineAdminNetworkPolicyIngressRule, index, priority int32) (*gressRule, error) {
	banpRule := &gressRule{
		name:        raw.Name,
		priority:    priority,
		gressIndex:  index,
		action:      GetACLActionForBANPRule(raw.Action),
		gressPrefix: string(libovsdbutil.ACLIngress),
		peers:       make([]*adminNetworkPolicyPeer, 0),
		ports:       make([]*adminNetworkPolicyPort, 0),
	}
	for _, peer := range raw.From {
		anpPeer, err := newAdminNetworkPolicyPeer(peer)
		if err != nil {
			return nil, err
		}
		banpRule.peers = append(banpRule.peers, anpPeer)
	}
	if raw.Ports != nil {
		for _, port := range *raw.Ports {
			anpPort := newAdminNetworkPolicyPort(port)
			banpRule.ports = append(banpRule.ports, anpPort)
		}
	}

	return banpRule, nil
}

// newBaselineAdminNetworkPolicyEgressRule takes the provided BANP API Egress Rule and creates a new corresponding
// gressRule cache object for that Rule.
func newBaselineAdminNetworkPolicyEgressRule(raw anpapi.BaselineAdminNetworkPolicyEgressRule, index, priority int32) (*gressRule, error) {
	banpRule := &gressRule{
		name:        raw.Name,
		priority:    priority,
		gressIndex:  index,
		action:      GetACLActionForBANPRule(raw.Action),
		gressPrefix: string(libovsdbutil.ACLEgress),
		peers:       make([]*adminNetworkPolicyPeer, 0),
		ports:       make([]*adminNetworkPolicyPort, 0),
	}
	for _, peer := range raw.To {
		banpPeer, err := newAdminNetworkPolicyPeer(peer)
		if err != nil {
			return nil, err
		}
		banpRule.peers = append(banpRule.peers, banpPeer)
	}
	if raw.Ports != nil {
		for _, port := range *raw.Ports {
			banpPort := newAdminNetworkPolicyPort(port)
			banpRule.ports = append(banpRule.ports, banpPort)
		}
	}
	return banpRule, nil
}
