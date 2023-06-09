package adminnetworkpolicy

import (
	"fmt"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	libovsdbops "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	libovsdbutil "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/util"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	addressset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/address_set"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	anpapi "sigs.k8s.io/network-policy-api/apis/v1alpha1"
)

var ErrorANPPriorityUnsupported = errors.New("OVNK only supports priority ranges 0-99")
var ErrorANPWithDuplicatePriority = errors.New("exists with the same priority")

// getPortProtocol returns the OVN syntax-specific protocol value for a v1.Protocol K8s type
func getPortProtocol(proto v1.Protocol) string {
	var protocol string
	switch proto {
	case v1.ProtocolTCP:
		protocol = "tcp"
	case v1.ProtocolSCTP:
		protocol = "sctp"
	case v1.ProtocolUDP:
		protocol = "udp"
	}
	return protocol
}

// getAdminNetworkPolicyPGName will return the hashed name and provided anp name as the port group name
func getAdminNetworkPolicyPGName(name string) (hashedPGName, readablePGName string) {
	readablePortGroupName := fmt.Sprintf("ANP:%s", name)
	return util.HashForOVN(readablePortGroupName), readablePortGroupName
}

// getANPRuleACLDbIDs will return the dbObjectIDs for a given rule's ACLs
func getANPRuleACLDbIDs(name, gressPrefix, gressIndex, controller string) *libovsdbops.DbObjectIDs {
	idType := libovsdbops.ACLAdminNetworkPolicy
	return libovsdbops.NewDbObjectIDs(idType, controller, map[libovsdbops.ExternalIDKey]string{
		libovsdbops.ObjectNameKey:      name,
		libovsdbops.PolicyDirectionKey: gressPrefix,
		// gressidx is the unique id for address set within given objectName and gressPrefix
		libovsdbops.GressIdxKey: gressIndex,
	})
}

// getACLActionForANPRule returns the corresponding OVN ACL action for a given ANP rule action
func getACLActionForANPRule(action anpapi.AdminNetworkPolicyRuleAction) string {
	var ovnACLAction string
	switch action {
	case anpapi.AdminNetworkPolicyRuleActionAllow:
		ovnACLAction = nbdb.ACLActionAllowRelated
	case anpapi.AdminNetworkPolicyRuleActionDeny:
		ovnACLAction = nbdb.ACLActionDrop
	case anpapi.AdminNetworkPolicyRuleActionPass:
		ovnACLAction = nbdb.ACLActionPass
	default:
		panic(fmt.Sprintf("Failed to build ANP ACL: unknown acl action %s", action))
	}
	return ovnACLAction
}

// GetANPPeerAddrSetDbIDs will return the dbObjectIDs for a given rule's address-set
func GetANPPeerAddrSetDbIDs(name, gressPrefix, gressIndex, controller string) *libovsdbops.DbObjectIDs {
	idType := libovsdbops.AddressSetAdminNetworkPolicy
	return libovsdbops.NewDbObjectIDs(idType, controller, map[libovsdbops.ExternalIDKey]string{
		libovsdbops.ObjectNameKey:      name,
		libovsdbops.PolicyDirectionKey: gressPrefix,
		// gressidx is the unique id for address set within given objectName and gressPrefix
		libovsdbops.GressIdxKey: gressIndex,
	})
}

// constructMatchFromAddressSet returns the L3Match for an ACL constructed from a gressRule
func constructMatchFromAddressSet(gressPrefix string, addrSetIndex *libovsdbops.DbObjectIDs) string {
	hashedAddressSetNameIPv4, hashedAddressSetNameIPv6 := addressset.GetHashNamesForAS(addrSetIndex)
	var direction, match string
	if gressPrefix == string(libovsdbutil.ACLIngress) {
		direction = "src"
	} else {
		direction = "dst"
	}

	switch {
	case config.IPv4Mode && config.IPv6Mode:
		match = fmt.Sprintf("(ip4.%s == $%s || ip6.%s == $%s)", direction, hashedAddressSetNameIPv4, direction, hashedAddressSetNameIPv6)
	case config.IPv4Mode:
		match = fmt.Sprintf("(ip4.%s == $%s)", direction, hashedAddressSetNameIPv4)
	case config.IPv6Mode:
		match = fmt.Sprintf("(ip6.%s == $%s)", direction, hashedAddressSetNameIPv6)
	}

	return fmt.Sprintf("(%s)", match)
}

// constructMatchFromPorts returns the L4Match for an ACL constructed from a gressRule
func constructMatchFromPorts(port *adminNetworkPolicyPort) string {
	if port.endPort != 0 && port.endPort != port.port {
		return fmt.Sprintf("(%s && %d<=%s.dst<=%d)", port.protocol, port.port, port.protocol, port.endPort)

	} else if port.port != 0 {
		return fmt.Sprintf("(%s && %s.dst==%d)", port.protocol, port.protocol, port.port)
	}
	return fmt.Sprintf("(%s)", port.protocol)
}
