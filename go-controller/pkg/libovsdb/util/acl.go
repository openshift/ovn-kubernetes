package util

import (
	"fmt"
	"strings"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	libovsdbops "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	knet "k8s.io/api/networking/v1"
)

// aclPipelineType defines when ACLs will be applied (direction and pipeline stage).
// All acls of the same type will be sorted by priority, priorities for different types are independent.
type ACLPipelineType string

const (
	// LportIngress will be converted to direction="to-lport" ACL
	LportIngress ACLPipelineType = "to-lport"
	// LportEgressAfterLB will be converted to direction="from-lport", options={"apply-after-lb": "true"} ACL
	LportEgressAfterLB ACLPipelineType = "from-lport-after-lb"
)

func PolicyTypeToAclPipeline(policyType knet.PolicyType) ACLPipelineType {
	switch policyType {
	case knet.PolicyTypeEgress:
		return LportEgressAfterLB
	case knet.PolicyTypeIngress:
		return LportIngress
	default:
		panic(fmt.Sprintf("Failed to convert PolicyType to aclPipelineType: unknown policyType type %s", policyType))
	}
}

type ACLDirection string

const (
	ACLEgress  ACLDirection = "Egress"
	ACLIngress ACLDirection = "Ingress"
)

func ACLDirectionToACLPipeline(aclDir ACLDirection) ACLPipelineType {
	switch aclDir {
	case ACLEgress:
		return LportEgressAfterLB
	case ACLIngress:
		return LportIngress
	default:
		panic(fmt.Sprintf("Failed to convert ACLDirection to aclPipelineType: unknown ACLDirection type %s", aclDir))
	}
}

// hash the provided input to make it a valid portGroup name.
func HashedPortGroup(s string) string {
	return util.HashForOVN(s)
}

func JoinACLName(substrings ...string) string {
	return strings.Join(substrings, "_")
}

// acl.Name is cropped to 64 symbols and is used for logging.
// currently only egress firewall, gress network policy and default deny network policy ACLs are logged.
// Other ACLs don't need a name.
// Just a namespace name may be 63 symbols long, therefore some information may be cropped.
// Therefore, "feature" as "EF" for EgressFirewall and "NP" for network policy goes first, then namespace,
// then acl-related info.
func GetACLName(dbIDs *libovsdbops.DbObjectIDs) string {
	t := dbIDs.GetIDsType()
	aclName := ""
	switch {
	case t.IsSameType(libovsdbops.ACLNetworkPolicy):
		aclName = "NP:" + dbIDs.GetObjectID(libovsdbops.ObjectNameKey) + ":" + dbIDs.GetObjectID(libovsdbops.PolicyDirectionKey) +
			":" + dbIDs.GetObjectID(libovsdbops.GressIdxKey)
	case t.IsSameType(libovsdbops.ACLNetpolNamespace):
		aclName = "NP:" + dbIDs.GetObjectID(libovsdbops.ObjectNameKey) + ":" + dbIDs.GetObjectID(libovsdbops.PolicyDirectionKey)
	case t.IsSameType(libovsdbops.ACLEgressFirewall):
		aclName = "EF:" + dbIDs.GetObjectID(libovsdbops.ObjectNameKey) + ":" + dbIDs.GetObjectID(libovsdbops.RuleIndex)
	}
	return fmt.Sprintf("%.63s", aclName)
}

// BuildACL should be used to build ACL instead of directly calling libovsdbops.BuildACL.
// It can properly set and reset log settings for ACL based on ACLLoggingLevels, and
// set acl.Name and acl.ExternalIDs based on given DbIDs
func BuildACL(dbIDs *libovsdbops.DbObjectIDs, priority int, match, action string, logLevels *ACLLoggingLevels,
	aclT ACLPipelineType) *nbdb.ACL {
	var options map[string]string
	var direction string
	switch aclT {
	case LportEgressAfterLB:
		direction = nbdb.ACLDirectionFromLport
		options = map[string]string{
			"apply-after-lb": "true",
		}
	case LportIngress:
		direction = nbdb.ACLDirectionToLport
	default:
		panic(fmt.Sprintf("Failed to build ACL: unknown acl type %s", aclT))
	}
	externalIDs := dbIDs.GetExternalIDs()
	aclName := GetACLName(dbIDs)
	log, logSeverity := getLogSeverity(action, logLevels)
	ACL := libovsdbops.BuildACL(
		aclName,
		direction,
		priority,
		match,
		action,
		types.OvnACLLoggingMeter,
		logSeverity,
		log,
		externalIDs,
		options,
		types.DefaultACLTier,
	)
	return ACL
}

func GetACLMatch(portGroupName, match string, aclDir ACLDirection) string {
	var aclMatch string
	switch aclDir {
	case ACLIngress:
		aclMatch = "outport == @" + portGroupName
	case ACLEgress:
		aclMatch = "inport == @" + portGroupName
	default:
		panic(fmt.Sprintf("Unknown acl direction %s", aclDir))
	}
	if match != "" {
		aclMatch += " && " + match
	}
	return aclMatch
}

// ACL logging severity levels
type ACLLoggingLevels struct {
	Allow string `json:"allow,omitempty"`
	Deny  string `json:"deny,omitempty"`
}

func getLogSeverity(action string, aclLogging *ACLLoggingLevels) (log bool, severity string) {
	severity = ""
	if aclLogging != nil {
		if action == nbdb.ACLActionAllow || action == nbdb.ACLActionAllowRelated || action == nbdb.ACLActionAllowStateless {
			severity = aclLogging.Allow
		} else if action == nbdb.ACLActionDrop || action == nbdb.ACLActionReject {
			severity = aclLogging.Deny
		}
	}
	log = severity != ""
	return log, severity
}

// UpdateACLLoggingWithPredicate finds all ACLs based on a given predicate, updates log settings,
// then transacts these changes with a single transaction.
func UpdateACLLoggingWithPredicate(nbClient libovsdbclient.Client, p func(*nbdb.ACL) bool, aclLogging *ACLLoggingLevels) error {
	ACLs, err := libovsdbops.FindACLsWithPredicate(nbClient, p)
	if err != nil {
		return fmt.Errorf("unable to list ACLs with predicate, err: %v", err)
	}
	return UpdateACLLogging(nbClient, ACLs, aclLogging)
}

func UpdateACLLogging(nbClient libovsdbclient.Client, ACLs []*nbdb.ACL, aclLogging *ACLLoggingLevels) error {
	if len(ACLs) == 0 {
		return nil
	}
	for i := range ACLs {
		log, severity := getLogSeverity(ACLs[i].Action, aclLogging)
		libovsdbops.SetACLLogging(ACLs[i], severity, log)
	}
	ops, err := libovsdbops.UpdateACLsLoggingOps(nbClient, nil, ACLs...)
	if err != nil {
		return fmt.Errorf("unable to get ACL logging ops: %v", err)
	}
	if _, err := libovsdbops.TransactAndCheck(nbClient, ops); err != nil {
		return fmt.Errorf("unable to update ACL logging: %v", err)
	}
	return nil
}
