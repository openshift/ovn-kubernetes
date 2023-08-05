package adminnetworkpolicy

import (
	"fmt"
	"strings"
	"time"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/libovsdb/ovsdb"
	libovsdbops "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	libovsdbutil "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/util"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"
	anpapi "sigs.k8s.io/network-policy-api/apis/v1alpha1"
)

// repairAdminNetworkPolicies is called at startup and as the name suggests
// aims to repair the NBDB logical objects -> port groups, acls and address-sets
// that are created for the admin network policies in the cluster
// Logic:
// We fetch all the ANPs present in the cluster from the Lister
// We fetch PGs, ACLs, AddressSets that are owned by ANP objectIDs based on
// externalIDs match from the NBDB. Using predicate search we check if
// the relevant ANP still exists for these objects and if not we delete them
// TODO (tssurya): Handle cleaning up stale IPs in the address-sets by fetching all the relevant
// peer pods that are being served by ANPs - pods could stop matching when ovnkube-controller is down
// TODO2 (tssurya): Handle cleaning up stale ports from PGs by fetching all the relevant
// subject pods that are being served by ANPs - pods could stop matching when ovnkube-controller is down
func (c *Controller) repairAdminNetworkPolicies() error {
	start := time.Now()
	defer func() {
		klog.Infof("Repairing admin network policies took %v", time.Since(start))
	}()
	c.Lock()
	defer c.Unlock()
	anps, err := c.anpLister.List(labels.Everything())
	if err != nil {
		return fmt.Errorf("unable to list ANPs from the lister, err: %v", err)
	}
	existingANPs := map[string]*anpapi.AdminNetworkPolicy{}
	for _, anp := range anps {
		existingANPs[anp.Name] = anp
		// let's populate the anpPriorityMap cache and add the correct ANP at the right priority
		if anp.Spec.Priority > ovnkSupportedPriorityUpperBound {
			// we don't want to add this ANP to the cache since we don't support this priority range
			continue
		}
		ovnPriority := ANPFlowStartPriority - anp.Spec.Priority*ANPMaxRulesPerObject
		status := meta.FindStatusCondition(anp.Status.Conditions, policyReadyStatusType+c.zone)
		if status != nil && strings.Contains(status.Message, "exists with the same priority") {
			// we don't want to add this ANP to the priority cache because this ANP's setup was never done
			continue
		}
		klog.Infof("Adding ANP %s at priority %d/%d to the anpPriority cache", anp.Name, anp.Spec.Priority, ovnPriority)
		c.anpPriorityMap[ovnPriority] = anp.Name
	}

	// Deal with PortGroup Repairs first
	// We grab all the port groups that belong to ANP controller using externalIDs
	// and compare the value with the name of existing ANPs. If no match is found
	// we delete that port group along with all the acls in it.
	p := func(pg *nbdb.PortGroup) bool {
		anpName, ok := pg.ExternalIDs[ANPExternalIDKey]
		if !ok {
			return false // we don't care about this PG as it doesn't belong to ANP controller
		}
		_, ok = existingANPs[anpName]
		return !ok // return if it doesn't exist in the cache
	}
	stalePGs, err := libovsdbops.FindPortGroupsWithPredicate(c.nbClient, p)
	if err != nil {
		return fmt.Errorf("unable to fetch port groups by predicate, err: %v", err)
	}
	if len(stalePGs) > 0 {
		klog.Infof("Deleting Stale PortGroups +%v", stalePGs)
		err = libovsdbops.DeletePortGroupsWithPredicate(c.nbClient, p)
		if err != nil {
			return fmt.Errorf("unable to delete stale port groups, err: %v", err)
		}
	}

	// Deal with ACL Repairs
	// We grab all the ACLs that belong to ANP controller using externalIDs
	// and compare with the rules we have in existing ANPs. The ones that don't match
	// will be deleted from the corresponding PGs.
	// NOTE: When we call syncAdminNetworkPolicy function after this for every ANP on startup,
	// the right ACLs will be recreated.
	aclPredicateIDs := libovsdbops.NewDbObjectIDs(libovsdbops.ACLAdminNetworkPolicy, c.controllerName, nil)
	aclPredicateFunc := func(acl *nbdb.ACL) bool {
		anp, ok := existingANPs[acl.ExternalIDs[libovsdbops.ObjectNameKey.String()]] // ObjectNameKey is ANPName
		if !ok {
			return true // if its not present in current list of ANPs, then we can consider this stale
		}
		// If the ANP exists, then we check the rules and ensure ACL is supposed to be present
		eRules := anp.Spec.Egress
		iRules := anp.Spec.Ingress
		if len(eRules) == 0 && len(iRules) == 0 {
			// no rules present, acl is stale
			return true
		}
		lowestPossiblePriority := (ANPFlowStartPriority - anp.Spec.Priority*ANPMaxRulesPerObject) - int32(len(eRules))
		if acl.ExternalIDs[libovsdbops.PolicyDirectionKey.String()] == string(libovsdbutil.ACLEgress) &&
			(int32(acl.Priority) <= lowestPossiblePriority) {
			// no egress rules present at that priority, acl is stale
			return true
		}
		lowestPossiblePriority = (ANPFlowStartPriority - anp.Spec.Priority*ANPMaxRulesPerObject) - int32(len(iRules))
		if acl.ExternalIDs[libovsdbops.PolicyDirectionKey.String()] == string(libovsdbutil.ACLIngress) &&
			(int32(acl.Priority) <= lowestPossiblePriority) {
			// no ingress rules present, acl is stale
			return true
		}
		return false // legit acl, not stale
	}
	aclPredicate := libovsdbops.GetPredicate[*nbdb.ACL](aclPredicateIDs, aclPredicateFunc)
	staleACLs, err := libovsdbops.FindACLsWithPredicate(c.nbClient, aclPredicate)
	if err != nil {
		return fmt.Errorf("unable to fetch acls by predicate, err: %v", err)
	}
	allOps := []ovsdb.Operation{}
	for _, staleACL := range staleACLs {
		staleACL := staleACL
		anpName := staleACL.ExternalIDs[libovsdbops.ObjectNameKey.String()]
		pgName, readablePGName := getAdminNetworkPolicyPGName(anpName, false)
		klog.Infof("Deleting Stale ACL %v from PortGroup %s", staleACL, readablePGName)
		allOps, err = libovsdbops.DeleteACLsFromPortGroupOps(c.nbClient, allOps, pgName, staleACL)
		if err != nil && !errors.Is(err, libovsdbclient.ErrNotFound) {
			// if the ACL or PG is already gone, then nothing to do; unreferences ACLs should be autoremoved
			return fmt.Errorf("unable to construct stale acl deletion ops, err: %v", err)
		}
	}
	_, err = libovsdbops.TransactAndCheck(c.nbClient, allOps)
	if err != nil {
		return fmt.Errorf("unable to transact operations that have ops +%v; err: %v", allOps, err)
	}
	// Deal with Address-Sets Repairs
	// We grab all the AddressSets that belong to ANP controller using externalIDs
	// and compare with the existing ANPs. The ones that don't match
	// will be deleted from the DB.
	// NOTE: When we call syncAdminNetworkPolicy function after this for every ANP on startup,
	// the right Address-sets will be recreated.
	// Since we clean ACLs before Address-sets we should not run into any referential ingegrity violation
	asPredicateIDs := libovsdbops.NewDbObjectIDs(libovsdbops.AddressSetAdminNetworkPolicy, c.controllerName, nil)
	asPredicateFunc := func(as *nbdb.AddressSet) bool {
		_, ok := existingANPs[as.ExternalIDs[libovsdbops.ObjectNameKey.String()]]
		return !ok // if not present in cache then its stale
	}
	asPredicate := libovsdbops.GetPredicate[*nbdb.AddressSet](asPredicateIDs, asPredicateFunc)
	if err := libovsdbops.DeleteAddressSetsWithPredicate(c.nbClient, asPredicate); err != nil {
		return fmt.Errorf("failed to remove stale egress qos address sets, err: %v", err)
	}
	return nil
}

// repairBaselineAdminNetworkPolicies is called at startup and as the name suggests
// aims to repair the NBDB logical objects -> port groups, acls and address-sets
// that are created for the baseline admin network policy in the cluster
// Logic:
// We fetch the singleton BANPs present in the cluster from the Lister
// We fetch PGs, ACLs, AddressSets that are owned by BANP objectIDs based on
// externalIDs match from the NBDB. Using predicate search we check if
// the relevant BANP still exists for these objects and if not we delete them
// TODO (tssurya): Handle cleaning up stale IPs in the address-sets by fetching all the relevant
// peer pods that are being served by BANP - pods could stop matching when ovnkube-controller is down
// TODO2 (tssurya): Handle cleaning up stale ports from PGs by fetching all the relevant
// pods that are being served by BANP - pods could stop matching when ovnkube-controller is down
func (c *Controller) repairBaselineAdminNetworkPolicy() error {
	start := time.Now()
	defer func() {
		klog.Infof("Repairing baseline admin network policies took %v", time.Since(start))
	}()
	c.Lock()
	defer c.Unlock()

	banps, err := c.banpLister.List(labels.Everything())
	if err != nil {
		return fmt.Errorf("unable to list BANPs from the lister, err: %v", err)
	}
	existingBANPs := map[string]*anpapi.BaselineAdminNetworkPolicy{}
	for _, banp := range banps {
		existingBANPs[banp.Name] = banp
	}

	// Deal with PortGroup Repairs first
	// We grab all the port groups that belong to BANP controller using externalIDs
	// and compare the value with the name of existing BANPs. If no match is found
	// we delete that port group along with all the acls in it.
	p := func(pg *nbdb.PortGroup) bool {
		banpName, ok := pg.ExternalIDs[BANPExternalIDKey]
		if !ok {
			return false // we don't care about this PG as it doesn't belong to BANP controller
		}
		_, ok = existingBANPs[banpName]
		return !ok // return if it doesn't exist in the cache
	}
	stalePGs, err := libovsdbops.FindPortGroupsWithPredicate(c.nbClient, p)
	if err != nil {
		return fmt.Errorf("unable to fetch port groups by predicate, err: %v", err)
	}
	if len(stalePGs) > 0 {
		klog.Infof("Deleting Stale PortGroups +%v", stalePGs)
		err = libovsdbops.DeletePortGroupsWithPredicate(c.nbClient, p)
		if err != nil && !errors.Is(err, libovsdbclient.ErrNotFound) {
			// if the ACL or PG is already gone, then nothing to do; unreferences ACLs should be autoremoved
			return fmt.Errorf("unable to delete stale port groups, err: %v", err)
		}
	}

	// Deal with ACL Repairs
	// We grab all the ACLs that belong to BANP controller using externalIDs
	// and compare with the rules we have in existing BANP. The ones that don't match
	// will be deleted from the corresponding PGs.
	// NOTE: When we call syncBaselineAdminNetworkPolicy function after this for the BANP on startup,
	// the right ACLs will be recreated.
	aclPredicateIDs := libovsdbops.NewDbObjectIDs(libovsdbops.ACLBaselineAdminNetworkPolicy, c.controllerName, nil)
	aclPredicateFunc := func(acl *nbdb.ACL) bool {
		anp, ok := existingBANPs[acl.ExternalIDs[libovsdbops.ObjectNameKey.String()]] // ObjectNameKey is BANPName
		if !ok {
			return true // if its not present in current BANPs, then we can consider this stale
		}
		// If the BANP exists, then we check the rules and ensure ACL is supposed to be present
		eRules := anp.Spec.Egress
		iRules := anp.Spec.Ingress
		if len(eRules) == 0 && len(iRules) == 0 {
			// no rules present, acl is stale
			return true
		}
		lowestPossiblePriority := BANPFlowPriority - int32(len(eRules))
		if acl.ExternalIDs[libovsdbops.PolicyDirectionKey.String()] == string(libovsdbutil.ACLEgress) &&
			(int32(acl.Priority) <= lowestPossiblePriority) {
			// no egress rules present at that priority, acl is stale
			return true
		}
		lowestPossiblePriority = BANPFlowPriority - int32(len(iRules))
		if acl.ExternalIDs[libovsdbops.PolicyDirectionKey.String()] == string(libovsdbutil.ACLIngress) &&
			(int32(acl.Priority) <= lowestPossiblePriority) {
			// no ingress rules present, acl is stale
			return true
		}
		return false // legit acl, not stale
	}
	aclPredicate := libovsdbops.GetPredicate[*nbdb.ACL](aclPredicateIDs, aclPredicateFunc)
	staleACLs, err := libovsdbops.FindACLsWithPredicate(c.nbClient, aclPredicate)
	if err != nil {
		return fmt.Errorf("unable to fetch acls by predicate, err: %v", err)
	}
	allOps := []ovsdb.Operation{}
	for _, staleACL := range staleACLs {
		banpName := staleACL.ExternalIDs[libovsdbops.ObjectNameKey.String()]
		pgName, readablePGName := getAdminNetworkPolicyPGName(banpName, true)
		klog.Infof("Deleting Stale ACL %v from PortGroup %s", staleACL, readablePGName)
		allOps, err = libovsdbops.DeleteACLsFromPortGroupOps(c.nbClient, allOps, pgName, staleACL)
		if err != nil {
			return fmt.Errorf("unable to construct stale acl deletion ops, err: %v", err)
		}
	}
	_, err = libovsdbops.TransactAndCheck(c.nbClient, allOps)
	if err != nil {
		return fmt.Errorf("unable to transact operations that have ops +%v; err: %v", allOps, err)
	}
	// Deal with Address-Sets Repairs
	// We grab all the AddressSets that belong to BANP controller using externalIDs
	// and compare with the existing ANPs. The ones that don't match
	// will be deleted from the DB.
	// NOTE: When we call syncBaselineAdminNetworkPolicy function after this for every BANP on startup,
	// the right Address-sets will be recreated.
	// Since we clean ACLs before Address-sets we should not run into any referential ingegrity violation
	asPredicateIDs := libovsdbops.NewDbObjectIDs(libovsdbops.AddressSetBaselineAdminNetworkPolicy, c.controllerName, nil)
	asPredicateFunc := func(as *nbdb.AddressSet) bool {
		_, ok := existingBANPs[as.ExternalIDs[libovsdbops.ObjectNameKey.String()]]
		return !ok // if not present in cache then its stale
	}
	asPredicate := libovsdbops.GetPredicate[*nbdb.AddressSet](asPredicateIDs, asPredicateFunc)
	if err := libovsdbops.DeleteAddressSetsWithPredicate(c.nbClient, asPredicate); err != nil {
		return fmt.Errorf("failed to remove stale egress qos address sets, err: %v", err)
	}
	return nil
}
