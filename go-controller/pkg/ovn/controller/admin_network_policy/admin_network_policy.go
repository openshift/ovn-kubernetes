package adminnetworkpolicy

import (
	"fmt"
	"reflect"
	"strconv"
	"sync"
	"time"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/libovsdb/ovsdb"
	libovsdbops "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	libovsdbutil "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/util"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/pkg/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	anpapi "sigs.k8s.io/network-policy-api/apis/v1alpha1"
)

func (c *Controller) processNextANPWorkItem(wg *sync.WaitGroup) bool {
	wg.Add(1)
	defer wg.Done()
	anpKey, quit := c.anpQueue.Get()
	if quit {
		return false
	}
	defer c.anpQueue.Done(anpKey)

	err := c.syncAdminNetworkPolicy(anpKey.(string))
	if err == nil {
		c.anpQueue.Forget(anpKey)
		return true
	}
	utilruntime.HandleError(fmt.Errorf("%v failed with: %v", anpKey, err))

	if c.anpQueue.NumRequeues(anpKey) < maxRetries {
		c.anpQueue.AddRateLimited(anpKey)
		return true
	}

	c.anpQueue.Forget(anpKey)
	return true
}

// syncAdminNetworkPolicy decides the main logic everytime
// we dequeue a key from the anpQueue cache
func (c *Controller) syncAdminNetworkPolicy(key string) error {
	// TODO(tssurya): This global lock will be inefficient, we will do perf runs and improve if needed
	c.Lock()
	defer c.Unlock()
	startTime := time.Now()
	_, anpName, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	klog.V(4).Infof("Processing sync for Admin Network Policy %s", anpName)

	defer func() {
		klog.V(4).Infof("Finished syncing Admin Network Policy %s : %v", anpName, time.Since(startTime))
	}()

	anp, err := c.anpLister.Get(anpName)
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	if anp == nil {
		// it was deleted; let's clear up all the related resources to that
		err = c.clearAdminNetworkPolicy(anpName)
		if err != nil {
			return err
		}
		return nil
	}
	// at this stage the ANP exists in the cluster
	err = c.ensureAdminNetworkPolicy(anp)
	if err != nil && errors.Unwrap(err) != ErrorANPPriorityUnsupported && errors.Unwrap(err) != ErrorANPWithDuplicatePriority {
		return err
	}
	return nil
}

// ensureAdminNetworkPolicy will handle the main reconcile logic for any given anp's
// add/update that might be triggered either due to ANP changes or the corresponding
// matching pod or namespace changes.
func (c *Controller) ensureAdminNetworkPolicy(anp *anpapi.AdminNetworkPolicy) error {
	// We only support priority ranges 0-99 in OVN-K for an ANP even if upstream
	// supports upto 1000. The 0 (highest) corresponds to 30,000 in OVN world and
	// 99 (lowest) corresponds to 20,100 in OVN world
	if anp.Spec.Priority > ovnkSupportedPriorityUpperBound {
		return fmt.Errorf("error attempting to add ANP %s with priority %d because, "+
			"%w", anp.Name, anp.Spec.Priority, ErrorANPPriorityUnsupported)
	}
	desiredANPState, err := newAdminNetworkPolicyState(anp)
	if err != nil {
		return err
	}
	// At a given time only 1 ANP can exist at a given priority. If two ANPs exist with same priority
	// the behaviour is undefined upstream but in OVNK we do not allow that
	if existingName, loaded := c.anpPriorityMap[desiredANPState.priority]; loaded && existingName != anp.Name {
		return fmt.Errorf("error attempting to add ANP %s with priority %d when another ANP %s, "+
			"%w", anp.Name, anp.Spec.Priority, existingName, ErrorANPWithDuplicatePriority)
	}
	// Based on the latest kapi ANP, namespace and pod objects:
	// 1) Construct Port Group name using ANP name and ports of pods in ANP subject
	// 2) Construct Address-sets with IPs of the peers in the rules
	// 3) Construct ACLs using AS-es and PGs
	portGroupName, _ := getAdminNetworkPolicyPGName(desiredANPState.name, false)
	desiredPorts, err := c.getPortsOfSubject(desiredANPState.subject)
	if err != nil {
		return fmt.Errorf("unable to fetch ports for anp %s: %v", desiredANPState.name, err)
	}
	err = c.getAddressSetOfPeers(desiredANPState)
	if err != nil {
		return fmt.Errorf("unable to build address sets for anp %s: %v", desiredANPState.name, err)
	}
	desiredACLs := c.getACLsOfRules(desiredANPState, portGroupName, false)

	// fetch the anpState from our cache
	currentANPState, loaded := c.anpCache[anp.Name]
	if !loaded {
		// this is a fresh ANP create
		klog.Infof("Creating admin network policy %s/%d", anp.Name, anp.Spec.Priority)
		// 4) Create the PG/ACL/AS in same transact (TODO: See if batching is more efficient after scale runs)
		// 6) Update the ANP caches to store all the created things if transact was successful
		err = c.createNewANP(desiredANPState, desiredACLs, desiredPorts, false)
		if err != nil {
			return fmt.Errorf("failed to create ANP %s: %v", desiredANPState.name, err)
		}
		// Let us update the anpPriorityMap cache by adding this new priority to it
		c.anpPriorityMap[desiredANPState.priority] = anp.Name
		// since transact was successful we can finally populate the cache
		c.anpCache[anp.Name] = desiredANPState
		return nil
	}
	var ops []ovsdb.Operation
	// ANP state existed in the cache, which means its either an ANP update or pod/namespace add/update/delete
	klog.V(3).Infof("Admin network policy %s/%d was found in cache...Syncing it", currentANPState.name, currentANPState.priority)
	hasPriorityChanged := (currentANPState.priority != desiredANPState.priority)
	// Did ANP.Spec.Ingress Change (rule inserts/deletes)? && || Did ANP.Spec.Egress Change (rule inserts/deletes)? && ||
	// If yes we need to fully recompute the acls present in our ANP's port group; Let's do a full recompute and return.
	// Reason behind a full recompute: Each rule has precendence based on its position and priority of ANP; if any of that changes
	// better to delete and recreate ACLs rather than figure out from caches
	// TODO(tssurya): Investigate if we can be smarter about which ACLs to delete and which to add
	// rather than always cleaning up everything and recreating them. But this is tricky since rules have precendence
	// from their ordering. Same goes for ANP Priority update - all rules have to be recreated with the right priorities.
	// NOTE: Changes to admin policies should be a rare action (can be improved post user feedback) - usually churn would be around namespaces and pods
	fullPeerRecompute := false
	if len(currentANPState.egressRules) != len(desiredANPState.egressRules) ||
		len(currentANPState.ingressRules) != len(desiredANPState.ingressRules) {
		// full recompute
		// which means update all ACLs and address-sets
		klog.V(3).Infof("ANP %s with priority (old %d, new %d) was updated", desiredANPState.name, currentANPState.priority, desiredANPState.priority)
		ops, err = c.constructOpsForRuleChanges(currentANPState, desiredANPState, false)
		if err != nil {
			return fmt.Errorf("failed to create update ANP ops %s: %v", desiredANPState.name, err)
		}
		fullPeerRecompute = true
	}

	// Did ANP.Spec.Ingress rules get updated?
	// (at this stage the length of ANP.Spec.Ingress hasn't changed, so individual rules either got updated at their values or positions are switched)
	// The fields that we care about for rebuilding ACLs are
	// (i) `ports` (ii) `actions` (iii) priority for a given rule
	// The changes to peer labels, peer pod label updates, namespace label updates etc can be inferred
	// from the podIPs cache we store.
	// Did the ANP.Spec.Ingress.Peers Change?
	// 1) ANP.Spec.Ingress.Peers.Namespaces changed && ||
	// 2) ANP.Spec.Ingress.Peers.Pods changed && ||
	// 3) A namespace started or stopped matching the peer && ||
	// 4) A pod started or stopped matching the peer
	// If yes we need to recompute the IPs present in our ANP's peer's address-sets
	atLeastOneRuleUpdated := false
	if !fullPeerRecompute && !reflect.DeepEqual(desiredANPState.ingressRules, currentANPState.ingressRules) {
		addrOps, err := c.constructOpsForPeerChanges(desiredANPState.ingressRules,
			currentANPState.ingressRules, &atLeastOneRuleUpdated, desiredANPState.name, false)
		if err != nil {
			return fmt.Errorf("failed to create ops for changes to ANP ingress peers: %v", err)
		}
		ops = append(ops, addrOps...)
	}

	// Did ANP.Spec.Egress rules get updated?
	// (at this stage the length of ANP.Spec.Egress hasn't changed, so individual rules either got updated at their values or positions are switched)
	// The fields that we care about for rebuilding ACLs are
	// (i) `ports` (ii) `actions` (iii) priority for a given rule
	// Did the ANP.Spec.Egress.Peers Change?
	// 1) ANP.Spec.Egress.Peers.Namespaces changed && ||
	// 2) ANP.Spec.Egress.Peers.Pods changed && ||
	// 3) A namespace started or stopped matching the peer && ||
	// 4) A pod started or stopped matching the peer
	// If yes we need to recompute the IPs present in our ANP's peer's address-sets
	if !fullPeerRecompute && !reflect.DeepEqual(desiredANPState.egressRules, currentANPState.egressRules) {
		addrOps, err := c.constructOpsForPeerChanges(desiredANPState.egressRules,
			currentANPState.egressRules, &atLeastOneRuleUpdated, desiredANPState.name, false)
		if err != nil {
			return fmt.Errorf("failed to create ops for changes to ANP egress peers: %v", err)
		}
		ops = append(ops, addrOps...)
	}
	// TODO(tssurya): Check if we can be more efficient by narrowing down exactly which ACL needs a change
	// The rules which didn't change -> those updates will be no-ops thanks to libovsdb
	// The rules that changed in terms of their `getACLMutableFields`
	// will be simply updated since externalIDs will remain the same for these ACLs
	// No delete ACLs action is required for this scenario
	// If full fullPeerRecompute=true then also we need to recreate the correct desired ACLs on the port-group
	// the stale ACLs will automatically be taken care of if they are not references by the port group
	if fullPeerRecompute || atLeastOneRuleUpdated || hasPriorityChanged {
		klog.V(3).Infof("ANP %s with priority %d was updated", desiredANPState.name, desiredANPState.priority)
		// now update the acls to the desired ones
		ops, err = libovsdbops.CreateOrUpdateACLsOps(c.nbClient, ops, desiredACLs...)
		if err != nil {
			return fmt.Errorf("failed to create new ACL ops for anp %s: %v", desiredANPState.name, err)
		}
		// since we update the portgroup with the new set of ACLs, any unreferenced set of ACLs
		// will be automatically removed
		ops, err = libovsdbops.UpdatePortGroupSetACLsOps(c.nbClient, ops, portGroupName, desiredACLs)
		if err != nil {
			return fmt.Errorf("failed to create ACL-on-PG update ops for anp %s: %v", desiredANPState.name, err)
		}
	}

	// Did the ANP.Spec.Subject Change?
	// 1) ANP.Spec.Namespaces changed && ||
	// 2) ANP.Spec.Pods changed && ||
	// 3) A namespace started or stopped matching the subject && ||
	// 4) A pod started or stopped matching the subject
	// If yes we need to recompute the ports present in our ANP's port group
	subjectOps, err := c.constructOpsForSubjectChanges(currentANPState, desiredANPState, portGroupName)
	if err != nil {
		return fmt.Errorf("failed to create ops for changes to ANP %s subject: %v", desiredANPState.name, err)
	}
	ops = append(ops, subjectOps...)
	_, err = libovsdbops.TransactAndCheck(c.nbClient, ops)
	if err != nil {
		return fmt.Errorf("failed to run ovsdb txn to update ANP %s: %v", desiredANPState.name, err)
	}
	// We also need to update c.anpPriorityMap cache
	if hasPriorityChanged {
		klog.V(3).Infof("Deleting and re-adding correct priority (old %d, new %d) from anpPriorityMap for %s",
			currentANPState.priority, desiredANPState.priority, desiredANPState.name)
		if existingName, loaded := c.anpPriorityMap[currentANPState.priority]; loaded && existingName == desiredANPState.name {
			delete(c.anpPriorityMap, currentANPState.priority)
		}
		// Let us update the anpPriorityMap cache by adding this new priority to it
		c.anpPriorityMap[desiredANPState.priority] = anp.Name
	}
	// since transact was successful we can finally replace the currentANPState in the cache with the latest desired one
	// TODO(tssurya); check if c.Lock is enough to protect the c.anpCache or we can be more efficient here
	c.anpCache[anp.Name] = desiredANPState
	return nil
}

// getACLsOfRules takes all the rules belonging to the ANP and initiates the conversion of rule->acl
func (c *Controller) getACLsOfRules(anp *adminNetworkPolicyState, pgName string, isBanp bool) []*nbdb.ACL {
	acls := []*nbdb.ACL{}
	for _, ingressRule := range anp.ingressRules {
		acl := c.convertANPRuleToACL(ingressRule, pgName, anp.name, isBanp)
		acls = append(acls, acl...)
	}
	for _, egressRule := range anp.egressRules {
		acl := c.convertANPRuleToACL(egressRule, pgName, anp.name, isBanp)
		acls = append(acls, acl...)
	}

	return acls
}

// convertANPRuleToACL takes the given gressRule and converts it into an ACL(0 ports rule) or
// multiple ACLs(ports are set) and returns those ACLs for a given gressRule
func (c *Controller) convertANPRuleToACL(rule *gressRule, pgName, anpName string, isBanp bool) []*nbdb.ACL {
	// create address-set
	// TODO (tssurya): Revisit this logic to see if its better to do one address-set per peer
	// and join them with OR if that is more perf efficient. Had briefly discussed this OVN team
	// We are not yet clear which is better since both have advantages and disadvantages.
	// Decide this after doing some scale runs.
	// TODO(tssurya): Use address-sets of namespaces whereever it makes sense; specially if namespace is already created
	klog.V(3).Infof("Creating ACL for rule %d/%s belonging to ANP %s", rule.priority, rule.gressPrefix, anpName)
	// create match based on direction and address-set name
	asIndex := GetANPPeerAddrSetDbIDs(anpName, rule.gressPrefix, fmt.Sprintf("%d", rule.gressIndex), c.controllerName, isBanp)
	l3Match := constructMatchFromAddressSet(rule.gressPrefix, asIndex)
	// create match based on rule type (ingress/egress) and port-group
	lportMatch := libovsdbutil.GetACLMatch(pgName, "", libovsdbutil.ACLDirection(rule.gressPrefix))
	var match string
	acls := []*nbdb.ACL{}
	// no ports in this rule; so its a single ACL
	if len(rule.ports) == 0 {
		match = fmt.Sprintf("%s && %s", l3Match, lportMatch)
		acl := libovsdbutil.BuildANPACL(
			getANPRuleACLDbIDs(anpName, rule.gressPrefix, fmt.Sprintf("%d", rule.gressIndex), c.controllerName, isBanp),
			int(rule.priority),
			match,
			rule.action,
			libovsdbutil.ACLDirectionToACLPipeline(libovsdbutil.ACLDirection(rule.gressPrefix)),
		)
		acls = append(acls, acl)
		return acls
	}

	// we have ports defined in this rule, so its one ACL per port
	// TODO(tssurya): There are some improvement PRs around this, adapt them in the future iterations
	for i, port := range rule.ports {
		l4Match := constructMatchFromPorts(port)
		match = fmt.Sprintf("%s && %s && %s", l3Match, lportMatch, l4Match)
		acl := libovsdbutil.BuildANPACL(
			getANPRuleACLDbIDs(anpName, rule.gressPrefix, fmt.Sprintf("%d.%d", rule.gressIndex, i), c.controllerName, isBanp),
			int(rule.priority),
			match,
			rule.action,
			libovsdbutil.ACLDirectionToACLPipeline(libovsdbutil.ACLDirection(rule.gressPrefix)),
		)
		acls = append(acls, acl)
	}

	return acls
}

// getAddressSetsOfPeers takes all the peers belonging to each of the ANP rule and initiates the conversion of rule.peer->set of ips
// These set of ips are then used to create the address-sets
func (c *Controller) getAddressSetOfPeers(anp *adminNetworkPolicyState) error {
	// create address-set
	// TODO (tssurya): Revisit this logic to see if its better to do one address-set per peer
	// and join them with OR if that is more perf efficient. Had briefly discussed this OVN team
	// We are not yet clear which is better since both have advantages and disadvantages.
	// Decide this after doing some scale runs.
	// TODO(tssurya): Use address-sets of namespaces whereever it makes sense; specially if namespace is already created
	var err error
	for _, ingressRule := range anp.ingressRules {
		ingressRule.podIPs, err = c.convertANPPeerToAddressSet(ingressRule.peers,
			ingressRule.gressIndex, ingressRule.gressPrefix, anp.name)
		if err != nil {
			return fmt.Errorf("unable to create address set for "+
				" rule %s with priority %d: %w", ingressRule.name, ingressRule.priority, err)
		}
	}
	for _, egressRule := range anp.egressRules {
		egressRule.podIPs, err = c.convertANPPeerToAddressSet(egressRule.peers,
			egressRule.gressIndex, egressRule.gressPrefix, anp.name)
		if err != nil {
			return fmt.Errorf("unable to create address set for "+
				" rule %s with priority %d: %w", egressRule.name, egressRule.priority, err)
		}
	}

	return nil
}

// convertANPPeerToAddressSet creates the address-set for all the provided peers.
// NOTE: We call ensureAS function using externalID match, so if the address-set already exists its no-op
// This function also takes care of populating the adminNetworkPolicyPeer.namespaces cache
// It also adds up all the podIPs that are supposed to be present in the created AS and returns them on
// a per-rule basis so that the actual ops to transact these into the AS can be constructed using that
func (c *Controller) convertANPPeerToAddressSet(peers []*adminNetworkPolicyPeer, gressIndex int32, gressPrefix,
	anpName string) (sets.Set[string], error) {
	peerPodIPs := sets.Set[string]{}
	for _, peer := range peers {
		// TODO: Double check how empty selector means all labels match works
		namespaces, err := c.anpNamespaceLister.List(peer.namespaceSelector)
		if err != nil {
			return nil, err
		}
		namespaceCache := make(map[string]sets.Set[string])
		// NOTE: Multiple peers may match on same podIP which is fine, we use sets to store them to avoid duplication
		for _, namespace := range namespaces {
			podCache, ok := namespaceCache[namespace.Name]
			if !ok {
				podCache = sets.Set[string]{}
				namespaceCache[namespace.Name] = podCache
			}
			podNamespaceLister := c.anpPodLister.Pods(namespace.Name)
			pods, err := podNamespaceLister.List(peer.podSelector)
			if err != nil {
				return nil, err
			}
			for _, pod := range pods {
				// we don't handle HostNetworked or completed pods; unscheduled pods shall be handled via pod update path
				if util.PodWantsHostNetwork(pod) || util.PodCompleted(pod) || !util.PodScheduled(pod) {
					continue
				}
				podIPs, err := util.GetPodIPsOfNetwork(pod, &util.DefaultNetInfo{})
				if err != nil {
					if errors.Is(err, util.ErrNoPodIPFound) {
						// we ignore podIPsNotFound error here because onANPPodUpdate
						// will take care of this; no need to add nil podIPs to slice...
						// move on to next item in the loop
						continue
					}
					return nil, err
				}
				peerPodIPs.Insert(util.StringSlice(podIPs)...)
				podCache.Insert(pod.Name)
			}
		}
		peer.namespaces = namespaceCache
	}
	return peerPodIPs, nil
}

// getPortsOfSubject calculates all the LSP's that match for the provided anp's subject and returns them
// It also populates the adminNetworkPolicySubject.namespaces and adminNetworkPolicySubject.podPorts
// pieces of the cache
func (c *Controller) getPortsOfSubject(anpSubject *adminNetworkPolicySubject) ([]*nbdb.LogicalSwitchPort, error) {
	ports := []*nbdb.LogicalSwitchPort{}
	anpSubject.podPorts = sets.Set[string]{}
	namespaces, err := c.anpNamespaceLister.List(anpSubject.namespaceSelector)
	if err != nil {
		return nil, err
	}
	namespaceCache := make(map[string]sets.Set[string])
	for _, namespace := range namespaces {
		podCache, ok := namespaceCache[namespace.Name]
		if !ok {
			podCache = sets.Set[string]{}
			namespaceCache[namespace.Name] = podCache
		}
		podNamespaceLister := c.anpPodLister.Pods(namespace.Name)
		pods, err := podNamespaceLister.List(anpSubject.podSelector)
		if err != nil {
			return nil, err
		}
		for _, pod := range pods {
			if util.PodWantsHostNetwork(pod) || util.PodCompleted(pod) || !util.PodScheduled(pod) || !c.isPodScheduledinLocalZone(pod) {
				continue
			}
			logicalPortName := util.GetLogicalPortName(pod.Namespace, pod.Name)
			lsp := &nbdb.LogicalSwitchPort{Name: logicalPortName}
			lsp, err = libovsdbops.GetLogicalSwitchPort(c.nbClient, lsp)
			if err != nil {
				if errors.Is(err, libovsdbclient.ErrNotFound) {
					// TODO(tssurya): Danger of doing this is if there is time gap between pod being annotated wit chosen IP
					// and pod's LSP being created, then we might setup the policies only after pod goes into running state
					// thus causing little bit of outage
					// we ignore ErrNotFound error here because onANPPodUpdate (pod.status.Running)
					// will take care of this; no need to add nil podIPs to slice...
					// move on to next item in the loop
					// If not we are going to have many such pods if ANP and pods are created at the same time thus causing
					// ANP create to fail on a single pod add failure
					continue
				}
				return nil, fmt.Errorf("error retrieving logical switch port with name %s "+
					" from libovsdb cache: %w", logicalPortName, err)
			}
			ports = append(ports, lsp)
			anpSubject.podPorts.Insert(lsp.UUID)
			podCache.Insert(pod.Name)
		}
	}
	anpSubject.namespaces = namespaceCache

	return ports, nil
}

// clearAdminNetworkPolicy will handle the logic for deleting all db objects related
// to the provided anp which got deleted.
// uses externalIDs to figure out ownership
func (c *Controller) clearAdminNetworkPolicy(anpName string) error {
	anp, loaded := c.anpCache[anpName]
	if !loaded {
		// there is no existing ANP configured with this name, nothing to clean
		klog.Infof("ANP %s not found in cache, nothing to clear", anpName)
		return nil
	}

	// clear NBDB objects for the given ANP (PG, ACLs on that PG, AddrSets used by the ACLs)
	var err error
	// remove PG for Subject (ACLs will get cleaned up automatically)
	portGroupName, readableGroupName := getAdminNetworkPolicyPGName(anp.name, false)
	// no need to batch this with address-set deletes since this itself will contain a bunch of ACLs that need to be deleted which is heavy enough.
	err = libovsdbops.DeletePortGroups(c.nbClient, portGroupName)
	if err != nil {
		return fmt.Errorf("unable to delete PG %s for ANP %s: %w", readableGroupName, anp.name, err)
	}
	// remove address-sets that were created for the peers of each rule fpr the whole ANP
	// do this after ACLs are gone so that there is no lingering references
	err = c.clearASForPeers(anp.name, libovsdbops.AddressSetAdminNetworkPolicy)
	if err != nil {
		return fmt.Errorf("failed to delete address-sets for ANP %s/%d: %w", anp.name, anp.priority, err)
	}
	// we can delete the object from the cache now.
	delete(c.anpPriorityMap, anp.priority)
	delete(c.anpCache, anpName)

	return nil
}

// clearASForPeers takes the externalID objectIDs and uses them to delete all the address-sets
// that were owned by anpName
func (c *Controller) clearASForPeers(anpName string, idType *libovsdbops.ObjectIDsType) error {
	predicateIDs := libovsdbops.NewDbObjectIDs(idType, c.controllerName,
		map[libovsdbops.ExternalIDKey]string{
			libovsdbops.ObjectNameKey: anpName,
		})
	asPredicate := libovsdbops.GetPredicate[*nbdb.AddressSet](predicateIDs, nil)
	if err := libovsdbops.DeleteAddressSetsWithPredicate(c.nbClient, asPredicate); err != nil {
		return fmt.Errorf("failed to destroy address-set for ANP %s, err: %v", anpName, err)
	}
	return nil
}

// createNewANP takes the desired state of the anp and creates the corresponding objects in the NBDB
func (c *Controller) createNewANP(desiredANPState *adminNetworkPolicyState, desiredACLs []*nbdb.ACL,
	desiredPorts []*nbdb.LogicalSwitchPort, isBanp bool) error {
	ops := []ovsdb.Operation{}
	var err error
	portGroupName, readableGroupName := getAdminNetworkPolicyPGName(desiredANPState.name, isBanp)
	pgExternalIDs := map[string]string{ANPExternalIDKey: desiredANPState.name, "name": readableGroupName}
	if isBanp {
		pgExternalIDs = map[string]string{BANPExternalIDKey: desiredANPState.name, "name": readableGroupName}
	}
	// now CreateOrUpdate the address-sets; add the right IPs - we treat the rest of the address-set cases as a fresh add or update
	addrSetOps, err := c.constructOpsForNewPeer(desiredANPState, isBanp)
	if err != nil {
		return fmt.Errorf("failed to create address-sets, %v", err)
	}
	ops = append(ops, addrSetOps...)
	ops, err = libovsdbops.CreateOrUpdateACLsOps(c.nbClient, ops, desiredACLs...)
	if err != nil {
		return fmt.Errorf("failed to create ACL ops: %v", err)
	}
	pg := libovsdbops.BuildPortGroup(portGroupName, desiredPorts, desiredACLs, pgExternalIDs)
	ops, err = libovsdbops.CreateOrUpdatePortGroupsOps(c.nbClient, ops, pg)
	if err != nil {
		return fmt.Errorf("failed to create ops to add port to a port group: %v", err)
	}
	_, err = libovsdbops.TransactAndCheck(c.nbClient, ops)
	if err != nil {
		return fmt.Errorf("failed to run ovsdb txn to add ports to port group: %v", err)
	}
	return nil
}

// constructOpsForRuleChanges takes the desired and current states of the anp and returns the corresponding ops for updating NBDB objects
func (c *Controller) constructOpsForRuleChanges(currentANPState, desiredANPState *adminNetworkPolicyState, isBanp bool) ([]ovsdb.Operation, error) {
	var ops []ovsdb.Operation
	var err error
	// Logic to delete address-sets:
	// we need to delete address-sets only if the number of rules in the desiredANPState object is
	// less than the number of rules in the currentANPState object (AddressSet indexes are calculated based on rule's position)
	// rest of the cases will be createorupdate of existing existing address-sets in the cluster
	idType := libovsdbops.AddressSetAdminNetworkPolicy
	if isBanp {
		idType = libovsdbops.AddressSetBaselineAdminNetworkPolicy
	}
	if len(desiredANPState.egressRules) < len(currentANPState.egressRules) || len(desiredANPState.ingressRules) < len(currentANPState.ingressRules) {
		predicateIDs := libovsdbops.NewDbObjectIDs(idType, c.controllerName,
			map[libovsdbops.ExternalIDKey]string{
				libovsdbops.ObjectNameKey: currentANPState.name,
			})
		predicateFunc := func(as *nbdb.AddressSet) bool {
			asIndex, _ := strconv.Atoi(as.ExternalIDs[libovsdbops.GressIdxKey.String()])
			return (as.ExternalIDs[libovsdbops.PolicyDirectionKey.String()] == string(libovsdbutil.ACLEgress) &&
				asIndex >= len(desiredANPState.egressRules)) ||
				(as.ExternalIDs[libovsdbops.PolicyDirectionKey.String()] == string(libovsdbutil.ACLIngress) &&
					asIndex >= len(desiredANPState.ingressRules))
		}
		asPredicate := libovsdbops.GetPredicate[*nbdb.AddressSet](predicateIDs, predicateFunc)
		ops, err = libovsdbops.DeleteAddressSetsWithPredicateOps(c.nbClient, ops, asPredicate)
		if err != nil {
			return nil, fmt.Errorf("failed to create address-set destroy ops for ANP %s, err: %v", currentANPState.name, err)
		}
	}
	// now CreateOrUpdate the address-sets; add the right IPs - we treat the rest of the address-set cases as an update
	addrSetOps, err := c.constructOpsForNewPeer(desiredANPState, isBanp)
	if err != nil {
		return nil, fmt.Errorf("failed to update address-sets for ANP %s, %v", desiredANPState.name, err)
	}
	ops = append(ops, addrSetOps...)
	return ops, nil
}

// constructOpsForNewPeer calls CreateOrUpdate address-sets with the list of podIPs we want to set on that address-set
// and returns the ops
// Difference between this and constructOpsForPeerChanges is that this one sets all the podIPs on address-sets and
// creates the address-set if it does not exist versus constructOpsForPeerChanges only updates the changed IPs on the
// specific address-sets.
// This should be called if ANP is being created/updated
func (c *Controller) constructOpsForNewPeer(desiredANPState *adminNetworkPolicyState, isBanp bool) ([]ovsdb.Operation, error) {
	var ops []ovsdb.Operation
	// now CreateOrUpdate the address-sets; add the right IPs
	for _, rule := range desiredANPState.ingressRules {
		asIndex := GetANPPeerAddrSetDbIDs(desiredANPState.name, rule.gressPrefix, fmt.Sprintf("%d", rule.gressIndex), c.controllerName, isBanp)
		_, addrSetOps, err := c.addressSetFactory.NewAddressSetOps(asIndex, util.StringsToIPs(rule.podIPs.UnsortedList()))
		if err != nil {
			return nil, fmt.Errorf("failed to create address-sets for ANP %s's"+
				" ingress rule %s/%s/%d: %v", desiredANPState.name, rule.name, rule.gressPrefix, rule.priority, err)
		}
		ops = append(ops, addrSetOps...)
	}
	for _, rule := range desiredANPState.egressRules {
		asIndex := GetANPPeerAddrSetDbIDs(desiredANPState.name, rule.gressPrefix, fmt.Sprintf("%d", rule.gressIndex), c.controllerName, isBanp)
		_, addrSetOps, err := c.addressSetFactory.NewAddressSetOps(asIndex, util.StringsToIPs(rule.podIPs.UnsortedList()))
		if err != nil {
			return nil, fmt.Errorf("failed to create address-sets for ANP %s's"+
				" egress rule %s/%s/%d: %v", desiredANPState.name, rule.name, rule.gressPrefix, rule.priority, err)
		}
		ops = append(ops, addrSetOps...)
	}
	return ops, nil
}

// constructOpsForPeerChanges takes the desired and current rules of the anp and returns the corresponding ops for updating NBDB AddressSet objects for those peers
// This should be called if namespace/pod is being created/updated
func (c *Controller) constructOpsForPeerChanges(desiredRules, currentRules []*gressRule, atLeastOneRuleUpdated *bool,
	anpName string, isBanp bool) ([]ovsdb.Operation, error) {
	var ops []ovsdb.Operation
	for i := range desiredRules {
		desiredRule := desiredRules[i]
		currentRule := currentRules[i]
		ipsToAdd := desiredRule.podIPs.Difference(currentRule.podIPs)
		asIndex := GetANPPeerAddrSetDbIDs(anpName, desiredRule.gressPrefix, fmt.Sprintf("%d", desiredRule.gressIndex), c.controllerName, isBanp)
		if len(ipsToAdd) > 0 {
			as, err := c.addressSetFactory.GetAddressSet(asIndex)
			if err != nil {
				return nil, fmt.Errorf("cannot ensure that addressSet %+v exists: err %v", asIndex.GetExternalIDs(), err)
			}
			klog.Infof("Adding podIPs %+v to address-set %s for ANP %s", ipsToAdd, as.GetName(), anpName)
			addrOps, err := as.AddIPsReturnOps(util.StringsToIPs(ipsToAdd.UnsortedList()))
			if err != nil {
				return nil, fmt.Errorf("failed to construct address-set %s's IP add ops for anp %s's rule"+
					" %s/%s/%d: %v", as.GetName(), anpName, desiredRule.name,
					desiredRule.gressPrefix, desiredRule.priority, err)
			}
			ops = append(ops, addrOps...)
		}
		ipsToRemove := currentRule.podIPs.Difference(desiredRule.podIPs)
		if len(ipsToRemove) > 0 {
			as, err := c.addressSetFactory.GetAddressSet(asIndex)
			if err != nil {
				return nil, fmt.Errorf("cannot ensure that addressSet %+v exists: err %v", asIndex.GetExternalIDs(), err)
			}
			klog.Infof("Deleting podIPs %+v from address-set %s for ANP %s", ipsToRemove, as.GetName(), anpName)
			addrOps, err := as.DeleteIPsReturnOps(util.StringsToIPs(ipsToRemove.UnsortedList()))
			if err != nil {
				return nil, fmt.Errorf("failed to construct address-set %s's IP delete ops for anp %s's rule"+
					" %s/%s/%d: %v", as.GetName(), anpName, desiredRule.name,
					desiredRule.gressPrefix, desiredRule.priority, err)
			}
			ops = append(ops, addrOps...)
		}
		if !*atLeastOneRuleUpdated && currentRule.action != desiredRule.action || !reflect.DeepEqual(desiredRule.ports, currentRule.ports) {
			klog.V(3).Infof("ANP %s's ingress rule %s at priority %d was updated", anpName, desiredRule.name, desiredRule.priority)
			*atLeastOneRuleUpdated = true
		}
	}
	return ops, nil
}

// constructOpsForSubjectChanges takes the current and desired cache states for a given ANP and returns the ops
// required to construct the transact to insert/delete ports to/from port-groups according to the ANP subject changes
func (c *Controller) constructOpsForSubjectChanges(currentANPState, desiredANPState *adminNetworkPolicyState, portGroupName string) ([]ovsdb.Operation, error) {
	var ops []ovsdb.Operation
	var err error
	portsToAdd := desiredANPState.subject.podPorts.Difference(currentANPState.subject.podPorts).UnsortedList()
	portsToDelete := currentANPState.subject.podPorts.Difference(desiredANPState.subject.podPorts).UnsortedList()
	if len(portsToAdd) > 0 {
		klog.Infof("Adding ports %+v to port-group %s for ANP %s", portsToAdd, portGroupName, desiredANPState.name)
		ops, err = libovsdbops.AddPortsToPortGroupOps(c.nbClient, ops, portGroupName, portsToAdd...)
		if err != nil {
			return nil, fmt.Errorf("failed to create Port-to-PG add ops for anp %s: %v", desiredANPState.name, err)
		}
	}
	if len(portsToDelete) > 0 {
		klog.Infof("Deleting ports %+v from port-group %s for ANP %s", portsToDelete, portGroupName, desiredANPState.name)
		ops, err = libovsdbops.DeletePortsFromPortGroupOps(c.nbClient, ops, portGroupName, portsToDelete...)
		if err != nil {
			return nil, fmt.Errorf("failed to create Port-from-PG delete ops for anp %s: %v", desiredANPState.name, err)
		}
	}
	return ops, nil
}
