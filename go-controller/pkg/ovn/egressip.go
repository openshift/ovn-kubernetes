package ovn

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	ocpcloudnetworkapi "github.com/openshift/api/cloudnetwork/v1"
	libovsdbclient "github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/libovsdb/ovsdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	egressipv1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/metrics"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	kapi "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

type egressIPDialer interface {
	dial(ip net.IP) bool
}

var dialer egressIPDialer = &egressIPDial{}

func (oc *Controller) reconcileEgressIP(old, new *egressipv1.EgressIP) (err error) {
	// Lock the assignment, this is needed because this function can end up
	// being called from WatchEgressNodes and WatchEgressIP, i.e: two different
	// go-routines and we need to make sure the assignment is safe.
	oc.eIPC.egressIPAssignmentMutex.Lock()
	defer oc.eIPC.egressIPAssignmentMutex.Unlock()

	// Initialize an empty name which is filled depending on the operation
	// (ADD/UPDATE/DELETE) we are performing. This is done as to be able to
	// delete the NB DB set up correctly when searching the DB based on the
	// name.
	name := ""

	// Initialize a status which will be used to compare against
	// new.spec.egressIPs and decide on what from the status should get deleted
	// or kept.
	status := []egressipv1.EgressIPStatusItem{}

	// Initialize two empty objects as to avoid SIGSEGV. The code should play
	// nicely with empty objects though.
	oldEIP, newEIP := &egressipv1.EgressIP{}, &egressipv1.EgressIP{}

	// Initialize two "nothing" selectors. Nothing selector are semantically
	// opposed to "empty" selectors, i.e: they select and match nothing, while
	// an empty one matches everything. If old/new are nil, and we don't do
	// this: we would have an empty EgressIP object which would result in two
	// empty selectors, matching everything, whereas we would mean the inverse
	newNamespaceSelector, _ := metav1.LabelSelectorAsSelector(nil)
	oldNamespaceSelector, _ := metav1.LabelSelectorAsSelector(nil)
	if old != nil {
		oldEIP = old
		oldNamespaceSelector, err = metav1.LabelSelectorAsSelector(&oldEIP.Spec.NamespaceSelector)
		if err != nil {
			return fmt.Errorf("invalid old namespaceSelector, err: %v", err)
		}
		name = oldEIP.Name
		status = oldEIP.Status.Items
	}
	if new != nil {
		newEIP = new
		newNamespaceSelector, err = metav1.LabelSelectorAsSelector(&newEIP.Spec.NamespaceSelector)
		if err != nil {
			return fmt.Errorf("invalid new namespaceSelector, err: %v", err)
		}
		name = newEIP.Name
		status = newEIP.Status.Items
	}

	// We do not initialize a nothing selector for the podSelector, because
	// these are allowed to be empty (i.e: matching all pods in a namespace), as
	// supposed to the namespaceSelector
	newPodSelector, err := metav1.LabelSelectorAsSelector(&newEIP.Spec.PodSelector)
	if err != nil {
		return fmt.Errorf("invalid new podSelector, err: %v", err)
	}
	oldPodSelector, err := metav1.LabelSelectorAsSelector(&oldEIP.Spec.PodSelector)
	if err != nil {
		return fmt.Errorf("invalid old podSelector, err: %v", err)
	}

	// Validate the spec and use only the valid egress IPs when performing any
	// successive operations, theoretically: the user could specify invalid IP
	// addresses, which would break us.
	validSpecIPs, err := oc.validateEgressIPSpec(name, newEIP.Spec.EgressIPs)
	if err != nil {
		return fmt.Errorf("invalid EgressIP spec, err: %v", err)
	}

	// Validate the status, on restart it could be the case that what might have
	// been assigned when ovnkube-master last ran is not a valid assignment
	// anymore (specifically if ovnkube-master has been crashing for a while).
	// Any invalid status at this point in time needs to be removed and assigned
	// to a valid node.
	validStatus, invalidStatus := oc.validateEgressIPStatus(name, status)
	for status := range validStatus {
		// If the spec has changed and an egress IP has been removed by the
		// user: we need to un-assign that egress IP
		if !validSpecIPs.Has(status.EgressIP) {
			invalidStatus[status] = ""
			delete(validStatus, status)
		}
	}

	// Add only the diff between what is requested and valid and that which
	// isn't already assigned.
	ipsToAssign := validSpecIPs
	ipsToRemove := sets.NewString()
	statusToAdd := make([]egressipv1.EgressIPStatusItem, 0, len(ipsToAssign))
	statusToKeep := make([]egressipv1.EgressIPStatusItem, 0, len(validStatus))
	for status := range validStatus {
		statusToKeep = append(statusToKeep, status)
		ipsToAssign.Delete(status.EgressIP)
	}
	statusToRemove := make([]egressipv1.EgressIPStatusItem, 0, len(invalidStatus))
	for status := range invalidStatus {
		statusToRemove = append(statusToRemove, status)
		ipsToRemove.Insert(status.EgressIP)
	}
	if ipsToRemove.Len() > 0 {
		// The following is added as to ensure that we only add after having
		// successfully removed egress IPs. This case is not very important on
		// bare-metal (since we execute the add after the remove below, and
		// hence have full control of the execution - barring its success), but
		// on a cloud: we don't execute anything below, we wait for the status
		// on the CloudPrivateIPConfig(s) we create to be set before executing
		// anything in the OVN DB. So, we need to make sure that we delete and
		// then add, mainly because if EIP1 is added to nodeX and then EIP2 is
		// removed from nodeX, we might remove the setup made for EIP1. The
		// add/delete ordering of events is not guaranteed on the cloud where we
		// depend on other controllers to execute the work for us however. By
		// comparing the spec to the status and applying the following truth
		// table we can ensure that order of events.

		// case ID    |    Egress IP to add    |    Egress IP to remove    |    ipsToAssign
		// 1          |    e1                  |    e1                     |    e1
		// 2          |    e2                  |    e1                     |    -
		// 3          |    e2                  |    -                      |    e2
		// 4          |    -                   |    e1                     |    -

		// Case 1 handles updates. Case 2 and 3 makes sure we don't add until we
		// successfully delete. Case 4 just shows an example of what would
		// happen if we don't have anything to add
		ipsToAssign = ipsToAssign.Intersection(ipsToRemove)
	}

	if !util.PlatformTypeIsEgressIPCloudProvider() {
		if len(statusToRemove) > 0 {
			// Delete the statusToRemove from the allocator cache. If we don't
			// do this we will occupy assignment positions for the ipsToAssign,
			// even though statusToRemove will be removed afterwards
			oc.deleteAllocatorEgressIPAssignments(statusToRemove)
			if err := oc.deleteEgressIPAssignments(name, statusToRemove); err != nil {
				return err
			}
		}
		if len(ipsToAssign) > 0 {
			statusToAdd = oc.assignEgressIPs(name, ipsToAssign.UnsortedList())
			statusToKeep = append(statusToKeep, statusToAdd...)
		}
		// Assign all statusToKeep, we need to warm up the podAssignment cache
		// on restart. We won't perform any additional transactions to the NB DB
		// for things which exists because the libovsdb operations use
		// modelClient which is idempotent.
		if err := oc.addEgressIPAssignments(name, statusToKeep, newEIP.Spec.NamespaceSelector, newEIP.Spec.PodSelector); err != nil {
			return err
		}
		// Add all assignments which are to be kept to the allocator cache,
		// allowing us to track all assignments which have been performed and
		// avoid incorrect future assignments due to a de-synchronized cache.
		oc.addAllocatorEgressIPAssignments(name, statusToKeep)
		// Update the object only on an ADD/UPDATE. If we are processing a
		// DELETE, new will be nil and we should not update the object.
		if len(statusToAdd) > 0 || (len(statusToRemove) > 0 && new != nil) {
			if err := oc.patchReplaceEgressIPStatus(name, statusToKeep); err != nil {
				return err
			}
		}
	} else {
		// Delete all assignments that are to be removed from the allocator
		// cache. If we don't do this we will occupy assignment positions for
		// the ipsToAdd, even though statusToRemove will be removed afterwards
		oc.deleteAllocatorEgressIPAssignments(statusToRemove)
		// If running on a public cloud we should not program OVN just yet, we
		// need confirmation from the cloud-network-config-controller that it
		// can assign the IPs. reconcileCloudPrivateIPConfig will take care of
		// processing the answer from the requests we make here, and update OVN
		// accordingly when we know what the outcome is.
		if len(ipsToAssign) > 0 {
			statusToAdd = oc.assignEgressIPs(name, ipsToAssign.UnsortedList())
			statusToKeep = append(statusToKeep, statusToAdd...)
		}
		// Same as above: Add all assignments which are to be kept to the
		// allocator cache, allowing us to track all assignments which have been
		// performed and avoid incorrect future assignments due to a
		// de-synchronized cache.
		oc.addAllocatorEgressIPAssignments(name, statusToKeep)
		// Execute CloudPrivateIPConfig changes for assignments which need to be
		// added/removed, assignments which don't change do not require any
		// further setup.
		if err := oc.executeCloudPrivateIPConfigChange(name, statusToAdd, statusToRemove); err != nil {
			return err
		}
	}

	// Record the egress IP allocator count
	metrics.RecordEgressIPCount(getEgressIPAllocationTotalCount(oc.eIPC.allocator))

	// If nothing has changed for what concerns the assignments, then check if
	// the namespaceSelector and podSelector have changed. If they have changed
	// then remove the setup for all pods which matched the old and add
	// everything for all pods which match the new.
	if len(ipsToAssign) == 0 &&
		len(statusToRemove) == 0 {
		// Only the namespace selector changed: remove the setup for all pods
		// matching the old and not matching the new, and add setup for the pod
		// matching the new and which didn't match the old.
		if !reflect.DeepEqual(newNamespaceSelector, oldNamespaceSelector) && reflect.DeepEqual(newPodSelector, oldPodSelector) {
			namespaces, err := oc.watchFactory.GetNamespaces()
			if err != nil {
				return err
			}
			for _, namespace := range namespaces {
				namespaceLabels := labels.Set(namespace.Labels)
				if !newNamespaceSelector.Matches(namespaceLabels) && oldNamespaceSelector.Matches(namespaceLabels) {
					if err := oc.deleteNamespaceEgressIPAssignment(name, oldEIP.Status.Items, namespace, oldEIP.Spec.PodSelector); err != nil {
						return err
					}
				}
				if newNamespaceSelector.Matches(namespaceLabels) && !oldNamespaceSelector.Matches(namespaceLabels) {
					if err := oc.addNamespaceEgressIPAssignments(name, newEIP.Status.Items, namespace, newEIP.Spec.PodSelector); err != nil {
						return err
					}
				}
			}
			// Only the pod selector changed: remove the setup for all pods
			// matching the old and not matching the new, and add setup for the pod
			// matching the new and which didn't match the old.
		} else if reflect.DeepEqual(newNamespaceSelector, oldNamespaceSelector) && !reflect.DeepEqual(newPodSelector, oldPodSelector) {
			namespaces, err := oc.watchFactory.GetNamespacesBySelector(newEIP.Spec.NamespaceSelector)
			if err != nil {
				return err
			}
			for _, namespace := range namespaces {
				pods, err := oc.watchFactory.GetPods(namespace.Name)
				if err != nil {
					return err
				}
				for _, pod := range pods {
					podLabels := labels.Set(pod.Labels)
					if !newPodSelector.Matches(podLabels) && oldPodSelector.Matches(podLabels) {
						if err := oc.deletePodEgressIPAssignments(name, oldEIP.Status.Items, pod); err != nil {
							return err
						}
					}
					if util.PodCompleted(pod) {
						continue
					}
					if newPodSelector.Matches(podLabels) && !oldPodSelector.Matches(podLabels) {
						if err := oc.addPodEgressIPAssignmentsWithLock(name, newEIP.Status.Items, pod); err != nil {
							return err
						}
					}
				}
			}
			// Both selectors changed: remove the setup for pods matching the
			// old ones and not matching the new ones, and add setup for all
			// matching the new ones but which didn't match the old ones.
		} else if !reflect.DeepEqual(newNamespaceSelector, oldNamespaceSelector) && !reflect.DeepEqual(newPodSelector, oldPodSelector) {
			namespaces, err := oc.watchFactory.GetNamespaces()
			if err != nil {
				return err
			}
			for _, namespace := range namespaces {
				namespaceLabels := labels.Set(namespace.Labels)
				// If the namespace does not match anymore then there's no
				// reason to look at the pod selector.
				if !newNamespaceSelector.Matches(namespaceLabels) && oldNamespaceSelector.Matches(namespaceLabels) {
					if err := oc.deleteNamespaceEgressIPAssignment(name, oldEIP.Status.Items, namespace, oldEIP.Spec.PodSelector); err != nil {
						return err
					}
				}
				// If the namespace starts matching, look at the pods selector
				// and pods in that namespace and perform the setup for the pods
				// which match the new pod selector or if the podSelector is empty
				// then just perform the setup.
				if newNamespaceSelector.Matches(namespaceLabels) && !oldNamespaceSelector.Matches(namespaceLabels) {
					pods, err := oc.watchFactory.GetPods(namespace.Name)
					if err != nil {
						return err
					}
					for _, pod := range pods {
						podLabels := labels.Set(pod.Labels)
						if newPodSelector.Matches(podLabels) {
							if err := oc.addPodEgressIPAssignmentsWithLock(name, newEIP.Status.Items, pod); err != nil {
								return err
							}
						}
					}
				}
				// If the namespace continues to match, look at the pods
				// selector and pods in that namespace.
				if newNamespaceSelector.Matches(namespaceLabels) && oldNamespaceSelector.Matches(namespaceLabels) {
					pods, err := oc.watchFactory.GetPods(namespace.Name)
					if err != nil {
						return err
					}
					for _, pod := range pods {
						podLabels := labels.Set(pod.Labels)
						if !newPodSelector.Matches(podLabels) && oldPodSelector.Matches(podLabels) {
							if err := oc.deletePodEgressIPAssignments(name, oldEIP.Status.Items, pod); err != nil {
								return err
							}
						}
						if newPodSelector.Matches(podLabels) && !oldPodSelector.Matches(podLabels) {
							if err := oc.addPodEgressIPAssignmentsWithLock(name, newEIP.Status.Items, pod); err != nil {
								return err
							}
						}
					}
				}
			}
		}
	}
	return nil
}

func (oc *Controller) reconcileEgressIPNamespace(old, new *v1.Namespace) error {
	// Same as for reconcileEgressIP: labels play nicely with empty object, not
	// nil ones.
	oldNamespace, newNamespace := &v1.Namespace{}, &v1.Namespace{}
	if old != nil {
		oldNamespace = old
	}
	if new != nil {
		newNamespace = new
	}

	// If the labels have not changed, then there's no change that we care
	// about: return.
	oldLabels := labels.Set(oldNamespace.Labels)
	newLabels := labels.Set(newNamespace.Labels)
	if reflect.DeepEqual(newLabels.AsSelector(), oldLabels.AsSelector()) {
		return nil
	}

	// Iterate all EgressIPs and check if this namespace start/stops matching
	// any and add/remove the setup accordingly. Namespaces can match multiple
	// EgressIP objects (ex: users can chose to have one EgressIP object match
	// all "blue" pods in namespace A, and a second EgressIP object match all
	// "red" pods in namespace A), so continue iterating all EgressIP objects
	// before finishing.
	egressIPs, err := oc.watchFactory.GetEgressIPs()
	if err != nil {
		return err
	}
	for _, egressIP := range egressIPs {
		namespaceSelector, _ := metav1.LabelSelectorAsSelector(&egressIP.Spec.NamespaceSelector)
		if namespaceSelector.Matches(oldLabels) && !namespaceSelector.Matches(newLabels) {
			if err := oc.deleteNamespaceEgressIPAssignment(egressIP.Name, egressIP.Status.Items, oldNamespace, egressIP.Spec.PodSelector); err != nil {
				return err
			}
		}
		if !namespaceSelector.Matches(oldLabels) && namespaceSelector.Matches(newLabels) {
			if err := oc.addNamespaceEgressIPAssignments(egressIP.Name, egressIP.Status.Items, newNamespace, egressIP.Spec.PodSelector); err != nil {
				return err
			}
		}
	}
	return nil
}

func (oc *Controller) reconcileEgressIPPod(old, new *v1.Pod) (err error) {
	oldPod, newPod := &v1.Pod{}, &v1.Pod{}
	namespace := &v1.Namespace{}
	if old != nil {
		oldPod = old
		namespace, err = oc.watchFactory.GetNamespace(oldPod.Namespace)
		if err != nil {
			return err
		}
	}
	if new != nil {
		newPod = new
		namespace, err = oc.watchFactory.GetNamespace(newPod.Namespace)
		if err != nil {
			return err
		}
	}

	newPodLabels := labels.Set(newPod.Labels)
	oldPodLabels := labels.Set(oldPod.Labels)

	// If the namespace the pod belongs to does not have any labels, just return
	// it can't match any EgressIP object
	namespaceLabels := labels.Set(namespace.Labels)
	if namespaceLabels.AsSelector().Empty() {
		return nil
	}

	// Iterate all EgressIPs and check if this pod start/stops matching any and
	// add/remove the setup accordingly. Pods should not match multiple EgressIP
	// objects: that is considered a user error and is undefined. However, in
	// such events iterate all EgressIPs and clean up as much as possible. By
	// iterating all EgressIPs we also cover the case where a pod has its labels
	// changed from matching one EgressIP to another, ex: EgressIP1 matching
	// "blue pods" and EgressIP2 matching "red pods". If a pod with a red label
	// gets changed to a blue label: we need add and remove the set up for both
	// EgressIP obejcts - since we can't be sure of which EgressIP object we
	// process first, always iterate all.
	egressIPs, err := oc.watchFactory.GetEgressIPs()
	if err != nil {
		return err
	}
	for _, egressIP := range egressIPs {
		namespaceSelector, _ := metav1.LabelSelectorAsSelector(&egressIP.Spec.NamespaceSelector)
		if namespaceSelector.Matches(namespaceLabels) {
			// If the namespace the pod belongs to matches this object then
			// check the if there's a podSelector defined on the EgressIP
			// object. If there is one: the user intends the EgressIP object to
			// match only a subset of pods in the namespace, and we'll have to
			// check that. If there is no podSelector: the user intends it to
			// match all pods in the namespace.
			podSelector, _ := metav1.LabelSelectorAsSelector(&egressIP.Spec.PodSelector)
			if !podSelector.Empty() {
				newMatches := podSelector.Matches(newPodLabels)
				oldMatches := podSelector.Matches(oldPodLabels)
				// If the podSelector doesn't match the pod, then continue
				// because this EgressIP intends to match other pods in that
				// namespace and not this one. Other EgressIP objects might
				// match the pod though so we need to check that.
				if !newMatches && !oldMatches {
					continue
				}
				// Check if the pod stopped matching. If the pod was deleted,
				// "new" will be nil and newPodLabels will not match, so this is
				// should cover that case.
				if !newMatches && oldMatches {
					if err := oc.deletePodEgressIPAssignments(egressIP.Name, egressIP.Status.Items, oldPod); err != nil {
						return err
					}
					continue
				}
				// If the pod starts matching the podSelector or continues to
				// match: add the pod. The reason as to why we need to continue
				// adding it if it continues to match, as opposed to once when
				// it started matching, is because the pod might not have pod
				// IPs assigned at that point and we need to continue trying the
				// pod setup for every pod update as to make sure we process the
				// pod IP assignment.
				if err := oc.addPodEgressIPAssignmentsWithLock(egressIP.Name, egressIP.Status.Items, newPod); err != nil {
					return err
				}
				continue
			}
			// If the podSelector is empty (i.e: the EgressIP object is intended
			// to match all pods in the namespace) and the pod has been deleted:
			// "new" will be nil and we need to remove the setup
			if new == nil {
				if err := oc.deletePodEgressIPAssignments(egressIP.Name, egressIP.Status.Items, oldPod); err != nil {
					return err
				}
				continue
			}
			// For all else, perform a setup for the pod
			if err := oc.addPodEgressIPAssignmentsWithLock(egressIP.Name, egressIP.Status.Items, newPod); err != nil {
				return err
			}
		}
	}
	return nil
}

func (oc *Controller) reconcileCloudPrivateIPConfig(old, new *ocpcloudnetworkapi.CloudPrivateIPConfig) error {
	oldCloudPrivateIPConfig, newCloudPrivateIPConfig := &ocpcloudnetworkapi.CloudPrivateIPConfig{}, &ocpcloudnetworkapi.CloudPrivateIPConfig{}
	shouldDelete, shouldAdd := false, false
	nodeToDelete := ""

	if old != nil {
		oldCloudPrivateIPConfig = old
		// We need to handle two types of deletes, A) object UPDATE where the
		// old egress IP <-> node assignment has been removed. This is indicated
		// by the old object having a .status.node set and the new object having
		// .status.node empty and the condition on the new being successful. B)
		// object DELETE, for which new is nil
		shouldDelete = oldCloudPrivateIPConfig.Status.Node != "" || new == nil
		// On DELETE we need to delete the .spec.node for the old object
		nodeToDelete = oldCloudPrivateIPConfig.Spec.Node
	}
	if new != nil {
		newCloudPrivateIPConfig = new
		// We should only proceed to setting things up for objects where the new
		// object has the same .spec.node and .status.node, and assignment
		// condition being true. This is how the cloud-network-config-controller
		// indicates a successful cloud assignment.
		shouldAdd = newCloudPrivateIPConfig.Status.Node == newCloudPrivateIPConfig.Spec.Node &&
			ocpcloudnetworkapi.CloudPrivateIPConfigConditionType(newCloudPrivateIPConfig.Status.Conditions[0].Type) == ocpcloudnetworkapi.Assigned &&
			kapi.ConditionStatus(newCloudPrivateIPConfig.Status.Conditions[0].Status) == kapi.ConditionTrue
		// See above explanation for the delete
		shouldDelete = shouldDelete && newCloudPrivateIPConfig.Status.Node == "" &&
			ocpcloudnetworkapi.CloudPrivateIPConfigConditionType(newCloudPrivateIPConfig.Status.Conditions[0].Type) == ocpcloudnetworkapi.Assigned &&
			kapi.ConditionStatus(newCloudPrivateIPConfig.Status.Conditions[0].Status) == kapi.ConditionTrue
		// On UPDATE we need to delete the old .status.node
		if shouldDelete {
			nodeToDelete = oldCloudPrivateIPConfig.Status.Node
		}
	}

	// As opposed to reconcileEgressIP, here we are only interested in changes
	// made to the status (since we are the only ones performing the change made
	// to the spec). So don't process the object if there is no change made to
	// the status.
	if reflect.DeepEqual(oldCloudPrivateIPConfig.Status, newCloudPrivateIPConfig.Status) {
		return nil
	}

	if shouldDelete {
		// Get the EgressIP owner reference
		egressIPName, exists := oldCloudPrivateIPConfig.Annotations[util.OVNEgressIPOwnerRefLabel]
		if !exists {
			return fmt.Errorf("CloudPrivateIPConfig object: %s is missing the egress IP owner reference annotation", oldCloudPrivateIPConfig.Name)
		}
		// Check if the egress IP has been deleted or not, if we are processing
		// a CloudPrivateIPConfig delete because the EgressIP has been deleted
		// then we need to remove the setup made for it, but not update the
		// object.
		egressIP, err := oc.kube.GetEgressIP(egressIPName)
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		egressIPString := cloudPrivateIPConfigNameToIPString(oldCloudPrivateIPConfig.Name)
		statusItem := egressipv1.EgressIPStatusItem{
			Node:     nodeToDelete,
			EgressIP: egressIPString,
		}
		if err := oc.deleteEgressIPAssignments(egressIPName, []egressipv1.EgressIPStatusItem{statusItem}); err != nil {
			return err
		}
		// If the EgressIP has been deleted just return at this point.
		if apierrors.IsNotFound(err) {
			return nil
		}
		// Deleting a status here means updating the object with the statuses we
		// want to keep
		updatedStatus := []egressipv1.EgressIPStatusItem{}
		for _, status := range egressIP.Status.Items {
			if !reflect.DeepEqual(status, statusItem) {
				updatedStatus = append(updatedStatus, status)
			}
		}
		if err := oc.patchReplaceEgressIPStatus(egressIP.Name, updatedStatus); err != nil {
			return err
		}
	}
	if shouldAdd {
		// Get the EgressIP owner reference
		egressIPName, exists := newCloudPrivateIPConfig.Annotations[util.OVNEgressIPOwnerRefLabel]
		if !exists {
			return fmt.Errorf("CloudPrivateIPConfig object: %s is missing the egress IP owner reference annotation", newCloudPrivateIPConfig.Name)
		}
		egressIP, err := oc.kube.GetEgressIP(egressIPName)
		if err != nil {
			return err
		}
		egressIPString := cloudPrivateIPConfigNameToIPString(newCloudPrivateIPConfig.Name)
		statusItem := egressipv1.EgressIPStatusItem{
			Node:     newCloudPrivateIPConfig.Status.Node,
			EgressIP: egressIPString,
		}
		if err := oc.addEgressIPAssignments(egressIP.Name, []egressipv1.EgressIPStatusItem{statusItem}, egressIP.Spec.NamespaceSelector, egressIP.Spec.PodSelector); err != nil {
			return err
		}
		// Guard against performing the same assignment twice, which might
		// happen when multiple updates come in on the same object.
		hasStatus := false
		for _, status := range egressIP.Status.Items {
			if reflect.DeepEqual(status, statusItem) {
				hasStatus = true
				break
			}
		}
		if !hasStatus {
			statusToKeep := append(egressIP.Status.Items, statusItem)
			if err := oc.patchReplaceEgressIPStatus(egressIP.Name, statusToKeep); err != nil {
				return err
			}
		}
	}
	return nil
}

type cloudPrivateIPConfigOp struct {
	toAdd    string
	toDelete string
}

// executeCloudPrivateIPConfigChange computes a diff between what needs to be
// assigned/removed and executes the object modification afterwards.
// Specifically: if one egress IP is moved from nodeA to nodeB, we actually care
// about an update on the CloudPrivateIPConfig object represented by that egress
// IP, cloudPrivateIPConfigOp is a helper used to determine that sort of
// operations from toAssign/toRemove
func (oc *Controller) executeCloudPrivateIPConfigChange(egressIPName string, toAssign, toRemove []egressipv1.EgressIPStatusItem) error {
	ops := make(map[string]*cloudPrivateIPConfigOp, len(toAssign)+len(toRemove))
	for _, assignment := range toAssign {
		ops[assignment.EgressIP] = &cloudPrivateIPConfigOp{
			toAdd: assignment.Node,
		}
	}
	for _, removal := range toRemove {
		if op, exists := ops[removal.EgressIP]; exists {
			op.toDelete = removal.Node
		} else {
			ops[removal.EgressIP] = &cloudPrivateIPConfigOp{
				toDelete: removal.Node,
			}
		}
	}
	return oc.executeCloudPrivateIPConfigOps(egressIPName, ops)
}

func (oc *Controller) executeCloudPrivateIPConfigOps(egressIPName string, ops map[string]*cloudPrivateIPConfigOp) error {
	for egressIP, op := range ops {
		cloudPrivateIPConfigName := ipStringToCloudPrivateIPConfigName(egressIP)
		cloudPrivateIPConfig, err := oc.watchFactory.GetCloudPrivateIPConfig(cloudPrivateIPConfigName)
		// toAdd and toDelete is non-empty, this indicates an UPDATE for which
		// the object **must** exist, if not: that's an error.
		if op.toAdd != "" && op.toDelete != "" {
			if err != nil {
				return fmt.Errorf("cloud update request failed for CloudPrivateIPConfig: %s, could not get item, err: %v", cloudPrivateIPConfigName, err)
			}
			// Do not update if object is being deleted
			if !cloudPrivateIPConfig.GetDeletionTimestamp().IsZero() {
				return fmt.Errorf("cloud update request failed, CloudPrivateIPConfig: %s is being deleted", cloudPrivateIPConfigName)
			}
			cloudPrivateIPConfig.Spec.Node = op.toAdd
			if _, err := oc.kube.UpdateCloudPrivateIPConfig(cloudPrivateIPConfig); err != nil {
				eIPRef := kapi.ObjectReference{
					Kind: "EgressIP",
					Name: egressIPName,
				}
				oc.recorder.Eventf(&eIPRef, kapi.EventTypeWarning, "CloudUpdateFailed", "egress IP: %s for object EgressIP: %s could not be updated, err: %v", egressIP, egressIPName, err)
				return fmt.Errorf("cloud update request failed for CloudPrivateIPConfig: %s, err: %v", cloudPrivateIPConfigName, err)
			}
			// toAdd is non-empty, this indicates an ADD
			// if the object already exists for the specified node that's a no-op
			// if the object already exists and the request is for a different node, that's an error
		} else if op.toAdd != "" {
			if err == nil {
				if op.toAdd == cloudPrivateIPConfig.Spec.Node {
					klog.Infof("CloudPrivateIPConfig: %s already assigned to node: %s", cloudPrivateIPConfigName, cloudPrivateIPConfig.Spec.Node)
					continue
				}
				return fmt.Errorf("cloud create request failed for CloudPrivateIPConfig: %s, err: item exists", cloudPrivateIPConfigName)
			}
			cloudPrivateIPConfig := ocpcloudnetworkapi.CloudPrivateIPConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
					Annotations: map[string]string{
						util.OVNEgressIPOwnerRefLabel: egressIPName,
					},
				},
				Spec: ocpcloudnetworkapi.CloudPrivateIPConfigSpec{
					Node: op.toAdd,
				},
			}
			if _, err := oc.kube.CreateCloudPrivateIPConfig(&cloudPrivateIPConfig); err != nil {
				eIPRef := kapi.ObjectReference{
					Kind: "EgressIP",
					Name: egressIPName,
				}
				oc.recorder.Eventf(&eIPRef, kapi.EventTypeWarning, "CloudAssignmentFailed", "egress IP: %s for object EgressIP: %s could not be created, err: %v", egressIP, egressIPName, err)
				return fmt.Errorf("cloud add request failed for CloudPrivateIPConfig: %s, err: %v", cloudPrivateIPConfigName, err)
			}
			// toDelete is non-empty, this indicates an DELETE for which
			// the object **must** exist, if not: that's an error.
		} else if op.toDelete != "" {
			if err != nil {
				return fmt.Errorf("cloud deletion request failed for CloudPrivateIPConfig: %s, could not get item, err: %v", cloudPrivateIPConfigName, err)
			}
			if err := oc.kube.DeleteCloudPrivateIPConfig(cloudPrivateIPConfigName); err != nil {
				eIPRef := kapi.ObjectReference{
					Kind: "EgressIP",
					Name: egressIPName,
				}
				oc.recorder.Eventf(&eIPRef, kapi.EventTypeWarning, "CloudDeletionFailed", "egress IP: %s for object EgressIP: %s could not be deleted, err: %v", egressIP, egressIPName, err)
				return fmt.Errorf("cloud deletion request failed for CloudPrivateIPConfig: %s, err: %v", cloudPrivateIPConfigName, err)
			}
		}
	}
	return nil
}

func (oc *Controller) validateEgressIPSpec(name string, egressIPs []string) (sets.String, error) {
	validatedEgressIPs := sets.NewString()
	for _, egressIP := range egressIPs {
		ip := net.ParseIP(egressIP)
		if ip == nil {
			eIPRef := kapi.ObjectReference{
				Kind: "EgressIP",
				Name: name,
			}
			oc.recorder.Eventf(&eIPRef, kapi.EventTypeWarning, "InvalidEgressIP", "egress IP: %s for object EgressIP: %s is not a valid IP address", egressIP, name)
			return nil, fmt.Errorf("unable to parse provided EgressIP: %s, invalid", egressIP)
		}
		validatedEgressIPs.Insert(ip.String())
	}
	return validatedEgressIPs, nil
}

// validateEgressIPStatus validates if the statuses are valid given what the
// cache knows about all egress nodes. WatchEgressNodes is initialized before
// any other egress IP handler, so te cache should be warm and correct once we
// start going this.
func (oc *Controller) validateEgressIPStatus(name string, items []egressipv1.EgressIPStatusItem) (map[egressipv1.EgressIPStatusItem]string, map[egressipv1.EgressIPStatusItem]string) {
	oc.eIPC.allocator.Lock()
	defer oc.eIPC.allocator.Unlock()
	valid, invalid := make(map[egressipv1.EgressIPStatusItem]string), make(map[egressipv1.EgressIPStatusItem]string)
	for _, eIPStatus := range items {
		validAssignment := true
		eNode, exists := oc.eIPC.allocator.cache[eIPStatus.Node]
		if !exists {
			klog.Errorf("Allocator error: EgressIP: %s claims to have an allocation on a node which is unassignable for egress IP: %s", name, eIPStatus.Node)
			validAssignment = false
		} else {
			if eNode.getAllocationCountForEgressIP(name) > 1 {
				klog.Errorf("Allocator error: EgressIP: %s claims multiple egress IPs on same node: %s, will attempt rebalancing", name, eIPStatus.Node)
				validAssignment = false
			}
			if !eNode.isEgressAssignable {
				klog.Errorf("Allocator error: EgressIP: %s assigned to node: %s which does not have egress label, will attempt rebalancing", name, eIPStatus.Node)
				validAssignment = false
			}
			if !eNode.isReachable {
				klog.Errorf("Allocator error: EgressIP: %s assigned to node: %s which is not reachable, will attempt rebalancing", name, eIPStatus.Node)
				validAssignment = false
			}
			if !eNode.isReady {
				klog.Errorf("Allocator error: EgressIP: %s assigned to node: %s which is not ready, will attempt rebalancing", name, eIPStatus.Node)
				validAssignment = false
			}
			ip := net.ParseIP(eIPStatus.EgressIP)
			if ip == nil {
				klog.Errorf("Allocator error: EgressIP allocation contains unparsable IP address: %s", eIPStatus.EgressIP)
				validAssignment = false
			}
			if node := oc.isAnyClusterNodeIP(ip); node != nil {
				klog.Errorf("Allocator error: EgressIP allocation: %s is the IP of node: %s ", ip.String(), node.name)
				validAssignment = false
			}
			if utilnet.IsIPv6(ip) && eNode.egressIPConfig.V6.Net != nil {
				if !eNode.egressIPConfig.V6.Net.Contains(ip) {
					klog.Errorf("Allocator error: EgressIP allocation: %s on subnet: %s which cannot host it", ip.String(), eNode.egressIPConfig.V4.Net.String())
					validAssignment = false
				}
			} else if !utilnet.IsIPv6(ip) && eNode.egressIPConfig.V4.Net != nil {
				if !eNode.egressIPConfig.V4.Net.Contains(ip) {
					klog.Errorf("Allocator error: EgressIP allocation: %s on subnet: %s which cannot host it", ip.String(), eNode.egressIPConfig.V4.Net.String())
					validAssignment = false
				}
			} else {
				klog.Errorf("Allocator error: EgressIP allocation on node: %s which does not support its IP protocol version", eIPStatus.Node)
				validAssignment = false
			}
		}
		if validAssignment {
			valid[eIPStatus] = ""
		} else {
			invalid[eIPStatus] = ""
		}
	}
	return valid, invalid
}

// addAllocatorEgressIPAssignments adds the allocation to the cache, so that
// they are tracked during the life-cycle of ovnkube-master
func (oc *Controller) addAllocatorEgressIPAssignments(name string, statusAssignments []egressipv1.EgressIPStatusItem) {
	oc.eIPC.allocator.Lock()
	defer oc.eIPC.allocator.Unlock()
	for _, status := range statusAssignments {
		if eNode, exists := oc.eIPC.allocator.cache[status.Node]; exists {
			eNode.allocations[status.EgressIP] = name
		}
	}
}

func (oc *Controller) addEgressIPAssignments(name string, statusAssignments []egressipv1.EgressIPStatusItem, namespaceSelector, podSelector metav1.LabelSelector) error {
	namespaces, err := oc.watchFactory.GetNamespacesBySelector(namespaceSelector)
	if err != nil {
		return err
	}
	for _, namespace := range namespaces {
		if err := oc.addNamespaceEgressIPAssignments(name, statusAssignments, namespace, podSelector); err != nil {
			return err
		}
	}
	return nil
}

func (oc *Controller) addNamespaceEgressIPAssignments(name string, statusAssignments []egressipv1.EgressIPStatusItem, namespace *kapi.Namespace, podSelector metav1.LabelSelector) error {
	var pods []*kapi.Pod
	var err error
	selector, _ := metav1.LabelSelectorAsSelector(&podSelector)
	if !selector.Empty() {
		pods, err = oc.watchFactory.GetPodsBySelector(namespace.Name, podSelector)
		if err != nil {
			return err
		}
	} else {
		pods, err = oc.watchFactory.GetPods(namespace.Name)
		if err != nil {
			return err
		}
	}
	for _, pod := range pods {
		if err := oc.addPodEgressIPAssignmentsWithLock(name, statusAssignments, pod); err != nil {
			return err
		}
	}
	return nil
}

func (oc *Controller) addPodEgressIPAssignmentsWithLock(name string, statusAssignments []egressipv1.EgressIPStatusItem, pod *kapi.Pod) error {
	oc.eIPC.podAssignmentMutex.Lock()
	defer oc.eIPC.podAssignmentMutex.Unlock()
	return oc.addPodEgressIPAssignments(name, statusAssignments, pod)
}

// addPodEgressIPAssignments tracks the setup made for each egress IP matching
// pod w.r.t to each status. This is mainly done to avoid a lot of duplicated
// work on ovnkube-master restarts when all egress IP handlers will most likely
// match and perform the setup for the same pod and status multiple times over.
func (oc *Controller) addPodEgressIPAssignments(name string, statusAssignments []egressipv1.EgressIPStatusItem, pod *kapi.Pod) error {
	// If statusAssignments is empty just return, not doing this will delete the
	// external GW set up, even though there might be no egress IP set up to
	// perform.
	if len(statusAssignments) == 0 {
		return nil
	}
	var remainingAssignments []egressipv1.EgressIPStatusItem
	podKey := getPodKey(pod)
	// Retrieve the pod's networking configuration from the
	// logicalPortCache. The reason for doing this: a) only normal network
	// pods are placed in this cache, b) once the pod is placed here we know
	// addLogicalPort has finished successfully setting up networking for
	// the pod, so we can proceed with retrieving its IP and deleting the
	// external GW configuration created in addLogicalPort for the pod.
	logicalPort, err := oc.logicalPortCache.get(util.GetLogicalPortName(pod.Namespace, pod.Name))
	if err != nil {
		return nil
	}
	// Since the logical switch port cache removes entries only 60 seconds
	// after deletion, its possible that when pod is recreated with the same name
	// within the 60seconds timer, stale info gets used to create SNATs and reroutes
	// for the eip pods. Checking if the expiry is set for the port or not can indicate
	// if the port is scheduled for deletion.
	if !logicalPort.expires.IsZero() {
		klog.Warningf("Stale LSP %s for pod %s found in cache refetching",
			logicalPort.name, podKey)
		return nil
	}
	podState, exists := oc.eIPC.podAssignment[podKey]
	if !exists {
		remainingAssignments = statusAssignments
		podState = &podAssignmentState{
			egressIPName:         name,
			egressStatuses:       make(map[egressipv1.EgressIPStatusItem]string),
			standbyEgressIPNames: sets.NewString(),
		}
		oc.eIPC.podAssignment[podKey] = podState
	} else if podState.egressIPName == name || podState.egressIPName == "" {
		// We do the setup only if this egressIP object is the one serving this pod OR
		// podState.egressIPName can be empty if no re-routes were found in
		// syncPodAssignmentCache for the existing pod, we will treat this case as a new add
		for _, status := range statusAssignments {
			if _, exists := podState.egressStatuses[status]; !exists {
				remainingAssignments = append(remainingAssignments, status)
			}
		}
		podState.egressIPName = name
		podState.standbyEgressIPNames.Delete(name)
	} else if podState.egressIPName != name {
		klog.Warningf("EgressIP object %s will not be configured for pod %s "+
			"since another egressIP object %s is serving it", name, podKey, podState.egressIPName)
		eIPRef := kapi.ObjectReference{
			Kind: "EgressIP",
			Name: name,
		}
		oc.recorder.Eventf(
			&eIPRef,
			kapi.EventTypeWarning,
			"UndefinedRequest",
			"EgressIP object %s will not be configured for pod %s since another egressIP object %s is serving it, this is undefined", name, podKey, podState.egressIPName,
		)
		podState.standbyEgressIPNames.Insert(name)
		return nil
	}
	for _, status := range remainingAssignments {
		klog.V(2).Infof("Adding pod egress IP status: %v for EgressIP: %s and pod: %s/%s", status, name, pod.Name, pod.Namespace)
		if err := oc.eIPC.addPodEgressIPAssignment(name, status, pod, logicalPort.ips); err != nil {
			return err
		}
		podState.egressStatuses[status] = ""
	}
	return nil
}

// deleteAllocatorEgressIPAssignments deletes the allocation as to keep the
// cache state correct, also see addAllocatorEgressIPAssignments
func (oc *Controller) deleteAllocatorEgressIPAssignments(statusAssignments []egressipv1.EgressIPStatusItem) {
	oc.eIPC.allocator.Lock()
	defer oc.eIPC.allocator.Unlock()
	for _, status := range statusAssignments {
		if eNode, exists := oc.eIPC.allocator.cache[status.Node]; exists {
			delete(eNode.allocations, status.EgressIP)
		}
	}
}

// deleteEgressIPAssignments performs a full egress IP setup deletion on a per
// (egress IP name - status) basis. The idea is thus to list the full content of
// the NB DB for that egress IP object and delete everything which match the
// status. We also need to update the podAssignment cache and finally re-add the
// external GW setup in case the pod still exists.
func (oc *Controller) deleteEgressIPAssignments(name string, statusesToRemove []egressipv1.EgressIPStatusItem) error {
	oc.eIPC.podAssignmentMutex.Lock()
	defer oc.eIPC.podAssignmentMutex.Unlock()
	for _, statusToRemove := range statusesToRemove {
		klog.V(2).Infof("Deleting pod egress IP status: %v for EgressIP: %s", statusToRemove, name)
		if err := oc.eIPC.deleteEgressIPStatusSetup(name, statusToRemove); err != nil {
			return err
		}
		for podKey, podStatus := range oc.eIPC.podAssignment {
			if podStatus.egressIPName != name {
				// we can continue here since this pod was not managed by this EIP object
				podStatus.standbyEgressIPNames.Delete(name)
				continue
			}
			if _, ok := podStatus.egressStatuses[statusToRemove]; !ok {
				// we can continue here since this pod was not managed by this statusToRemove
				continue
			}
			// this pod was managed by statusToRemove.EgressIP; we need to try and add its SNAT back towards nodeIP
			podNamespace, podName := getPodNamespaceAndNameFromKey(podKey)
			if err := oc.eIPC.addExternalGWPodSNAT(podNamespace, podName, statusToRemove); err != nil {
				return err
			}
			delete(podStatus.egressStatuses, statusToRemove)
			if len(podStatus.egressStatuses) == 0 && len(podStatus.standbyEgressIPNames) == 0 {
				// pod could be managed by more than one egressIP
				// so remove the podKey from cache only if we are sure
				// there are no more egressStatuses managing this pod
				klog.V(5).Infof("Deleting pod key %s from assignment cache", podKey)
				delete(oc.eIPC.podAssignment, podKey)
			} else if len(podStatus.egressStatuses) == 0 && len(podStatus.standbyEgressIPNames) > 0 {
				klog.V(2).Infof("Pod %s has standby egress IP %+v", podKey, podStatus.standbyEgressIPNames.UnsortedList())
				podStatus.egressIPName = "" // we have deleted the current egressIP that was managing the pod
				if err := oc.addStandByEgressIPAssignment(podKey, podStatus); err != nil {
					klog.Errorf("Adding standby egressIPs for pod %s with status %v failed: %v", podKey, podStatus, err)
					// We are not returning the error on purpose, this will be best effort without any retries because
					// retrying deleteEgressIPAssignments for original EIP because addStandByEgressIPAssignment failed is useless.
					// Since we delete statusToRemove from podstatus.egressStatuses the first time we call this function,
					// later when the operation is retried we will never continue down the loop
					// since we add SNAT to node only if this pod was managed by statusToRemove
					return nil
				}
			}
		}
	}
	return nil
}

func (oc *Controller) deleteNamespaceEgressIPAssignment(name string, statusAssignments []egressipv1.EgressIPStatusItem, namespace *kapi.Namespace, podSelector metav1.LabelSelector) error {
	var pods []*kapi.Pod
	var err error
	selector, _ := metav1.LabelSelectorAsSelector(&podSelector)
	if !selector.Empty() {
		pods, err = oc.watchFactory.GetPodsBySelector(namespace.Name, podSelector)
		if err != nil {
			return err
		}
	} else {
		pods, err = oc.watchFactory.GetPods(namespace.Name)
		if err != nil {
			return err
		}
	}
	for _, pod := range pods {
		if err := oc.deletePodEgressIPAssignments(name, statusAssignments, pod); err != nil {
			return err
		}
	}
	return nil
}

func (oc *Controller) deletePodEgressIPAssignments(name string, statusesToRemove []egressipv1.EgressIPStatusItem, pod *kapi.Pod) error {
	oc.eIPC.podAssignmentMutex.Lock()
	defer oc.eIPC.podAssignmentMutex.Unlock()
	podKey := getPodKey(pod)
	podStatus, exists := oc.eIPC.podAssignment[podKey]
	if !exists {
		return nil
	} else if podStatus.egressIPName != name {
		// standby egressIP no longer matches this pod, update cache
		podStatus.standbyEgressIPNames.Delete(name)
		return nil
	}
	podIPs, err := util.GetPodCIDRsWithFullMask(pod)
	if err != nil {
		return err
	}
	for _, statusToRemove := range statusesToRemove {
		klog.V(2).Infof("Deleting pod egress IP status: %v for EgressIP: %s and pod: %s/%s", statusToRemove, name, pod.Name, pod.Namespace)
		if err := oc.eIPC.deletePodEgressIPAssignment(name, statusToRemove, podIPs); err != nil {
			return err
		}
		if err := oc.eIPC.addExternalGWPodSNAT(pod.Namespace, pod.Name, statusToRemove); err != nil {
			return err
		}
		delete(podStatus.egressStatuses, statusToRemove)
	}
	// Delete the key if there are no more status assignments to keep
	// for the pod.
	if len(podStatus.egressStatuses) == 0 {
		// pod could be managed by more than one egressIP
		// so remove the podKey from cache only if we are sure
		// there are no more egressStatuses managing this pod
		klog.V(5).Infof("Deleting pod key %s from assignment cache", podKey)
		delete(oc.eIPC.podAssignment, podKey)
	}
	return nil
}

func (oc *Controller) isEgressNodeReady(egressNode *kapi.Node) bool {
	for _, condition := range egressNode.Status.Conditions {
		if condition.Type == v1.NodeReady {
			return condition.Status == v1.ConditionTrue
		}
	}
	return false
}

func (oc *Controller) isEgressNodeReachable(egressNode *kapi.Node) bool {
	oc.eIPC.allocator.Lock()
	defer oc.eIPC.allocator.Unlock()
	if eNode, exists := oc.eIPC.allocator.cache[egressNode.Name]; exists {
		return eNode.isReachable || oc.isReachable(eNode)
	}
	return false
}

type egressIPCacheEntry struct {
	egressPods       map[string]sets.String
	gatewayRouterIPs sets.String
	egressIPs        sets.String
}

func (oc *Controller) syncEgressIPs(namespaces []interface{}) {
	// This part will take of syncing stale data which we might have in OVN if
	// there's no ovnkube-master running for a while, while there are changes to
	// pods/egress IPs.
	// It will sync:
	// - Egress IPs which have been deleted while ovnkube-master was down
	// - pods/namespaces which have stopped matching on egress IPs while
	//   ovnkube-master was down
	// This function is called when handlers for EgressIPNamespaceType are started
	// since namespaces is the first object that egressIP feature starts watching
	oc.syncWithRetry("syncEgressIPs", func() error {
		egressIPCache, err := oc.generateCacheForEgressIP()
		if err != nil {
			return fmt.Errorf("syncEgressIPs unable to generate cache for egressip: %v", err)
		}
		if err = oc.syncStaleEgressReroutePolicy(egressIPCache); err != nil {
			return fmt.Errorf("syncEgressIPs unable to remove stale reroute policies: %v", err)
		}
		if err = oc.syncStaleSNATRules(egressIPCache); err != nil {
			return fmt.Errorf("syncEgressIPs unable to remove stale nats: %v", err)
		}
		if err = oc.syncPodAssignmentCache(egressIPCache); err != nil {
			return fmt.Errorf("syncEgressIPs unable to sync internal pod assignment cache: %v", err)
		}
		return nil
	})
}

// syncPodAssignmentCache rebuilds the internal pod cache used by the egressIP feature.
// We use the existing kapi and ovn-db information to populate oc.eIPC.podAssignment cache for
// all the pods that are managed by egressIPs.
// NOTE: This is done mostly to handle the corner case where one pod has more than one
// egressIP object matching it, in which case we do the ovn setup only for one of the objects.
func (oc *Controller) syncPodAssignmentCache(egressIPCache map[string]egressIPCacheEntry) error {
	oc.eIPC.podAssignmentMutex.Lock()
	defer oc.eIPC.podAssignmentMutex.Unlock()
	for egressIPName, state := range egressIPCache {
		p := func(item *nbdb.LogicalRouterPolicy) bool {
			return item.Priority == types.EgressIPReroutePriority && item.ExternalIDs["name"] == egressIPName
		}
		reRoutePolicies, err := libovsdbops.FindLogicalRouterPoliciesWithPredicate(oc.nbClient, p)
		if err != nil {
			return err
		}
		for podKey, podIPs := range state.egressPods {
			podState, ok := oc.eIPC.podAssignment[podKey]
			if !ok {
				podState = &podAssignmentState{
					egressStatuses:       make(map[egressipv1.EgressIPStatusItem]string),
					standbyEgressIPNames: sets.NewString(),
				}
			}

			podState.standbyEgressIPNames.Insert(egressIPName)
			for _, policy := range reRoutePolicies {
				splitMatch := strings.Split(policy.Match, " ")
				if len(splitMatch) <= 0 {
					continue
				}
				logicalIP := splitMatch[len(splitMatch)-1]
				parsedLogicalIP := net.ParseIP(logicalIP)
				if parsedLogicalIP == nil {
					continue
				}

				if podIPs.Has(parsedLogicalIP.String()) { // should match for only one egressIP object
					podState.egressIPName = egressIPName
					podState.standbyEgressIPNames.Delete(egressIPName)
					klog.Infof("EgressIP %s is managing pod %s", egressIPName, podKey)
				}
			}
			oc.eIPC.podAssignment[podKey] = podState
		}
	}

	return nil
}

// This function implements a portion of syncEgressIPs.
// It removes OVN logical router policies used by EgressIPs deleted while ovnkube-master was down.
// It also removes stale nexthops from router policies used by EgressIPs.
// Upon failure, it may be invoked multiple times in order to avoid a pod restart.
func (oc *Controller) syncStaleEgressReroutePolicy(egressIPCache map[string]egressIPCacheEntry) error {
	logicalRouter := nbdb.LogicalRouter{}
	logicalRouterPolicyRes := []nbdb.LogicalRouterPolicy{}
	logicalRouterPolicyStaleNexthops := make(map[string]nbdb.LogicalRouterPolicy)
	opModels := []libovsdbops.OperationModel{
		{
			ModelPredicate: func(lrp *nbdb.LogicalRouterPolicy) bool {
				if lrp.Priority != types.EgressIPReroutePriority {
					return false
				}
				egressIPName := lrp.ExternalIDs["name"]
				cacheEntry, exists := egressIPCache[egressIPName]
				splitMatch := strings.Split(lrp.Match, " ")
				logicalIP := splitMatch[len(splitMatch)-1]
				parsedLogicalIP := net.ParseIP(logicalIP)
				egressPodIPs := sets.NewString()
				if exists {
					for _, podIPs := range cacheEntry.egressPods {
						egressPodIPs.Insert(podIPs.UnsortedList()...)
					}
				}
				if !exists || cacheEntry.gatewayRouterIPs.Len() == 0 || !egressPodIPs.Has(parsedLogicalIP.String()) {
					klog.Infof("syncStaleEgressReroutePolicy will delete %s due to no nexthop or stale logical ip: %v", egressIPName, lrp)
					return true
				}
				// Check for stale nexthops that may exist in the logical router policy and store that in logicalRouterPolicyStaleNexthops.
				// Note: adding missing nexthop(s) to the logical router policy is done outside the scope of this function.
				onlyStaleNextHops := true
				staleNextHops := sets.NewString()
				for _, nexthop := range lrp.Nexthops {
					if cacheEntry.gatewayRouterIPs.Has(nexthop) {
						onlyStaleNextHops = false
					} else {
						staleNextHops.Insert(nexthop)
					}
				}
				if staleNextHops.Len() > 0 {
					// If all nexthops are stale, let's go ahead and remove the entire row
					if onlyStaleNextHops {
						klog.Infof("syncStaleEgressReroutePolicy will delete %s due to stale nexthops: %v", egressIPName, lrp)
						return true
					}
					logicalRouterPolicyStaleNexthops[lrp.UUID] = nbdb.LogicalRouterPolicy{
						UUID:     lrp.UUID,
						Nexthops: staleNextHops.UnsortedList(),
					}
				}
				return false
			},
			ExistingResult: &logicalRouterPolicyRes,
			DoAfter: func() {
				logicalRouter.Policies = libovsdbops.ExtractUUIDsFromModels(&logicalRouterPolicyRes)
			},
			BulkOp: true,
		},
		{
			Model:          &logicalRouter,
			ModelPredicate: func(lr *nbdb.LogicalRouter) bool { return lr.Name == types.OVNClusterRouter },
			OnModelMutations: []interface{}{
				&logicalRouter.Policies,
			},
		},
	}
	if err := oc.modelClient.Delete(opModels...); err != nil {
		return fmt.Errorf("unable to remove stale logical router policies, err: %v", err)
	}

	// Update Logical Router Policies that have stale nexthops. Notice that we must do this separately
	// because 1) there is no model predicates, and 2) logicalRouterPolicyStaleNexthops must be populated
	opModels2 := make([]libovsdbops.OperationModel, 0, len(logicalRouterPolicyStaleNexthops))
	for lrpUUID := range logicalRouterPolicyStaleNexthops {
		lrp := logicalRouterPolicyStaleNexthops[lrpUUID]
		klog.Infof("syncStaleEgressReroutePolicy will update %s to remove stale nexthops: %v", lrp.UUID, lrp.Nexthops)
		opModels2 = append(opModels2, libovsdbops.OperationModel{
			Model: &lrp,
			OnModelMutations: []interface{}{
				&lrp.Nexthops,
			},
		})
	}
	if err := oc.modelClient.Delete(opModels2...); err != nil {
		return fmt.Errorf("unable to remove stale next hops from logical router policies, err: %v", err)
	}

	return nil
}

// This function implements a portion of syncEgressIPs.
// It removes OVN NAT rules used by EgressIPs deleted while ovnkube-master was down.
// Upon failure, it may be invoked multiple times in order to avoid a pod restart.
func (oc *Controller) syncStaleSNATRules(egressIPCache map[string]egressIPCacheEntry) error {
	predicate := func(item *nbdb.NAT) bool {
		egressIPName, exists := item.ExternalIDs["name"]
		// Exclude rows that have no name or are not the right type
		if !exists || item.Type != nbdb.NATTypeSNAT {
			return false
		}
		parsedLogicalIP := net.ParseIP(item.LogicalIP).String()
		cacheEntry, exists := egressIPCache[egressIPName]
		egressPodIPs := sets.NewString()
		if exists {
			for _, podIPs := range cacheEntry.egressPods {
				egressPodIPs.Insert(podIPs.UnsortedList()...)
			}
		}
		if !exists || !egressPodIPs.Has(parsedLogicalIP) {
			klog.Infof("syncStaleSNATRules will delete %s due to logical ip: %v", egressIPName, item)
			return true
		}
		if !cacheEntry.egressIPs.Has(item.ExternalIP) {
			klog.Infof("syncStaleSNATRules will delete %s due to external ip: %v", egressIPName, item)
			return true
		}
		return false
	}

	nats, err := libovsdbops.FindNATsUsingPredicate(oc.nbClient, predicate)
	if err != nil {
		return fmt.Errorf("unable to sync egress IPs err: %v", err)
	}

	if len(nats) == 0 {
		// No stale nat entries to deal with: noop.
		return nil
	}

	routers, err := libovsdbops.FindRoutersUsingNAT(oc.nbClient, nats)
	if err != nil {
		return fmt.Errorf("unable to sync egress IPs, err: %v", err)
	}

	var errors []error
	ops := []ovsdb.Operation{}
	for _, router := range routers {
		ops, err = libovsdbops.DeleteNATsFromRouterOps(oc.nbClient, ops, &router, nats...)
		if err != nil {
			klog.Errorf("Error deleting stale NAT from router %s: %v", router.Name, err)
			errors = append(errors, err)
			continue
		}
	}
	if len(errors) > 0 {
		return fmt.Errorf("failed deleting stale NAT: %v", utilerrors.NewAggregate(errors))
	}

	_, err = libovsdbops.TransactAndCheck(oc.nbClient, ops)
	if err != nil {
		return fmt.Errorf("error deleting stale NATs: %v", err)
	}
	return nil
}

// generateCacheForEgressIP builds a cache of egressIP name -> podIPs for fast
// access when syncing egress IPs. The Egress IP setup will return a lot of
// atomic items with the same general information repeated across most (egressIP
// name, logical IP defined for that name), hence use a cache to avoid round
// trips to the API server per item.
func (oc *Controller) generateCacheForEgressIP() (map[string]egressIPCacheEntry, error) {
	egressIPCache := make(map[string]egressIPCacheEntry)
	egressIPs, err := oc.watchFactory.GetEgressIPs()
	if err != nil {
		return nil, err
	}
	for _, egressIP := range egressIPs {
		egressIPCache[egressIP.Name] = egressIPCacheEntry{
			egressPods:       make(map[string]sets.String),
			gatewayRouterIPs: sets.NewString(),
			egressIPs:        sets.NewString(),
		}
		for _, status := range egressIP.Status.Items {
			isEgressIPv6 := utilnet.IsIPv6String(status.EgressIP)
			gatewayRouterIP, err := oc.eIPC.getGatewayRouterJoinIP(status.Node, isEgressIPv6)
			if err != nil {
				klog.Errorf("Unable to retrieve gateway IP for node: %s, protocol is IPv6: %v, err: %v", status.Node, isEgressIPv6, err)
				continue
			}
			egressIPCache[egressIP.Name].gatewayRouterIPs.Insert(gatewayRouterIP.String())
			egressIPCache[egressIP.Name].egressIPs.Insert(status.EgressIP)
		}
		namespaces, err := oc.watchFactory.GetNamespacesBySelector(egressIP.Spec.NamespaceSelector)
		if err != nil {
			klog.Errorf("Error building egress IP sync cache, cannot retrieve namespaces for EgressIP: %s, err: %v", egressIP.Name, err)
			continue
		}
		for _, namespace := range namespaces {
			pods, err := oc.watchFactory.GetPodsBySelector(namespace.Name, egressIP.Spec.PodSelector)
			if err != nil {
				klog.Errorf("Error building egress IP sync cache, cannot retrieve pods for namespace: %s and egress IP: %s, err: %v", namespace.Name, egressIP.Name, err)
				continue
			}
			for _, pod := range pods {
				if util.PodCompleted(pod) {
					continue
				}
				// FIXME(trozet): potential race where pod is not yet added in the cache by the pod handler
				logicalPort, err := oc.logicalPortCache.get(util.GetLogicalPortName(pod.Namespace, pod.Name))
				if err != nil {
					klog.Errorf("Error getting logical port %s, err: %v", util.GetLogicalPortName(pod.Namespace, pod.Name), err)
					continue
				}
				podKey := getPodKey(pod)
				_, ok := egressIPCache[egressIP.Name].egressPods[podKey]
				if !ok {
					egressIPCache[egressIP.Name].egressPods[podKey] = sets.NewString()
				}
				for _, ipNet := range logicalPort.ips {
					egressIPCache[egressIP.Name].egressPods[podKey].Insert(ipNet.IP.String())
				}
			}
		}
	}
	return egressIPCache, nil
}

// isAnyClusterNodeIP verifies that the IP is not any node IP.
func (oc *Controller) isAnyClusterNodeIP(ip net.IP) *egressNode {
	for _, eNode := range oc.eIPC.allocator.cache {
		if ip.Equal(eNode.egressIPConfig.V6.IP) || ip.Equal(eNode.egressIPConfig.V4.IP) {
			return eNode
		}
	}
	return nil
}

type EgressIPPatchStatus struct {
	Op    string                    `json:"op"`
	Path  string                    `json:"path"`
	Value egressipv1.EgressIPStatus `json:"value"`
}

// patchReplaceEgressIPStatus performs a replace patch operation of the egress
// IP status by replacing the status with the provided value. This allows us to
// update only the status field, without overwriting any other. This is
// important because processing egress IPs can take a while (when running on a
// public cloud and in the worst case), hence we don't want to perform a full
// object update which risks resetting the EgressIP object's fields to the state
// they had when we started processing the change.
func (oc *Controller) patchReplaceEgressIPStatus(name string, statusItems []egressipv1.EgressIPStatusItem) error {
	klog.Infof("Patching status on EgressIP %s: %v", name, statusItems)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		t := []EgressIPPatchStatus{
			{
				Op:   "replace",
				Path: "/status",
				Value: egressipv1.EgressIPStatus{
					Items: statusItems,
				},
			},
		}
		op, err := json.Marshal(&t)
		if err != nil {
			return fmt.Errorf("error serializing status patch operation: %+v, err: %v", statusItems, err)
		}
		return oc.kube.PatchEgressIP(name, op)
	})
}

// assignEgressIPs is the main assignment algorithm for egress IPs to nodes.
// Specifically we have a couple of hard constraints: a) the subnet of the node
// must be able to host the egress IP b) the egress IP cannot be a node IP c)
// the IP cannot already be assigned and reference by another EgressIP object d)
// no two egress IPs for the same EgressIP object can be assigned to the same
// node e) (for public clouds) the amount of egress IPs assigned to one node
// must respect its assignment capacity. Moreover there is a soft constraint:
// the assignments need to be balanced across all cluster nodes, so that no node
// becomes a bottleneck. The balancing is achieved by sorting the nodes in
// ascending order following their existing amount of allocations, and trying to
// assign the egress IP to the node with the lowest amount of allocations every
// time, this does not guarantee complete balance, but mostly complete.
func (oc *Controller) assignEgressIPs(name string, egressIPs []string) []egressipv1.EgressIPStatusItem {
	oc.eIPC.allocator.Lock()
	defer oc.eIPC.allocator.Unlock()
	assignments := []egressipv1.EgressIPStatusItem{}
	assignableNodes, existingAllocations := oc.getSortedEgressData()
	if len(assignableNodes) == 0 {
		eIPRef := kapi.ObjectReference{
			Kind: "EgressIP",
			Name: name,
		}
		oc.recorder.Eventf(&eIPRef, kapi.EventTypeWarning, "NoMatchingNodeFound", "no assignable nodes for EgressIP: %s, please tag at least one node with label: %s", name, util.GetNodeEgressLabel())
		klog.Errorf("No assignable nodes found for EgressIP: %s and requested IPs: %v", name, egressIPs)
		return assignments
	}
	klog.V(5).Infof("Current assignments are: %+v", existingAllocations)
	for _, egressIP := range egressIPs {
		klog.V(5).Infof("Will attempt assignment for egress IP: %s", egressIP)
		eIPC := net.ParseIP(egressIP)
		if status, exists := existingAllocations[eIPC.String()]; exists {
			// On public clouds we will re-process assignments for the same IP
			// multiple times due to the nature of syncing each individual
			// CloudPrivateIPConfig one at a time. This means that we are
			// expected to end up in this situation multiple times per sync. Ex:
			// Say we an EgressIP is created with IP1, IP2, IP3. We begin by
			// assigning them all the first round. Next we get the
			// CloudPrivateIPConfig confirming the addition of IP1, leading us
			// to re-assign IP2, IP3, but since we've already assigned them
			// we'll end up here. This is not an error. What would be an error
			// is if the user created EIP1 with IP1 and a second EIP2 with IP1
			if name == status.Name {
				// IP is already assigned for this EgressIP object
				assignments = append(assignments, egressipv1.EgressIPStatusItem{
					Node:     status.Node,
					EgressIP: eIPC.String(),
				})
				continue
			} else {
				klog.Errorf("IP: %q for EgressIP: %s is already allocated for EgressIP: %s on %s", egressIP, name, status.Name, status.Node)
				return assignments
			}
		}
		if node := oc.isAnyClusterNodeIP(eIPC); node != nil {
			eIPRef := kapi.ObjectReference{
				Kind: "EgressIP",
				Name: name,
			}
			oc.recorder.Eventf(
				&eIPRef,
				kapi.EventTypeWarning,
				"UnsupportedRequest",
				"Egress IP: %v for object EgressIP: %s is the IP address of node: %s, this is unsupported", eIPC, name, node.name,
			)
			klog.Errorf("Egress IP: %v is the IP address of node: %s", eIPC, node.name)
			return assignments
		}
		for _, eNode := range assignableNodes {
			klog.V(5).Infof("Attempting assignment on egress node: %+v", eNode)
			if eNode.getAllocationCountForEgressIP(name) > 0 {
				klog.V(5).Infof("Node: %s is already in use by another egress IP for this EgressIP: %s, trying another node", eNode.name, name)
				continue
			}
			if eNode.egressIPConfig.Capacity.IP < util.UnlimitedNodeCapacity {
				if eNode.egressIPConfig.Capacity.IP-len(eNode.allocations) <= 0 {
					klog.V(5).Infof("Additional allocation on Node: %s exhausts it's IP capacity, trying another node", eNode.name)
					continue
				}
			}
			if eNode.egressIPConfig.Capacity.IPv4 < util.UnlimitedNodeCapacity && utilnet.IsIPv4(eIPC) {
				if eNode.egressIPConfig.Capacity.IPv4-getIPFamilyAllocationCount(eNode.allocations, false) <= 0 {
					klog.V(5).Infof("Additional allocation on Node: %s exhausts it's IPv4 capacity, trying another node", eNode.name)
					continue
				}
			}
			if eNode.egressIPConfig.Capacity.IPv6 < util.UnlimitedNodeCapacity && utilnet.IsIPv6(eIPC) {
				if eNode.egressIPConfig.Capacity.IPv6-getIPFamilyAllocationCount(eNode.allocations, true) <= 0 {
					klog.V(5).Infof("Additional allocation on Node: %s exhausts it's IPv6 capacity, trying another node", eNode.name)
					continue
				}
			}
			if (eNode.egressIPConfig.V6.Net != nil && eNode.egressIPConfig.V6.Net.Contains(eIPC)) ||
				(eNode.egressIPConfig.V4.Net != nil && eNode.egressIPConfig.V4.Net.Contains(eIPC)) {
				assignments = append(assignments, egressipv1.EgressIPStatusItem{
					Node:     eNode.name,
					EgressIP: eIPC.String(),
				})
				klog.Infof("Successful assignment of egress IP: %s on node: %+v", egressIP, eNode)
				eNode.allocations[eIPC.String()] = name
				break
			}
		}
	}
	if len(assignments) == 0 {
		eIPRef := kapi.ObjectReference{
			Kind: "EgressIP",
			Name: name,
		}
		oc.recorder.Eventf(&eIPRef, kapi.EventTypeWarning, "NoMatchingNodeFound", "No matching nodes found, which can host any of the egress IPs: %v for object EgressIP: %s", egressIPs, name)
		klog.Errorf("No matching host found for EgressIP: %s", name)
		return assignments
	}
	if len(assignments) < len(egressIPs) {
		eIPRef := kapi.ObjectReference{
			Kind: "EgressIP",
			Name: name,
		}
		oc.recorder.Eventf(&eIPRef, kapi.EventTypeWarning, "UnassignedRequest", "Not all egress IPs for EgressIP: %s could be assigned, please tag more nodes", name)
	}
	return assignments
}

func getIPFamilyAllocationCount(allocations map[string]string, isIPv6 bool) (count int) {
	for allocation := range allocations {
		if utilnet.IsIPv4String(allocation) && !isIPv6 {
			count++
		}
		if utilnet.IsIPv6String(allocation) && isIPv6 {
			count++
		}
	}
	return
}

type egressIPNodeStatus struct {
	Node string
	Name string
}

// getSortedEgressData returns a sorted slice of all egressNodes based on the
// amount of allocations found in the cache
func (oc *Controller) getSortedEgressData() ([]*egressNode, map[string]egressIPNodeStatus) {
	assignableNodes := []*egressNode{}
	allAllocations := make(map[string]egressIPNodeStatus)
	for _, eNode := range oc.eIPC.allocator.cache {
		if eNode.isEgressAssignable && eNode.isReady && eNode.isReachable {
			assignableNodes = append(assignableNodes, eNode)
		}
		for ip, eipName := range eNode.allocations {
			allAllocations[ip] = egressIPNodeStatus{Node: eNode.name, Name: eipName}
		}
	}
	sort.Slice(assignableNodes, func(i, j int) bool {
		return len(assignableNodes[i].allocations) < len(assignableNodes[j].allocations)
	})
	return assignableNodes, allAllocations
}

func (oc *Controller) setNodeEgressAssignable(nodeName string, isAssignable bool) {
	oc.eIPC.allocator.Lock()
	defer oc.eIPC.allocator.Unlock()
	if eNode, exists := oc.eIPC.allocator.cache[nodeName]; exists {
		eNode.isEgressAssignable = isAssignable
		// if the node is not assignable/ready/reachable anymore we need to
		// empty all of it's allocations from our cache since we'll clear all
		// assignments from this node later on, because of this.
		if !isAssignable {
			eNode.allocations = make(map[string]string)
		}
	}
}

func (oc *Controller) setNodeEgressReady(nodeName string, isReady bool) {
	oc.eIPC.allocator.Lock()
	defer oc.eIPC.allocator.Unlock()
	if eNode, exists := oc.eIPC.allocator.cache[nodeName]; exists {
		eNode.isReady = isReady
		// see setNodeEgressAssignable
		if !isReady {
			eNode.allocations = make(map[string]string)
		}
	}
}

func (oc *Controller) setNodeEgressReachable(nodeName string, isReachable bool) {
	oc.eIPC.allocator.Lock()
	defer oc.eIPC.allocator.Unlock()
	if eNode, exists := oc.eIPC.allocator.cache[nodeName]; exists {
		eNode.isReachable = isReachable
		// see setNodeEgressAssignable
		if !isReachable {
			eNode.allocations = make(map[string]string)
		}
	}
}

func (oc *Controller) addEgressNode(nodeName string) error {
	klog.V(5).Infof("Egress node: %s about to be initialized", nodeName)
	// This option will program OVN to start sending GARPs for all external IPS
	// that the logical switch port has been configured to use. This is
	// necessary for egress IP because if an egress IP is moved between two
	// nodes, the nodes need to actively update the ARP cache of all neighbors
	// as to notify them the change. If this is not the case: packets will
	// continue to be routed to the old node which hosted the egress IP before
	// it was moved, and the connections will fail.
	lsp := nbdb.LogicalSwitchPort{
		Name: types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + nodeName,
		// Setting nat-addresses to router will send out GARPs for all externalIPs and LB VIPs
		// hosted on the GR. Setting exclude-lb-vips-from-garp to true will make sure GARPs for
		// LB VIPs are not sent, thereby preventing GARP overload.
		Options: map[string]string{"nat-addresses": "router", "exclude-lb-vips-from-garp": "true"},
	}
	opModel := libovsdbops.OperationModel{
		Model: &lsp,
		OnModelMutations: []interface{}{
			&lsp.Options,
		},
		ErrNotFound: true,
	}
	if _, err := oc.modelClient.CreateOrUpdate(opModel); err != nil {
		klog.Errorf("Unable to configure GARP on external logical switch port for egress node: %s, "+
			"this will result in packet drops during egress IP re-assignment,  err: %v", nodeName, err)

	}
	// If a node has been labelled for egress IP we need to check if there are any
	// egress IPs which are missing an assignment. If there are, we need to send a
	// synthetic update since reconcileEgressIP will then try to assign those IPs to
	// this node (if possible)
	egressIPs, err := oc.kube.GetEgressIPs()
	if err != nil {
		return fmt.Errorf("unable to list EgressIPs, err: %v", err)
	}
	for _, egressIP := range egressIPs.Items {
		if len(egressIP.Spec.EgressIPs) != len(egressIP.Status.Items) {
			// Send a "synthetic update" on all egress IPs which are not fully
			// assigned, the reconciliation loop for WatchEgressIP will try to
			// assign stuff to this new node. The workqueue's delta FIFO
			// implementation will not trigger a watch event for updates on
			// objects which have no semantic difference, hence: call the
			// reconciliation function directly.
			if err := oc.reconcileEgressIP(nil, &egressIP); err != nil {
				klog.Errorf("Synthetic update for EgressIP: %s failed, err: %v", egressIP.Name, err)
			}
		}
	}
	return nil
}

func (oc *Controller) deleteEgressNode(nodeName string) error {
	klog.V(5).Infof("Egress node: %s about to be removed", nodeName)
	// This will remove the option described in addEgressNode from the logical
	// switch port, since this node will not be used for egress IP assignments
	// from now on.
	lsp := nbdb.LogicalSwitchPort{
		Name:    types.EXTSwitchToGWRouterPrefix + types.GWRouterPrefix + nodeName,
		Options: map[string]string{"nat-addresses": "", "exclude-lb-vips-from-garp": ""},
	}
	opModel := libovsdbops.OperationModel{
		Model: &lsp,
		OnModelMutations: []interface{}{
			&lsp.Options,
		},
		ErrNotFound: true,
	}
	if err := oc.modelClient.Delete(opModel); err != nil {
		klog.Errorf("Unable to remove GARP configuration on external logical switch port for egress node: %s, err: %v", nodeName, err)
	}
	// Since the node has been labelled as "not usable" for egress IP
	// assignments we need to find all egress IPs which have an assignment to
	// it, and move them elsewhere.
	egressIPs, err := oc.kube.GetEgressIPs()
	if err != nil {
		return fmt.Errorf("unable to list EgressIPs, err: %v", err)
	}
	for _, egressIP := range egressIPs.Items {
		for _, status := range egressIP.Status.Items {
			if status.Node == nodeName {
				// Send a "synthetic update" on all egress IPs which have an
				// assignment to this node. The reconciliation loop for
				// WatchEgressIP will see that the current assignment status to
				// this node is invalid and try to re-assign elsewhere. The
				// workqueue's delta FIFO implementation will not trigger a
				// watch event for updates on objects which have no semantic
				// difference, hence: call the reconciliation function directly.
				if err := oc.reconcileEgressIP(nil, &egressIP); err != nil {
					klog.Errorf("Re-assignment for EgressIP: %s failed, unable to update object, err: %v", egressIP.Name, err)
				}
				break
			}
		}
	}
	return nil
}

func (oc *Controller) initEgressIPAllocator(node *kapi.Node) (err error) {
	oc.eIPC.allocator.Lock()
	defer oc.eIPC.allocator.Unlock()
	if _, exists := oc.eIPC.allocator.cache[node.Name]; !exists {
		var parsedEgressIPConfig *util.ParsedNodeEgressIPConfiguration
		if util.PlatformTypeIsEgressIPCloudProvider() {
			parsedEgressIPConfig, err = util.ParseCloudEgressIPConfig(node)
			if err != nil {
				return fmt.Errorf("unable to use cloud node for egress assignment, err: %v", err)
			}
		} else {
			parsedEgressIPConfig, err = util.ParseNodePrimaryIfAddr(node)
			if err != nil {
				return fmt.Errorf("unable to use node for egress assignment, err: %v", err)
			}
		}
		nodeSubnets, err := util.ParseNodeHostSubnetAnnotation(node)
		if err != nil {
			return fmt.Errorf("failed to parse node %s subnets annotation %v", node.Name, err)
		}
		mgmtIPs := make([]net.IP, len(nodeSubnets))
		for i, subnet := range nodeSubnets {
			mgmtIPs[i] = util.GetNodeManagementIfAddr(subnet).IP
		}
		oc.eIPC.allocator.cache[node.Name] = &egressNode{
			name:           node.Name,
			egressIPConfig: parsedEgressIPConfig,
			mgmtIPs:        mgmtIPs,
			allocations:    make(map[string]string),
		}
	}
	return nil
}

// addNodeForEgress sets up default logical router policy for every node and
// initiates the allocator cache for the node in question, if the node has the
// necessary annotation.
func (oc *Controller) addNodeForEgress(node *v1.Node) error {
	v4Addr, v6Addr := getNodeInternalAddrs(node)
	v4ClusterSubnet, v6ClusterSubnet := getClusterSubnets()
	if err := oc.createDefaultNoRerouteNodePolicies(v4Addr, v6Addr, v4ClusterSubnet, v6ClusterSubnet); err != nil {
		return err
	}
	if err := oc.initEgressIPAllocator(node); err != nil {
		klog.V(5).Infof("Egress node initialization error: %v", err)
	}
	return nil
}

// deleteNodeForEgress remove the default allow logical router policies for the
// node and removes the node from the allocator cache.
func (oc *Controller) deleteNodeForEgress(node *v1.Node) error {
	v4Addr, v6Addr := getNodeInternalAddrs(node)
	v4ClusterSubnet, v6ClusterSubnet := getClusterSubnets()
	if err := oc.deleteDefaultNoRerouteNodePolicies(v4Addr, v6Addr, v4ClusterSubnet, v6ClusterSubnet); err != nil {
		return err
	}
	oc.eIPC.allocator.Lock()
	delete(oc.eIPC.allocator.cache, node.Name)
	oc.eIPC.allocator.Unlock()
	return nil
}

// initClusterEgressPolicies will initialize the default allow policies for
// east<->west traffic. Egress IP is based on routing egress traffic to specific
// egress nodes, we don't want to route any other traffic however and these
// policies will take care of that. Also, we need to initialize the go-routine
// which verifies if egress nodes are ready and reachable, typically if an
// egress node experiences problems we want to move all egress IP assignment
// away from that node elsewhere so that the pods using the egress IP can
// continue to do so without any issues.
func (oc *Controller) initClusterEgressPolicies(nodes []interface{}) {
	v4ClusterSubnet, v6ClusterSubnet := getClusterSubnets()
	oc.createDefaultNoReroutePodPolicies(v4ClusterSubnet, v6ClusterSubnet)
	oc.createDefaultNoRerouteServicePolicies(v4ClusterSubnet, v6ClusterSubnet)
	go oc.checkEgressNodesReachability()
}

// egressNode is a cache helper used for egress IP assignment, representing an egress node
type egressNode struct {
	egressIPConfig     *util.ParsedNodeEgressIPConfiguration
	mgmtIPs            []net.IP
	allocations        map[string]string
	isReady            bool
	isReachable        bool
	isEgressAssignable bool
	name               string
}

func (e *egressNode) getAllocationCountForEgressIP(name string) (count int) {
	for _, egressIPName := range e.allocations {
		if egressIPName == name {
			count++
		}
	}
	return
}

// podAssignmentState keeps track of which egressIP object is serving
// the related pod.
// NOTE: At a given time only one object will be configured. This is
// transparent to the user
type podAssignmentState struct {
	// the name of the egressIP object that is currently serving this pod
	egressIPName string
	// the list of egressIPs within the above egressIP object that are serving this pod
	egressStatuses map[egressipv1.EgressIPStatusItem]string
	// list of other egressIP object names that also match this pod but are on standby
	standbyEgressIPNames sets.String
}

// Clone deep-copies and returns the copied podAssignmentState
func (pas *podAssignmentState) Clone() *podAssignmentState {
	clone := &podAssignmentState{
		egressIPName: pas.egressIPName,
	}
	clone.standbyEgressIPNames = make(sets.String, len(pas.standbyEgressIPNames))
	for k := range pas.standbyEgressIPNames {
		clone.standbyEgressIPNames.Insert(k)
	}
	clone.egressStatuses = make(map[egressipv1.EgressIPStatusItem]string, len(pas.egressStatuses))
	for k, v := range pas.egressStatuses {
		clone.egressStatuses[k] = v
	}
	return clone
}

type allocator struct {
	*sync.Mutex
	// A cache used for egress IP assignments containing data for all cluster nodes
	// used for egress IP assignments
	cache map[string]*egressNode
}

type egressIPController struct {
	// egressIPAssignmentMutex is used to ensure a safe updates between
	// concurrent go-routines which could be modifying the egress IP status
	// assignment simultaneously. Currently WatchEgressNodes and WatchEgressIP
	// run two separate go-routines which do this.
	egressIPAssignmentMutex *sync.Mutex
	// podAssignmentMutex is used to ensure safe access to podAssignment.
	// Currently WatchEgressIP, WatchEgressNamespace and WatchEgressPod could
	// all access that map simultaneously, hence why this guard is needed.
	podAssignmentMutex *sync.Mutex
	// podAssignment is a cache used for keeping track of which egressIP status
	// has been setup for each pod. The key is defined by getPodKey
	podAssignment map[string]*podAssignmentState
	// allocator is a cache of egress IP centric data needed to when both route
	// health-checking and tracking allocations made
	allocator allocator
	// libovsdb northbound client interface
	nbClient libovsdbclient.Client
	// modelClient for performing idempotent NB operations
	modelClient libovsdbops.ModelClient
	// watchFactory watching k8s objects
	watchFactory *factory.WatchFactory
	// reachability check interval
	reachabilityCheckInterval time.Duration
}

// addStandByEgressIPAssignment does the same setup that is done by addPodEgressIPAssignments but for
// the standby egressIP. This must always be called with a lock on podAssignmentState mutex
// This is special case function called only from deleteEgressIPAssignments, don't use this for normal setup
// Any failure from here will not be retried, its a corner case undefined behaviour
func (oc *Controller) addStandByEgressIPAssignment(podKey string, podStatus *podAssignmentState) error {
	podNamespace, podName := getPodNamespaceAndNameFromKey(podKey)
	pod, err := oc.watchFactory.GetPod(podNamespace, podName)
	if err != nil {
		return err
	}
	eipsToAssign := podStatus.standbyEgressIPNames.UnsortedList()
	var eipToAssign string
	var eip *egressipv1.EgressIP
	for _, eipName := range eipsToAssign {
		eip, err = oc.watchFactory.GetEgressIP(eipName)
		if err != nil {
			klog.Warningf("There seems to be a stale standby egressIP %s for pod %s "+
				"which doesn't exist: %v; removing this standby egressIP from cache...", eipName, podKey, err)
			podStatus.standbyEgressIPNames.Delete(eipName)
			continue
		}
		eipToAssign = eipName // use the first EIP we find successfully
		break
	}
	if eipToAssign == "" {
		klog.Infof("No standby egressIP's found for pod %s", podKey)
		return nil
	}

	podState := &podAssignmentState{
		egressStatuses:       make(map[egressipv1.EgressIPStatusItem]string),
		standbyEgressIPNames: podStatus.standbyEgressIPNames,
	}
	oc.eIPC.podAssignment[podKey] = podState
	// NOTE: We let addPodEgressIPAssignments take care of setting egressIPName and egressStatuses and removing it from standBy
	err = oc.addPodEgressIPAssignments(eipToAssign, eip.Status.Items, pod)
	if err != nil {
		return err
	}
	return nil
}

// addPodEgressIPAssignment will program OVN with logical router policies
// (routing pod traffic to the egress node) and NAT objects on the egress node
// (SNAT-ing to the egress IP).
func (e *egressIPController) addPodEgressIPAssignment(egressIPName string, status egressipv1.EgressIPStatusItem, pod *kapi.Pod, podIPs []*net.IPNet) (err error) {
	if err := e.deleteExternalGWPodSNAT(pod, podIPs, status); err != nil {
		return err
	}
	if err := e.handleEgressReroutePolicy(podIPs, status, egressIPName, e.createEgressReroutePolicy); err != nil {
		return fmt.Errorf("unable to create logical router policy, err: %v", err)
	}
	ops, err := createNATRuleOps(e.nbClient, podIPs, status, egressIPName)
	if err != nil {
		return fmt.Errorf("unable to create NAT rule for status: %v, err: %v", status, err)
	}
	_, err = libovsdbops.TransactAndCheck(e.nbClient, ops)
	return err
}

// deletePodEgressIPAssignment deletes the OVN programmed egress IP
// configuration mentioned for addPodEgressIPAssignment.
func (e *egressIPController) deletePodEgressIPAssignment(egressIPName string, status egressipv1.EgressIPStatusItem, podIPs []*net.IPNet) error {
	if err := e.handleEgressReroutePolicy(podIPs, status, egressIPName, e.deleteEgressReroutePolicy); errors.Is(err, libovsdbclient.ErrNotFound) {
		// if the gateway router join IP setup is already gone, then don't count it as error.
		klog.Warningf("Unable to delete logical router policy, err: %v", err)
	} else if err != nil {
		return fmt.Errorf("unable to delete logical router policy, err: %v", err)
	}
	ops, err := deleteNATRuleOps(e.nbClient, []ovsdb.Operation{}, podIPs, status, egressIPName)
	if err != nil {
		return fmt.Errorf("unable to delete NAT rule for status: %v, err: %v", status, err)
	}
	_, err = libovsdbops.TransactAndCheck(e.nbClient, ops)
	return err
}

// addExternalGWPodSNAT performs the required external GW setup in two particular
// cases:
// - An egress IP matching pod stops matching by means of EgressIP object
// deletion
// - An egress IP matching pod stops matching by means of changed EgressIP
// selector change.
// In both cases we should re-add the external GW setup. We however need to
// guard against a third case, which is: pod deletion, for that it's enough to
// check the informer cache since on pod deletion the event handlers are
// triggered after the update to the informer cache. We should not re-add the
// external GW setup in those cases.
func (e *egressIPController) addExternalGWPodSNAT(podNamespace, podName string, status egressipv1.EgressIPStatusItem) error {
	if config.Gateway.DisableSNATMultipleGWs {
		if pod, err := e.watchFactory.GetPod(podNamespace, podName); err == nil && pod.Spec.NodeName == status.Node {
			// if the pod still exists, add snats to->nodeIP (on the node where the pod exists) for these podIPs after deleting the snat to->egressIP
			// NOTE: This needs to be done only if the pod was on the same node as egressNode
			extIPs, err := getExternalIPsGR(e.watchFactory, pod.Spec.NodeName)
			if err != nil {
				return err
			}
			podIPs, err := util.GetPodCIDRsWithFullMask(pod)
			if err != nil {
				return err
			}
			err = addOrUpdatePodSNAT(e.nbClient, pod.Spec.NodeName, extIPs, podIPs)
			if err != nil {
				return err
			}
			klog.V(5).Infof("Adding SNAT on %s since egress node managing %s/%s was the same: %s", pod.Spec.NodeName, pod.Namespace, pod.Name, status.Node)
		}
	}
	return nil
}

// deleteExternalGWPodSNAT performs the required external GW teardown for the given pod
func (e *egressIPController) deleteExternalGWPodSNAT(pod *kapi.Pod, podIPs []*net.IPNet, status egressipv1.EgressIPStatusItem) error {
	if config.Gateway.DisableSNATMultipleGWs && status.Node == pod.Spec.NodeName {
		// remove snats to->nodeIP (from the node where pod exists if that node is also serving
		// as an egress node for this pod) for these podIPs before adding the snat to->egressIP
		extIPs, err := getExternalIPsGR(e.watchFactory, pod.Spec.NodeName)
		if err != nil {
			return err
		}
		err = deletePodSNAT(e.nbClient, pod.Spec.NodeName, extIPs, podIPs)
		if err != nil {
			return err
		}
	} else if config.Gateway.DisableSNATMultipleGWs {
		// it means the node on which the pod is is different from the egressNode that is managing the pod
		klog.V(5).Infof("Not deleting SNAT on %s since egress node managing %s/%s is %s", pod.Spec.NodeName, pod.Namespace, pod.Name, status.Node)
	}
	return nil
}

func (e *egressIPController) getGatewayRouterJoinIP(node string, wantsIPv6 bool) (net.IP, error) {
	gatewayIPs, err := util.GetLRPAddrs(e.nbClient, types.GWRouterToJoinSwitchPrefix+types.GWRouterPrefix+node)
	if err != nil {
		return nil, fmt.Errorf("attempt at finding node gateway router network information failed, err: %w", err)
	}
	if gatewayIP, err := util.MatchIPNetFamily(wantsIPv6, gatewayIPs); err != nil {
		return nil, fmt.Errorf("could not find node %s gateway router: %v", node, err)
	} else {
		return gatewayIP.IP, nil
	}
}

// createEgressReroutePolicy uses logical router policies to force egress traffic to the egress node, for that we need
// to retrive the internal gateway router IP attached to the egress node. This method handles both the shared and
// local gateway mode case
func (e *egressIPController) handleEgressReroutePolicy(podIPNets []*net.IPNet, status egressipv1.EgressIPStatusItem, egressIPName string, cb func(filterOption, egressIPName string, gatewayRouterIP string) error) error {
	gatewayRouterIPv4, gatewayRouterIPv6 := "", ""
	isEgressIPv6 := utilnet.IsIPv6String(status.EgressIP)
	gatewayRouterIP, err := e.getGatewayRouterJoinIP(status.Node, isEgressIPv6)
	if err != nil {
		return fmt.Errorf("unable to retrieve gateway IP for node: %s, protocol is IPv6: %v, err: %w", status.Node, isEgressIPv6, err)
	}
	if isEgressIPv6 {
		gatewayRouterIPv6 = gatewayRouterIP.String()
	} else {
		gatewayRouterIPv4 = gatewayRouterIP.String()
	}
	for _, podIPNet := range podIPNets {
		podIP := podIPNet.IP
		if utilnet.IsIPv6(podIP) && gatewayRouterIPv6 != "" {
			filterOption := fmt.Sprintf("ip6.src == %s", podIP.String())
			if err := cb(filterOption, egressIPName, gatewayRouterIPv6); err != nil {
				return err
			}
		} else if !utilnet.IsIPv6(podIP) && gatewayRouterIPv4 != "" {
			filterOption := fmt.Sprintf("ip4.src == %s", podIP.String())
			if err := cb(filterOption, egressIPName, gatewayRouterIPv4); err != nil {
				return err
			}
		}
	}
	return nil
}

// createEgressReroutePolicy performs idempotent updates of the
// LogicalRouterPolicy corresponding to the egressIP object, according to the
// following update procedure:
// - if the LogicalRouterPolicy does not exist: it adds it by creating the
// reference to it from ovn_cluster_router and specifying the array of nexthops
// to equal [gatewayRouterIP]
// - if the LogicalRouterPolicy does exist: it add the gatewayRouterIP to the
// array of nexthops
func (e *egressIPController) createEgressReroutePolicy(filterOption, egressIPName string, gatewayRouterIP string) error {
	logicalRouter := nbdb.LogicalRouter{}
	logicalRouterPolicy := nbdb.LogicalRouterPolicy{
		Match:    filterOption,
		Priority: types.EgressIPReroutePriority,
		Nexthops: []string{gatewayRouterIP},
		Action:   nbdb.LogicalRouterPolicyActionReroute,
		ExternalIDs: map[string]string{
			"name": egressIPName,
		},
	}
	opsModel := []libovsdbops.OperationModel{
		{
			Model: &logicalRouterPolicy,
			ModelPredicate: func(lrp *nbdb.LogicalRouterPolicy) bool {
				return lrp.Match == filterOption && lrp.Priority == types.EgressIPReroutePriority && lrp.ExternalIDs["name"] == egressIPName
			},
			OnModelMutations: []interface{}{
				&logicalRouterPolicy.Nexthops,
			},
			DoAfter: func() {
				if logicalRouterPolicy.UUID != "" {
					logicalRouter.Policies = []string{logicalRouterPolicy.UUID}
				}
			},
		},
		{
			Model:          &logicalRouter,
			ModelPredicate: func(lr *nbdb.LogicalRouter) bool { return lr.Name == types.OVNClusterRouter },
			OnModelMutations: []interface{}{
				&logicalRouter.Policies,
			},
			ErrNotFound: true,
		},
	}
	if _, err := e.modelClient.CreateOrUpdate(opsModel...); err != nil {
		return fmt.Errorf("unable to create logical router policy, err: %v", err)
	}
	return nil
}

// deleteEgressReroutePolicy performs idempotent updates of the
// LogicalRouterPolicy corresponding to the egressIP object, according to the
// following update procedure:
// - if the LogicalRouterPolicy exist and has the len(nexthops) > 1: it removes
// the specified gatewayRouterIP from nexthops
// - if the LogicalRouterPolicy exist and has the len(nexthops) == 1: it removes
// the LogicalRouterPolicy completely
func (e *egressIPController) deleteEgressReroutePolicy(filterOption, egressIPName string, gatewayRouterIP string) error {
	logicalRouter := nbdb.LogicalRouter{}
	logicalRouterPolicy := nbdb.LogicalRouterPolicy{
		Nexthops: []string{gatewayRouterIP},
	}
	logicalRouterPolicyRes := []nbdb.LogicalRouterPolicy{}
	opsModel := []libovsdbops.OperationModel{
		{
			Model: &logicalRouterPolicy,
			ModelPredicate: func(lrp *nbdb.LogicalRouterPolicy) bool {
				return lrp.Match == filterOption && lrp.Priority == types.EgressIPReroutePriority && lrp.ExternalIDs["name"] == egressIPName
			},
			OnModelMutations: []interface{}{
				&logicalRouterPolicy.Nexthops,
			},
			ExistingResult: &logicalRouterPolicyRes,
			DoAfter: func() {
				logicalRouter.Policies = libovsdbops.ExtractUUIDsFromModels(&logicalRouterPolicyRes)
			},
		},
		{
			Model: &logicalRouter,
			ModelPredicate: func(lr *nbdb.LogicalRouter) bool {
				if len(logicalRouterPolicyRes) == 1 && len(logicalRouterPolicyRes[0].Nexthops) == 1 && logicalRouterPolicyRes[0].Nexthops[0] == gatewayRouterIP {
					return lr.Name == types.OVNClusterRouter
				}
				return false
			},
			OnModelMutations: []interface{}{
				&logicalRouter.Policies,
			},
		},
	}
	if err := e.modelClient.Delete(opsModel...); err != nil {
		return fmt.Errorf("unable to remove logical router policy, err: %v", err)
	}
	return nil
}

// deleteEgressIPStatusSetup deletes the entire set up in the NB DB for an
// EgressIPStatusItem. The set up in the NB DB gets tagged with the name of the
// EgressIP, hence lookup the LRP and NAT objects which match that as well as
// the attributes of the EgressIPStatusItem. Keep in mind: the LRP should get
// completely deleted once the remaining and last nexthop equals the
// gatewayRouterIP corresponding to the node in the EgressIPStatusItem, else
// just remove the gatewayRouterIP from the list of nexthops
func (e *egressIPController) deleteEgressIPStatusSetup(name string, status egressipv1.EgressIPStatusItem) error {
	isEgressIPv6 := utilnet.IsIPv6String(status.EgressIP)
	gatewayRouterIP, err := e.getGatewayRouterJoinIP(status.Node, isEgressIPv6)
	if errors.Is(err, libovsdbclient.ErrNotFound) {
		// if the gateway router join IP setup is already gone, then don't count it as error. Unfortunately we won't remove
		// any SNATs in this case however if joinIP setup is gone, its safe to assume the GR and all SNATs on it are also gone.
		klog.Warningf("Unable to retrieve gateway IP for node: %s, protocol is IPv6: %v, err: %v", status.Node, isEgressIPv6, err)
	} else if err != nil {
		return fmt.Errorf("unable to retrieve gateway IP for node: %s, protocol is IPv6: %v, err: %v", status.Node, isEgressIPv6, err)
	}

	ops := []ovsdb.Operation{}

	if gatewayRouterIP != nil {
		gwIP := gatewayRouterIP.String()
		policyPred := func(item *nbdb.LogicalRouterPolicy) bool {
			hasGatewayRouterIPNexthop := false
			for _, nexthop := range item.Nexthops {
				if nexthop == gwIP {
					hasGatewayRouterIPNexthop = true
					break
				}
			}
			return item.Priority == types.EgressIPReroutePriority && item.ExternalIDs["name"] == name && hasGatewayRouterIPNexthop
		}
		ops, err = libovsdbops.DeleteNextHopFromLogicalRouterPoliciesWithPredicateOps(e.nbClient, nil, types.OVNClusterRouter, policyPred, gwIP)
		if err != nil {
			return fmt.Errorf("error removing nexthop IP %s from egress ip %s policies on router %s: %v",
				gatewayRouterIP, name, types.OVNClusterRouter, err)
		}
	}
	nat := nbdb.NAT{}
	natResult := []nbdb.NAT{}
	natLogicalRouter := nbdb.LogicalRouter{}

	opsModel := []libovsdbops.OperationModel{
		{
			Model: &nat,
			ModelPredicate: func(nat *nbdb.NAT) bool {
				return nat.ExternalIDs["name"] == name && nat.ExternalIP == status.EgressIP
			},
			ExistingResult: &natResult,
			DoAfter: func() {
				natLogicalRouter.Nat = libovsdbops.ExtractUUIDsFromModels(&natResult)
			},
			BulkOp: true,
		},
		{
			Model: &natLogicalRouter,
			ModelPredicate: func(lr *nbdb.LogicalRouter) bool {
				// Find the router that has the removed nat
				for _, lrNat := range lr.Nat {
					for _, delNat := range natLogicalRouter.Nat {
						if lrNat == delNat {
							return true
						}
					}
				}
				return false
			},
			OnModelMutations: []interface{}{
				&natLogicalRouter.Nat,
			},
		},
	}
	ops, err = e.modelClient.DeleteOps(ops, opsModel...)
	if err != nil {
		return fmt.Errorf("unable to remove logical router policies of egress IP status setup, err: %v", err)
	}
	_, err = libovsdbops.TransactAndCheck(e.nbClient, ops)
	if err != nil {
		return fmt.Errorf("unable to transact removal of egress IP status setup, err: %v", err)
	}
	return nil
}

// checkEgressNodesReachability continuously checks if all nodes used for egress
// IP assignment are reachable, and updates the nodes following the result. This
// is important because egress IP is based upon routing traffic to these nodes,
// and if they aren't reachable we shouldn't be using them for egress IP.
func (oc *Controller) checkEgressNodesReachability() {
	timer := time.NewTicker(oc.eIPC.reachabilityCheckInterval)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			checkEgressNodesReachabilityIterate(oc)
		case <-oc.stopChan:
			klog.V(5).Infof("Stop channel got triggered: will stop checkEgressNodesReachability")
			return
		}
	}
}

func checkEgressNodesReachabilityIterate(oc *Controller) {
	reAddOrDelete := map[string]bool{}
	oc.eIPC.allocator.Lock()
	for _, eNode := range oc.eIPC.allocator.cache {
		if eNode.isEgressAssignable && eNode.isReady {
			wasReachable := eNode.isReachable
			isReachable := oc.isReachable(eNode)
			if wasReachable && !isReachable {
				reAddOrDelete[eNode.name] = true
			} else if !wasReachable && isReachable {
				reAddOrDelete[eNode.name] = false
			}
			eNode.isReachable = isReachable
		}
	}
	oc.eIPC.allocator.Unlock()
	for nodeName, shouldDelete := range reAddOrDelete {
		if shouldDelete {
			klog.Warningf("Node: %s is detected as unreachable, deleting it from egress assignment", nodeName)
			if err := oc.deleteEgressNode(nodeName); err != nil {
				klog.Errorf("Node: %s is detected as unreachable, but could not re-assign egress IPs, err: %v", nodeName, err)
			}
		} else {
			klog.Infof("Node: %s is detected as reachable and ready again, adding it to egress assignment", nodeName)
			if err := oc.addEgressNode(nodeName); err != nil {
				klog.Errorf("Node: %s is detected as reachable and ready again, but could not re-assign egress IPs, err: %v", nodeName, err)
			}
		}
	}
}

func (oc *Controller) isReachable(node *egressNode) bool {
	for _, ip := range node.mgmtIPs {
		if dialer.dial(ip) {
			return true
		}
	}
	return false
}

type egressIPDial struct{}

// Blantant copy from: https://github.com/openshift/sdn/blob/master/pkg/network/common/egressip.go#L499-L505
// Ping a node and return whether or not we think it is online. We do this by trying to
// open a TCP connection to the "discard" service (port 9); if the node is offline, the
// attempt will either time out with no response, or else return "no route to host" (and
// we will return false). If the node is online then we presumably will get a "connection
// refused" error; but the code below assumes that anything other than timeout or "no
// route" indicates that the node is online.
func (e *egressIPDial) dial(ip net.IP) bool {
	timeout := time.Second
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), "9"), timeout)
	if conn != nil {
		conn.Close()
	}
	if opErr, ok := err.(*net.OpError); ok {
		if opErr.Timeout() {
			return false
		}
		if sysErr, ok := opErr.Err.(*os.SyscallError); ok && sysErr.Err == syscall.EHOSTUNREACH {
			return false
		}
	}
	return true
}

func getClusterSubnets() ([]*net.IPNet, []*net.IPNet) {
	var v4ClusterSubnets = []*net.IPNet{}
	var v6ClusterSubnets = []*net.IPNet{}
	for _, clusterSubnet := range config.Default.ClusterSubnets {
		if !utilnet.IsIPv6CIDR(clusterSubnet.CIDR) {
			v4ClusterSubnets = append(v4ClusterSubnets, clusterSubnet.CIDR)
		} else {
			v6ClusterSubnets = append(v6ClusterSubnets, clusterSubnet.CIDR)
		}
	}
	return v4ClusterSubnets, v6ClusterSubnets
}

// getNodeInternalAddrs returns the first IPv4 and/or IPv6 InternalIP defined
// for the node. On certain cloud providers (AWS) the egress IP will be added to
// the list of node IPs as an InternalIP address, we don't want to create the
// default allow logical router policies for that IP. Node IPs are ordered,
// meaning the egress IP will never be first in this list.
func getNodeInternalAddrs(node *v1.Node) (net.IP, net.IP) {
	var v4Addr, v6Addr net.IP
	for _, nodeAddr := range node.Status.Addresses {
		if nodeAddr.Type == v1.NodeInternalIP {
			ip := net.ParseIP(nodeAddr.Address)
			if !utilnet.IsIPv6(ip) && v4Addr == nil {
				v4Addr = ip
			} else if utilnet.IsIPv6(ip) && v6Addr == nil {
				v6Addr = ip
			}
		}
	}
	return v4Addr, v6Addr
}

// createDefaultNoRerouteServicePolicies ensures service reachability from the
// host network to any service backed by egress IP matching pods
func (oc *Controller) createDefaultNoRerouteServicePolicies(v4ClusterSubnet, v6ClusterSubnet []*net.IPNet) {
	for _, v4Subnet := range v4ClusterSubnet {
		match := fmt.Sprintf("ip4.src == %s && ip4.dst == %s", v4Subnet.String(), config.Gateway.V4JoinSubnet)
		if err := oc.createLogicalRouterPolicy(match, types.DefaultNoRereoutePriority); err != nil {
			klog.Errorf("Unable to create IPv4 no-reroute service policies, err: %v", err)
		}
	}
	for _, v6Subnet := range v6ClusterSubnet {
		match := fmt.Sprintf("ip6.src == %s && ip6.dst == %s", v6Subnet.String(), config.Gateway.V6JoinSubnet)
		if err := oc.createLogicalRouterPolicy(match, types.DefaultNoRereoutePriority); err != nil {
			klog.Errorf("Unable to create IPv6 no-reroute service policies, err: %v", err)
		}
	}
}

// createDefaultNoReroutePodPolicies ensures egress pods east<->west traffic with regular pods,
// i.e: ensuring that an egress pod can still communicate with a regular pod / service backed by regular pods
func (oc *Controller) createDefaultNoReroutePodPolicies(v4ClusterSubnet, v6ClusterSubnet []*net.IPNet) {
	for _, v4Subnet := range v4ClusterSubnet {
		match := fmt.Sprintf("ip4.src == %s && ip4.dst == %s", v4Subnet.String(), v4Subnet.String())
		if err := oc.createLogicalRouterPolicy(match, types.DefaultNoRereoutePriority); err != nil {
			klog.Errorf("Unable to create IPv4 no-reroute pod policies, err: %v", err)
		}
	}
	for _, v6Subnet := range v6ClusterSubnet {
		match := fmt.Sprintf("ip6.src == %s && ip6.dst == %s", v6Subnet.String(), v6Subnet.String())
		if err := oc.createLogicalRouterPolicy(match, types.DefaultNoRereoutePriority); err != nil {
			klog.Errorf("Unable to create IPv6 no-reroute pod policies, err: %v", err)
		}
	}
}

// createDefaultNoRerouteNodePolicies ensures egress pods east<->west traffic with hostNetwork pods,
// i.e: ensuring that an egress pod can still communicate with a hostNetwork pod / service backed by hostNetwork pods
func (oc *Controller) createDefaultNoRerouteNodePolicies(v4NodeAddr, v6NodeAddr net.IP, v4ClusterSubnet, v6ClusterSubnet []*net.IPNet) error {
	if v4NodeAddr != nil {
		for _, v4Subnet := range v4ClusterSubnet {
			match := fmt.Sprintf("ip4.src == %s && ip4.dst == %s/32", v4Subnet.String(), v4NodeAddr.String())
			if err := oc.createLogicalRouterPolicy(match, types.DefaultNoRereoutePriority); err != nil {
				klog.Errorf("Unable to create IPv4 no-reroute node policies, err: %v", err)
			}
		}
	}
	if v6NodeAddr != nil {
		for _, v6Subnet := range v6ClusterSubnet {
			match := fmt.Sprintf("ip6.src == %s && ip6.dst == %s/128", v6Subnet.String(), v6NodeAddr.String())
			if err := oc.createLogicalRouterPolicy(match, types.DefaultNoRereoutePriority); err != nil {
				klog.Errorf("Unable to create IPv6 no-reroute node policies, err: %v", err)
			}
		}
	}
	return nil
}

func (oc *Controller) createLogicalRouterPolicy(match string, priority int) error {
	logicalRouter := nbdb.LogicalRouter{}
	logicalRouterPolicy := nbdb.LogicalRouterPolicy{
		Priority: priority,
		Action:   nbdb.LogicalRouterPolicyActionAllow,
		Match:    match,
	}
	opModels := []libovsdbops.OperationModel{
		{
			Model: &logicalRouterPolicy,
			ModelPredicate: func(lrp *nbdb.LogicalRouterPolicy) bool {
				return lrp.Match == match && lrp.Priority == priority
			},
			DoAfter: func() {
				if logicalRouterPolicy.UUID != "" {
					logicalRouter.Policies = []string{logicalRouterPolicy.UUID}
				}
			},
		},
		{
			Model:          &logicalRouter,
			ModelPredicate: func(lr *nbdb.LogicalRouter) bool { return lr.Name == types.OVNClusterRouter },
			OnModelMutations: []interface{}{
				&logicalRouter.Policies,
			},
			ErrNotFound: true,
		},
	}
	if _, err := oc.modelClient.CreateOrUpdate(opModels...); err != nil {
		return fmt.Errorf("unable to create logical router policy, err: %v", err)
	}
	return nil
}

func (oc *Controller) deleteLogicalRouterPolicy(match string, priority int) error {
	logicalRouter := nbdb.LogicalRouter{}
	logicalRouterPolicyRes := []nbdb.LogicalRouterPolicy{}
	opModels := []libovsdbops.OperationModel{
		{
			ModelPredicate: func(lrp *nbdb.LogicalRouterPolicy) bool {
				return lrp.Match == match && lrp.Priority == priority
			},
			ExistingResult: &logicalRouterPolicyRes,
			DoAfter: func() {
				logicalRouter.Policies = libovsdbops.ExtractUUIDsFromModels(&logicalRouterPolicyRes)
			},
			BulkOp: true,
		},
		{
			Model:          &logicalRouter,
			ModelPredicate: func(lr *nbdb.LogicalRouter) bool { return lr.Name == types.OVNClusterRouter },
			OnModelMutations: []interface{}{
				&logicalRouter.Policies,
			},
		},
	}

	if err := oc.modelClient.Delete(opModels...); err != nil {
		return fmt.Errorf("unable to delete logical router policy, err: %v", err)
	}
	return nil
}

func (oc *Controller) deleteDefaultNoRerouteNodePolicies(v4NodeAddr, v6NodeAddr net.IP, v4ClusterSubnet, v6ClusterSubnet []*net.IPNet) error {
	if v4NodeAddr != nil {
		for _, v4Subnet := range v4ClusterSubnet {
			match := fmt.Sprintf("ip4.src == %s && ip4.dst == %s/32", v4Subnet.String(), v4NodeAddr.String())
			if err := oc.deleteLogicalRouterPolicy(match, types.DefaultNoRereoutePriority); err != nil {
				return fmt.Errorf("unable to delete IPv4 no-reroute node policies, err: %v", err)
			}
		}
	}
	if v6NodeAddr != nil {
		for _, v6Subnet := range v6ClusterSubnet {
			match := fmt.Sprintf("ip6.src == %s && ip6.dst == %s/128", v6Subnet.String(), v6NodeAddr.String())
			if err := oc.deleteLogicalRouterPolicy(match, types.DefaultNoRereoutePriority); err != nil {
				return fmt.Errorf("unable to delete IPv6 no-reroute node policies, err: %v", err)
			}
		}
	}
	return nil
}

func buildSNATFromEgressIPStatus(podIP net.IP, status egressipv1.EgressIPStatusItem, egressIPName string) (*nbdb.NAT, error) {
	podIPStr := podIP.String()
	mask := util.GetIPFullMask(podIPStr)
	_, logicalIP, err := net.ParseCIDR(podIPStr + mask)
	if err != nil {
		return nil, fmt.Errorf("failed to parse podIP: %s, error: %v", podIP.String(), err)
	}
	externalIP := net.ParseIP(status.EgressIP)
	logicalPort := types.K8sPrefix + status.Node
	externalIds := map[string]string{"name": egressIPName}
	nat := libovsdbops.BuildRouterSNAT(&externalIP, logicalIP, logicalPort, externalIds)
	return nat, nil
}

func createNATRuleOps(nbClient libovsdbclient.Client, podIPs []*net.IPNet, status egressipv1.EgressIPStatusItem, egressIPName string) ([]ovsdb.Operation, error) {
	nats := make([]*nbdb.NAT, 0, len(podIPs))
	var nat *nbdb.NAT
	var err error
	for _, podIP := range podIPs {
		if (utilnet.IsIPv6String(status.EgressIP) && utilnet.IsIPv6(podIP.IP)) || (!utilnet.IsIPv6String(status.EgressIP) && !utilnet.IsIPv6(podIP.IP)) {
			nat, err = buildSNATFromEgressIPStatus(podIP.IP, status, egressIPName)
			if err != nil {
				return nil, err
			}
			nats = append(nats, nat)
		}
	}
	router := &nbdb.LogicalRouter{
		Name: util.GetGatewayRouterFromNode(status.Node),
	}
	ops, err := libovsdbops.AddOrUpdateNATsToRouterOps(nbClient, []ovsdb.Operation{}, router, nats...)
	if err != nil {
		return nil, fmt.Errorf("unable to create snat rules, for router: %s, error: %v", router.Name, err)
	}
	return ops, nil
}

func deleteNATRuleOps(nbClient libovsdbclient.Client, ops []ovsdb.Operation, podIPs []*net.IPNet, status egressipv1.EgressIPStatusItem, egressIPName string) ([]ovsdb.Operation, error) {
	nats := make([]*nbdb.NAT, 0, len(podIPs))
	var nat *nbdb.NAT
	var err error
	for _, podIP := range podIPs {
		if (utilnet.IsIPv6String(status.EgressIP) && utilnet.IsIPv6(podIP.IP)) || (!utilnet.IsIPv6String(status.EgressIP) && !utilnet.IsIPv6(podIP.IP)) {
			nat, err = buildSNATFromEgressIPStatus(podIP.IP, status, egressIPName)
			if err != nil {
				return nil, err
			}
			nats = append(nats, nat)
		}
	}
	router := &nbdb.LogicalRouter{
		Name: util.GetGatewayRouterFromNode(status.Node),
	}
	ops, err = libovsdbops.DeleteNATsFromRouterOps(nbClient, ops, router, nats...)
	if err != nil {
		return nil, fmt.Errorf("unable to remove snat rules for router: %s, error: %v", router.Name, err)
	}
	return ops, nil
}

func getPodKey(pod *kapi.Pod) string {
	return fmt.Sprintf("%s_%s", pod.Namespace, pod.Name)
}

func getPodNamespaceAndNameFromKey(podKey string) (string, string) {
	parts := strings.Split(podKey, "_")
	return parts[0], parts[1]
}

func getEgressIPAllocationTotalCount(allocator allocator) float64 {
	count := 0
	allocator.Lock()
	defer allocator.Unlock()
	for _, eNode := range allocator.cache {
		count += len(eNode.allocations)
	}
	return float64(count)
}

// cloudPrivateIPConfigNameToIPString converts the resource name to the string
// representation of net.IP. Given a limitation in the Kubernetes API server
// (see: https://github.com/kubernetes/kubernetes/pull/100950)
// CloudPrivateIPConfig.metadata.name cannot represent an IPv6 address. To
// work-around this limitation it was decided that the network plugin creating
// the CR will fully expand the IPv6 address and replace all colons with dots,
// ex:

// The CloudPrivateIPConfig name fc00.f853.0ccd.e793.0000.0000.0000.0054 will be
// represented as address: fc00:f853:ccd:e793::54

// We thus need to replace every fifth character's dot with a colon.
func cloudPrivateIPConfigNameToIPString(name string) string {
	// Handle IPv4, which will work fine.
	if ip := net.ParseIP(name); ip != nil {
		return name
	}
	// Handle IPv6, for which we want to convert the fully expanded "special
	// name" to go's default IP representation
	name = strings.ReplaceAll(name, ".", ":")
	return net.ParseIP(name).String()
}

// ipStringToCloudPrivateIPConfigName converts the net.IP string representation
// to a CloudPrivateIPConfig compatible name.

// The string representation of the IPv6 address fc00:f853:ccd:e793::54 will be
// represented as: fc00.f853.0ccd.e793.0000.0000.0000.0054

// We thus need to fully expand the IP string and replace every fifth
// character's colon with a dot.
func ipStringToCloudPrivateIPConfigName(ipString string) (name string) {
	ip := net.ParseIP(ipString)
	if ip.To4() != nil {
		return ipString
	}
	dst := make([]byte, hex.EncodedLen(len(ip)))
	hex.Encode(dst, ip)
	for i := 0; i < len(dst); i += 4 {
		if len(dst)-i == 4 {
			name += string(dst[i : i+4])
		} else {
			name += string(dst[i:i+4]) + "."
		}
	}
	return
}
