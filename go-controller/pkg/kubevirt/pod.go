package kubevirt

import (
	"fmt"
	"net"
	"sort"
	"strings"

	kubevirtv1 "kubevirt.io/api/core/v1"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	listersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/util/retry"

	libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	libovsdbops "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	logicalswitchmanager "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/logical_switch_manager"
	ovntypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

var (
	virtLauncherPodLabel = map[string]string{
		kubevirtv1.AppLabel: "virt-launcher",
	}
)

// IsPodLiveMigratable will return true if the pod belongs
// to kubevirt and should use the live migration features
func IsPodLiveMigratable(pod *corev1.Pod) bool {
	_, ok := pod.Annotations[kubevirtv1.AllowPodBridgeNetworkLiveMigrationAnnotation]
	return ok
}

// findVMRelatedPods will return pods belong to the same vm annotated at pod and
// filter out the one at the function argument
func findVMRelatedPods(client *factory.WatchFactory, pod *corev1.Pod) ([]*corev1.Pod, error) {
	vmDescription, err := NewVMDescriptionFromPod(pod)
	if err != nil {
		return nil, err
	}
	vmPods, err := vmDescription.OwnedPods(client.PodCoreInformer().Lister())
	if err != nil {
		return nil, err
	}
	filteredOutVMPods := []*corev1.Pod{}
	for _, vmPod := range vmPods {
		// The purpose of this function is to return the "other" pods related
		// to a VM.
		if vmPod.UID == pod.UID {
			continue
		}
		filteredOutVMPods = append(filteredOutVMPods, vmPod)
	}

	return filteredOutVMPods, nil
}

// findPodAnnotation will return the the OVN pod
// annotation from any other pod annotated with the same VM as pod
func findPodAnnotation(client *factory.WatchFactory, pod *corev1.Pod, nadName string) (*util.PodAnnotation, error) {
	vmPods, err := findVMRelatedPods(client, pod)
	if err != nil {
		return nil, fmt.Errorf("failed finding related pods for pod %s/%s when looking for network info: %v", pod.Namespace, pod.Name, err)
	}
	// virtual machine is not being live migrated so there is no other
	// vm pods
	if len(vmPods) == 0 {
		return nil, nil
	}

	for _, vmPod := range vmPods {
		podAnnotation, err := util.UnmarshalPodAnnotation(vmPod.Annotations, nadName)
		if err == nil {
			return podAnnotation, nil
		}
	}
	return nil, fmt.Errorf("missing virtual machine pod annotation at stale pods for %s/%s", pod.Namespace, pod.Name)
}

// EnsurePodAnnotationForVM will at live migration extract the ovn pod
// annotations from the source vm pod and copy it
// to the target vm pod so ip address follow vm during migration. This has to
// done before creating the LSP to be sure that Address field get configured
// correctly at the target VM pod LSP.
func EnsurePodAnnotationForVM(watchFactory *factory.WatchFactory, kube *kube.KubeOVN, pod *corev1.Pod, nadName string) (*util.PodAnnotation, error) {
	if !IsPodLiveMigratable(pod) {
		return nil, nil
	}

	if podAnnotation, err := util.UnmarshalPodAnnotation(pod.Annotations, nadName); err == nil {
		return podAnnotation, nil
	}

	podAnnotation, err := findPodAnnotation(watchFactory, pod, nadName)
	if err != nil {
		return nil, err
	}
	if podAnnotation == nil {
		return nil, nil
	}

	var modifiedPod *corev1.Pod
	resultErr := retry.RetryOnConflict(util.OvnConflictBackoff, func() error {
		// Informer cache should not be mutated, so get a copy of the object
		pod, err := watchFactory.GetPod(pod.Namespace, pod.Name)
		if err != nil {
			return err
		}
		// Informer cache should not be mutated, so get a copy of the object
		modifiedPod = pod.DeepCopy()
		if podAnnotation != nil {
			modifiedPod.Annotations, err = util.MarshalPodAnnotation(modifiedPod.Annotations, podAnnotation, nadName)
			if err != nil {
				return err
			}
		}
		return kube.UpdatePodStatus(modifiedPod)
	})
	if resultErr != nil {
		return nil, fmt.Errorf("failed to update labels and annotations on pod %s/%s: %v", pod.Namespace, pod.Name, resultErr)
	}
	return podAnnotation, nil
}

// AllVMPodsAreCompleted return true if all the vm pods are completed
func AllVMPodsAreCompleted(podLister listersv1.PodLister, pod *corev1.Pod) (bool, error) {
	if !util.PodCompleted(pod) {
		return false, nil
	}

	vmDescription, err := NewVMDescriptionFromPod(pod)
	if err != nil {
		return false, err
	}

	vmPods, err := vmDescription.OwnedPods(podLister)
	if err != nil {
		return false, fmt.Errorf("failed finding related pods for pod %s/%s when checking if they are completed: %v", pod.Namespace, pod.Name, err)
	}

	for _, vmPod := range vmPods {
		if !util.PodCompleted(vmPod) {
			return false, nil
		}
	}
	return true, nil
}

// IsMigratedSourcePodStale return false if the pod is live migratable,
// not completed and is the running VM pod with newest creation timestamp
func IsMigratedSourcePodStale(client *factory.WatchFactory, pod *corev1.Pod) (bool, error) {
	if !IsPodLiveMigratable(pod) {
		return false, nil
	}

	if util.PodCompleted(pod) {
		return true, nil
	}

	vmPods, err := findVMRelatedPods(client, pod)
	if err != nil {
		return false, fmt.Errorf("failed finding related pods for pod %s/%s when checking live migration left overs: %v", pod.Namespace, pod.Name, err)
	}

	for _, vmPod := range vmPods {
		if vmPod.CreationTimestamp.After(pod.CreationTimestamp.Time) {
			return true, nil
		}
	}

	return false, nil
}

// ZoneContainsPodSubnet will return true if the logical switch tonains
// the pod subnet and also the switch name owning it, this means that
// this zone owns the that subnet.
func ZoneContainsPodSubnet(lsManager *logicalswitchmanager.LogicalSwitchManager, ips []*net.IPNet) (string, bool) {
	return lsManager.GetSubnetName(ips)
}

// nodeContainsPodSubnet will return true if the node subnet annotation
// contains the subnets from the argument
func nodeContainsPodSubnet(watchFactory *factory.WatchFactory, nodeName string, podAnnotation *util.PodAnnotation, nadName string) (bool, error) {
	node, err := watchFactory.GetNode(nodeName)
	if err != nil {
		return false, err
	}
	nodeHostSubNets, err := util.ParseNodeHostSubnetAnnotation(node, nadName)
	if err != nil {
		return false, err
	}
	for _, subnet := range podAnnotation.IPs {
		for _, nodeHostSubNet := range nodeHostSubNets {
			if nodeHostSubNet.Contains(subnet.IP) {
				return true, nil
			}
		}
	}
	return false, nil
}

// VMDescription holds the identity and ownership information for a KubeVirt
// virtual machine derived from one of its virt-launcher pods. The key field
// stores the namespaced name of the VM, and ownedPodsFn is a closure that
// lists all pods belonging to the same VM via label or annotation selectors.
type VMDescription struct {
	key         ktypes.NamespacedName
	ownedPodsFn func(podLister listersv1.PodLister) ([]*corev1.Pod, error)
}

func (vm VMDescription) Key() ktypes.NamespacedName {
	return vm.key
}

func (vm VMDescription) OwnedPods(podLister listersv1.PodLister) ([]*corev1.Pod, error) {
	return vm.ownedPodsFn(podLister)
}

func vmNameFromPod(pod *corev1.Pod) (string, error) {
	vmName, ok := pod.Annotations[kubevirtv1.DomainAnnotation]
	if !ok {
		return "", fmt.Errorf("virtual machine pod %s/%s is missing the mandatory kubevirt annotation %s", pod.Namespace, pod.Name, kubevirtv1.DomainAnnotation)
	}
	return vmName, nil
}

// nameToLabel truncates name to fit within the Kubernetes label value
// maximum length of 63 characters (validation.LabelValueMaxLength). If
// name already fits, it is returned unchanged.
func nameToLabel(name string) string {
	if len(name) <= validation.LabelValueMaxLength {
		return name
	}
	return name[:validation.LabelValueMaxLength]
}

// NewVMDescriptionFromPod builds a VMDescription from a virt-launcher pod.
// Returns (nil, nil) if the pod is not owned by a virtual machine.
// The VM name is extracted from the kubevirt domain annotation on the pod,
// and the returned VMDescription.ownedPodsFn lists all sibling virt-launcher
// pods belonging to the same VM. When the VM name label matches the
// (possibly truncated) VM name, the lookup uses that label for efficiency;
// otherwise it falls back to the generic virt-launcher label and filters
// by the domain annotation to avoid false matches across VMs with long or
// colliding names.
func NewVMDescriptionFromPod(pod *corev1.Pod) (*VMDescription, error) {
	if !IsPodOwnedByVirtualMachine(pod) {
		return nil, nil
	}

	vmName, err := vmNameFromPod(pod)
	if err != nil {
		return nil, fmt.Errorf("failed to get VM name from pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	vmDescription := VMDescription{
		key: ktypes.NamespacedName{Namespace: pod.Namespace, Name: vmName},
	}

	// By default filter pods first by "virt-launcher" pods
	labelSelector := virtLauncherPodLabel

	// if the label is the same (truncating it if is > 63 chars) search directly by label so we iterate less
	vmNameLabel, ok := pod.Labels[kubevirtv1.VirtualMachineNameLabel]
	if ok && nameToLabel(vmName) == vmNameLabel {
		labelSelector = map[string]string{kubevirtv1.VirtualMachineNameLabel: vmNameLabel}
	}

	vmDescription.ownedPodsFn = func(podLister listersv1.PodLister) ([]*corev1.Pod, error) {
		labelMatchedPods, err := podLister.Pods(vmDescription.key.Namespace).List(labels.SelectorFromSet(labelSelector))
		if err != nil {
			return nil, err
		}
		// Filter by DomainAnnotation to ensure we only include pods that actually belong to this VM
		// (different VMs can have the same label if one VM's name matches another VM's hostname, or if vms names are very long but matches the truncated version of it)
		ownedPods := []*corev1.Pod{}
		for _, virtLauncherPod := range labelMatchedPods {
			podVMName, err := vmNameFromPod(virtLauncherPod)
			if err != nil {
				return nil, err
			}
			if podVMName == vmDescription.key.Name {
				ownedPods = append(ownedPods, virtLauncherPod)
			}
		}
		return ownedPods, nil
	}

	return &vmDescription, nil
}

// CleanUpLiveMigratablePod remove routing and DHCP ovn related resources
// when all the pods for the same VM as `pod` argument are completed.
func CleanUpLiveMigratablePod(nbClient libovsdbclient.Client, watchFactory *factory.WatchFactory, pod *corev1.Pod) error {
	if !IsPodLiveMigratable(pod) {
		return nil
	}

	allVMPodsCompleted, err := AllVMPodsAreCompleted(watchFactory.PodCoreInformer().Lister(), pod)
	if err != nil {
		return fmt.Errorf("failed cleaning up VM when checking if pod is leftover: %v", err)
	}

	// Do cleanup only if all the pods related to the VM are completed
	if !allVMPodsCompleted {
		return nil
	}

	if err := DeleteDHCPOptions(nbClient, pod); err != nil {
		return err
	}
	if err := DeleteRoutingForMigratedPod(nbClient, pod); err != nil {
		return err
	}
	return nil
}

func SyncVirtualMachines(nbClient libovsdbclient.Client, vms map[ktypes.NamespacedName]bool, controllerName string) error {
	if err := libovsdbops.DeleteLogicalRouterStaticRoutesWithPredicate(nbClient, ovntypes.OVNClusterRouter, func(item *nbdb.LogicalRouterStaticRoute) bool {
		return ownsItAndIsOrphanOrWrongZone(item.ExternalIDs, vms, controllerName)
	}); err != nil {
		return fmt.Errorf("failed deleting stale vm static routes: %v", err)
	}
	if err := libovsdbops.DeleteLogicalRouterPoliciesWithPredicate(nbClient, ovntypes.OVNClusterRouter, func(item *nbdb.LogicalRouterPolicy) bool {
		return ownsItAndIsOrphanOrWrongZone(item.ExternalIDs, vms, controllerName)
	}); err != nil {
		return fmt.Errorf("failed deleting stale vm policies: %v", err)
	}
	if err := libovsdbops.DeleteDHCPOptionsWithPredicate(nbClient, func(item *nbdb.DHCPOptions) bool {
		return ownsItAndIsOrphanOrWrongZone(item.ExternalIDs, vms, controllerName)
	}); err != nil {
		return fmt.Errorf("failed deleting stale dhcp options: %v", err)
	}
	return nil
}

// FindLiveMigratablePods will return all the pods with a `vm.kubevirt.io`
// label filtered by `kubevirt.io/allow-pod-bridge-network-live-migration`
// annotation
func FindLiveMigratablePods(watchFactory *factory.WatchFactory) ([]*corev1.Pod, error) {
	vmPods, err := watchFactory.GetAllPodsBySelector(
		metav1.LabelSelector{
			MatchLabels: virtLauncherPodLabel,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed looking for live migratable pods: %v", err)
	}
	liveMigratablePods := []*corev1.Pod{}
	for _, vmPod := range vmPods {
		if IsPodLiveMigratable(vmPod) {
			liveMigratablePods = append(liveMigratablePods, vmPod)
		}
	}
	return liveMigratablePods, nil
}

// allocateSyncMigratablePodIPs will refill ip pool in
// case the node has take over the vm subnet for live migrated vms
func allocateSyncMigratablePodIPs(watchFactory *factory.WatchFactory, lsManager *logicalswitchmanager.LogicalSwitchManager, nodeName, nadName string, pod *corev1.Pod, allocatePodIPsOnSwitch func(*corev1.Pod, *util.PodAnnotation, string, string) (string, error)) (*ktypes.NamespacedName, string, *util.PodAnnotation, error) {
	isStale, err := IsMigratedSourcePodStale(watchFactory, pod)
	if err != nil {
		return nil, "", nil, err
	}

	// We care only for Running virt-launcher pods
	if isStale {
		return nil, "", nil, nil
	}

	vmDescription, err := NewVMDescriptionFromPod(pod)
	if err != nil {
		return nil, "", nil, err
	}
	if vmDescription == nil {
		return nil, "", nil, nil
	}
	vmKey := vmDescription.Key()

	annotation, err := util.UnmarshalPodAnnotation(pod.Annotations, nadName)
	if err != nil {
		return nil, "", nil, nil
	}
	switchName, zoneContainsPodSubnet := ZoneContainsPodSubnet(lsManager, annotation.IPs)
	// If this zone do not own the subnet or the node that is passed
	// do not match the switch, they should not be deallocated
	if !zoneContainsPodSubnet || (nodeName != "" && switchName != nodeName) {
		return &vmKey, "", annotation, nil
	}
	expectedLogicalPortName, err := allocatePodIPsOnSwitch(pod, annotation, nadName, switchName)
	if err != nil {
		return &vmKey, "", nil, err
	}
	return &vmKey, expectedLogicalPortName, annotation, nil
}

// AllocateSyncMigratablePodIPsOnZone will refill ip pool in
// with pod's IPs if those IPs belong to the zone
func AllocateSyncMigratablePodIPsOnZone(watchFactory *factory.WatchFactory, lsManager *logicalswitchmanager.LogicalSwitchManager, nadName string, pod *corev1.Pod, allocatePodIPsOnSwitch func(*corev1.Pod, *util.PodAnnotation, string, string) (string, error)) (*ktypes.NamespacedName, string, *util.PodAnnotation, error) {
	// We care about the whole zone so we pass the nodeName empty
	return allocateSyncMigratablePodIPs(watchFactory, lsManager, nadName, "", pod, allocatePodIPsOnSwitch)
}

// ZoneContainsPodSubnetOrUntracked returns whether a pod with its corresponding
// allocated IPs as reflected on the annotation come from a subnet that is
// either assigned to a node of the zone or, not assigned to any node after
// migrating from a node that has since been deleted and the subnet originally
// assigned to that node has not yet been re-assigned to a different node. For
// convenience, the host subnets might not provided in which case they might be
// parsed and returned if used.
func ZoneContainsPodSubnetOrUntracked(watchFactory *factory.WatchFactory, lsManager *logicalswitchmanager.LogicalSwitchManager, hostSubnets []*net.IPNet, annotation *util.PodAnnotation) ([]*net.IPNet, bool, error) {
	_, local := ZoneContainsPodSubnet(lsManager, annotation.IPs)
	if local {
		return nil, true, nil
	}
	if len(hostSubnets) == 0 {
		nodes, err := watchFactory.GetNodes()
		if err != nil {
			return nil, false, err
		}
		hostSubnets, err = util.ParseNodesHostSubnetAnnotation(nodes, ovntypes.DefaultNetworkName)
		if err != nil {
			return nil, false, err
		}
	}
	// we can just use one of the IPs to check if it belongs to a subnet assigned
	// to a node
	return hostSubnets, !util.IsContainedInAnyCIDR(annotation.IPs[0], hostSubnets...), nil
}

// IsPodOwnedByVirtualMachine returns true if the pod is own by a
// kubevirt virtual machine, false otherwise.
func IsPodOwnedByVirtualMachine(pod *corev1.Pod) bool {
	for k, v := range virtLauncherPodLabel {
		if pod.Labels[k] != v {
			return false
		}
	}
	return true
}

// IsPodAllowedForMigration determines whether a given pod is eligible for live migration
func IsPodAllowedForMigration(pod *corev1.Pod, netInfo util.NetInfo) bool {
	return IsPodOwnedByVirtualMachine(pod) &&
		(netInfo.TopologyType() == ovntypes.Layer2Topology ||
			netInfo.TopologyType() == ovntypes.LocalnetTopology)
}

func isTargetPodReady(targetPod *corev1.Pod) bool {
	if targetPod == nil {
		return false
	}

	// This annotation only appears on live migration scenarios, and it signals
	// that target VM pod is ready to receive traffic, so we can route
	// traffic to it.
	targetReadyTimestamp := targetPod.Annotations[kubevirtv1.MigrationTargetReadyTimestamp]

	// VM is ready to receive traffic
	return targetReadyTimestamp != ""
}

func filterNotComplete(vmPods []*corev1.Pod) []*corev1.Pod {
	var notCompletePods []*corev1.Pod
	for _, vmPod := range vmPods {
		if !util.PodCompleted(vmPod) {
			notCompletePods = append(notCompletePods, vmPod)
		}
	}

	return notCompletePods
}

func tooManyPodsError(livingPods []*corev1.Pod) error {
	var podNames = make([]string, len(livingPods))
	for i := range livingPods {
		podNames[i] = livingPods[i].Namespace + "/" + livingPods[i].Name
	}
	return fmt.Errorf("unexpected live migration state at pods: %s", strings.Join(podNames, ","))
}

// LiveMigrationState represents the various states of a live migration process.
type LiveMigrationState string

const (
	// LiveMigrationInProgress indicates that a live migration is currently ongoing.
	LiveMigrationInProgress LiveMigrationState = "InProgress"

	// LiveMigrationTargetDomainReady indicates that the target domain is ready to take over.
	LiveMigrationTargetDomainReady LiveMigrationState = "TargetDomainReady"

	// LiveMigrationFailed indicates that the live migration process has failed.
	LiveMigrationFailed LiveMigrationState = "Failed"
)

// LiveMigrationStatus provides details about the current status of a live migration.
// It includes information about the source and target pods as well as the migration state.
type LiveMigrationStatus struct {
	SourcePod *corev1.Pod        // SourcePod is the original pod.
	TargetPod *corev1.Pod        // TargetPod is the destination pod.
	State     LiveMigrationState // State is the current state of the live migration.
}

// IsTargetDomainReady returns true if the target domain in the live migration process is ready.
func (lm LiveMigrationStatus) IsTargetDomainReady() bool {
	return lm.State == LiveMigrationTargetDomainReady
}

// DiscoverLiveMigrationStatus determines the status of a live migration for a given pod.
// It analyzes the state of pods associated with a VirtualMachine (VM) to identify whether
// a live migration is in progress, the target domain is ready, or the migration has failed.
//
// Note: The function assumes that the pod is part of a VirtualMachine resource managed
// by KubeVirt.
func DiscoverLiveMigrationStatus(client *factory.WatchFactory, pod *corev1.Pod) (*LiveMigrationStatus, error) {
	vmDescription, err := NewVMDescriptionFromPod(pod)
	if err != nil {
		return nil, err
	}

	if vmDescription == nil {
		return nil, nil
	}

	vmPods, err := vmDescription.OwnedPods(client.PodCoreInformer().Lister())
	if err != nil {
		return nil, err
	}

	// no migration
	if len(vmPods) < 2 {
		// If the only remaining pod has the migration target ready
		// annotation, the migration completed and the source pod is gone.
		if len(vmPods) == 1 && isTargetPodReady(vmPods[0]) {
			return &LiveMigrationStatus{
				TargetPod: vmPods[0],
				State:     LiveMigrationTargetDomainReady,
			}, nil
		}
		return nil, nil
	}

	// Sort vmPods by creation time
	sort.Slice(vmPods, func(i, j int) bool {
		return vmPods[j].CreationTimestamp.After(vmPods[i].CreationTimestamp.Time)
	})

	targetPod := vmPods[len(vmPods)-1]
	livingPods := filterNotComplete(vmPods)

	// If there is no living pod we should state no live migration status
	if len(livingPods) == 0 {
		return nil, nil
	}

	// There is a living pod but is not the target one so the migration
	// has failed.
	if util.PodCompleted(targetPod) {
		return &LiveMigrationStatus{
			SourcePod: livingPods[0],
			TargetPod: targetPod,
			State:     LiveMigrationFailed,
		}, nil
	}

	// Source pod completed but target is still living. If the target has the
	// migration ready annotation, the migration completed successfully.
	if len(livingPods) < 2 {
		if isTargetPodReady(targetPod) {
			return &LiveMigrationStatus{
				TargetPod: targetPod,
				State:     LiveMigrationTargetDomainReady,
			}, nil
		}
		return nil, nil
	}

	if len(livingPods) > 2 {
		return nil, tooManyPodsError(livingPods)
	}

	status := LiveMigrationStatus{
		SourcePod: livingPods[0],
		TargetPod: livingPods[1],
		State:     LiveMigrationInProgress,
	}

	if isTargetPodReady(status.TargetPod) {
		status.State = LiveMigrationTargetDomainReady
	}
	return &status, nil
}
