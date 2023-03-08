package ovn

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	kapi "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"

	kubevirtv1 "kubevirt.io/api/core/v1"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kubevirt"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	ovntypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

// ensureNetworkInfoForVM will at live migration extract the ovn pod
// annotations and original switch name from the source vm pod and copy it
// to the target vm pod so ip address follow vm during migration. This has to
// done before creating the LSP to be sure that Address field get configured
// correctly at the target VM pod LSP.
func ensureNetworkInfoForVM(watchFactory *factory.WatchFactory, kube *kube.KubeOVN, pod *corev1.Pod) error {
	if !kubevirt.IsPodLiveMigratable(pod) {
		return nil
	}
	vmNetworkInfo, err := kubevirt.FindNetworkInfo(watchFactory, pod)
	if err != nil {
		return err
	}
	resultErr := retry.RetryOnConflict(util.OvnConflictBackoff, func() error {
		// Informer cache should not be mutated, so get a copy of the object
		pod, err := watchFactory.GetPod(pod.Namespace, pod.Name)
		if err != nil {
			return err
		}
		cpod := pod.DeepCopy()
		_, ok := cpod.Labels[kubevirt.OriginalSwitchNameLabel]
		if !ok {
			cpod.Labels[kubevirt.OriginalSwitchNameLabel] = vmNetworkInfo.OriginalSwitchName
		}
		if vmNetworkInfo.Status != "" {
			cpod.Annotations[util.OvnPodAnnotationName] = vmNetworkInfo.Status
		}
		return kube.UpdatePod(cpod)
	})
	if resultErr != nil {
		return fmt.Errorf("failed to update labels and annotations on pod %s/%s: %v", pod.Namespace, pod.Name, resultErr)
	}

	// There is nothing to check
	if vmNetworkInfo.Status == "" {
		return nil
	}
	// Wait until informers cache get updated so we don't depend on conflict
	// mechanism at next pod annotations update
	return wait.ExponentialBackoff(util.OvnConflictBackoff, func() (bool, error) {
		pod, err := watchFactory.GetPod(pod.Namespace, pod.Name)
		if err != nil {
			return false, err
		}
		currentNetworkInfoStatus, ok := pod.Annotations[util.OvnPodAnnotationName]
		if !ok || currentNetworkInfoStatus != vmNetworkInfo.Status {
			return false, err
		}
		originalSwitchName, ok := pod.Labels[kubevirt.OriginalSwitchNameLabel]
		if !ok || originalSwitchName != vmNetworkInfo.OriginalSwitchName {
			return false, err
		}
		return true, nil
	})
}

func (oc *DefaultNetworkController) ensureDHCPOptionsForVM(pod *corev1.Pod, lsp *nbdb.LogicalSwitchPort) error {
	ovnPodAnnotation, err := util.UnmarshalPodAnnotation(pod.Annotations, ovntypes.DefaultNetworkName)
	if err != nil {
		return fmt.Errorf("failed retrieving subnets to configure DHCP at lsp %s: %v", lsp.Name, err)
	}
	// Fake router to delegate on proxy arp mechanism
	vmName, ok := pod.Labels[kubevirtv1.VirtualMachineNameLabel]
	if !ok {
		return fmt.Errorf("missing %s label at pod %s/%s when configuaring DHCP", kubevirtv1.VirtualMachineNameLabel, pod.Namespace, pod.Name)
	}
	dhcpConfigs, err := kubevirt.ComposeDHCPConfigs(oc.watchFactory, oc.controllerName, pod.Namespace, vmName, ovnPodAnnotation.IPs)
	if err != nil {
		return fmt.Errorf("failed composing DHCP options: %v", err)
	}
	err = libovsdbops.CreateOrUpdateDhcpOptions(oc.nbClient, lsp, dhcpConfigs.V4, dhcpConfigs.V6)
	if err != nil {
		return fmt.Errorf("failed creation or updating OVN operations to add DHCP options: %v", err)
	}
	return nil
}

func (oc *DefaultNetworkController) deleteDHCPOptions(pod *kapi.Pod) error {
	vmKey := kubevirt.ExtractVMNameFromPod(pod)
	if vmKey == nil {
		return nil
	}
	predicateIDs := libovsdbops.NewDbObjectIDs(libovsdbops.VirtualMachineDHCPOptions, oc.controllerName,
		map[libovsdbops.ExternalIDKey]string{
			libovsdbops.NamespaceIndex:      vmKey.Namespace,
			libovsdbops.VirtualMachineIndex: vmKey.Name,
		})
	predicate := libovsdbops.GetPredicate[*nbdb.DHCPOptions](predicateIDs, nil)
	return libovsdbops.DeleteDHCPOptionsWithPredicate(oc.nbClient, predicate)
}

func (oc *DefaultNetworkController) kubevirtCleanUp(pod *corev1.Pod) error {
	if kubevirt.IsPodLiveMigratable(pod) {
		isMigratedSourcePodStale, err := kubevirt.IsMigratedSourcePodStale(oc.watchFactory, pod)
		if err != nil {
			return err
		}

		if !isMigratedSourcePodStale {
			if err := oc.deleteDHCPOptions(pod); err != nil {
				return err
			}
		}
	}
	return nil
}
