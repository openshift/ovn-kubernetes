package ovn

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	kapi "k8s.io/api/core/v1"

	kubevirtv1 "kubevirt.io/api/core/v1"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kubevirt"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	ovntypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

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
	err = libovsdbops.CreateOrUpdateDhcpOptions(oc.nbClient, lsp, dhcpConfigs)
	if err != nil {
		return fmt.Errorf("failed creation or updating OVN operations to add DHCP options: %v", err)
	}
	return nil
}

func (oc *DefaultNetworkController) deleteDHCPOptions(pod *kapi.Pod) error {
	predicate := func(item *nbdb.DHCPOptions) bool {
		return kubevirt.ExternalIDsContainsVM(item.ExternalIDs, kubevirt.ExtractVMFromPod(pod))
	}
	return libovsdbops.DeleteDHCPOptionsWithPredicate(oc.nbClient, predicate)
}

func (oc *DefaultNetworkController) kubevirtCleanUp(pod *corev1.Pod) error {
	if kubevirt.PodIsLiveMigratable(pod) {
		isMigratedSourcePodState, err := kubevirt.IsMigratedSourcePodStale(oc.watchFactory, pod)
		if err != nil {
			return err
		}

		if !isMigratedSourcePodState {
			if err := oc.deleteDHCPOptions(pod); err != nil {
				return err
			}
		}
	}
	return nil
}
