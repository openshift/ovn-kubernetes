package ovn

import (
	"fmt"
	"net"

	corev1 "k8s.io/api/core/v1"
	kapi "k8s.io/api/core/v1"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kubevirt"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
)

func (oc *DefaultNetworkController) ensureDHCPOptionsForVM(pod *corev1.Pod, lsp *nbdb.LogicalSwitchPort) error {
	if !kubevirt.AllowPodBridgeNetworkLiveMigration(pod.Annotations) {
		return nil
	}

	switchNames, err := oc.getSwitchNames(pod)
	if err != nil {
		return err
	}
	var switchSubnets []*net.IPNet
	if switchSubnets = oc.lsManager.GetSwitchSubnets(switchNames.Original); switchSubnets == nil {
		return fmt.Errorf("subnet not found for switch %s to configuare DHCP at lsp %s", switchNames.Original, lsp.Name)
	}
	// Fake router to delegate on proxy arp mechanism
	vmName, ok := pod.Labels[kubevirt.VMLabel]
	if !ok {
		return fmt.Errorf("missing %s label at pod %s/%s when configuaring DHCP", kubevirt.VMLabel, pod.Namespace, pod.Name)
	}
	dhcpConfig, err := kubevirt.ComposeDHCPConfig(oc.watchFactory, vmName, switchSubnets)
	if err != nil {
		return fmt.Errorf("failed composing DHCP options: %v", err)
	}

	if dhcpConfig.V4Options != nil {
		dhcpConfig.V4Options.ExternalIDs = map[string]string{
			"namespace":      pod.Namespace,
			kubevirt.VMLabel: vmName,
		}
	}
	if dhcpConfig.V6Options != nil {
		dhcpConfig.V6Options.ExternalIDs = map[string]string{
			"namespace":      pod.Namespace,
			kubevirt.VMLabel: vmName,
		}
	}
	err = libovsdbops.CreateOrUpdateDhcpOptions(oc.nbClient, lsp, dhcpConfig.V4Options, dhcpConfig.V6Options)
	if err != nil {
		return fmt.Errorf("failed creation or updating OVN operations to add DHCP options: %v", err)
	}
	return nil
}

func (oc *DefaultNetworkController) deleteDHCPOptions(pod *kapi.Pod) error {
	predicate := func(item *nbdb.DHCPOptions) bool {
		return kubevirt.PodMatchesExternalIDs(pod, item.ExternalIDs)
	}
	return libovsdbops.DeleteDHCPOptionsWithPredicate(oc.nbClient, predicate)
}

func (oc *DefaultNetworkController) kubevirtCleanUp(pod *corev1.Pod) error {
	if kubevirt.AllowPodBridgeNetworkLiveMigration(pod.Annotations) {
		isLiveMigrationLefover, err := kubevirt.PodIsLiveMigrationLeftOver(oc.watchFactory, pod)
		if err != nil {
			return err
		}

		if !isLiveMigrationLefover {
			if err := oc.deleteDHCPOptions(pod); err != nil {
				return err
			}
		}
	}
	return nil
}
