package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/ovn-org/ovn-kubernetes/test/e2e/deploymentconfig"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	e2epodoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
)

const (
	defaultOvsBridge = "breth0"
	secondaryBridge  = "ovsbr1"
	add              = "add-br"
	del              = "del-br"
)

func setupUnderlay(ovsPods []v1.Pod, bridgeName, portName, networkName string, vlanID int) error {
	for _, ovsPod := range ovsPods {
		if bridgeName != defaultOvsBridge {
			if err := addOVSBridge(ovsPod.Namespace, ovsPod.Name, bridgeName); err != nil {
				return err
			}

			if vlanID > 0 {
				if err := ovsEnableVLANAccessPort(ovsPod.Namespace, ovsPod.Name, bridgeName, portName, vlanID); err != nil {
					return err
				}
			} else {
				if err := ovsAttachPortToBridge(ovsPod.Namespace, ovsPod.Name, bridgeName, portName); err != nil {
					return err
				}
			}
		}
		if err := configureBridgeMappings(
			ovsPod.Namespace,
			ovsPod.Name,
			defaultNetworkBridgeMapping(),
			bridgeMapping(networkName, bridgeName),
		); err != nil {
			return err
		}
	}
	return nil
}

func ovsRemoveSwitchPort(ovsPods []v1.Pod, portName string, newVLANID int) error {
	for _, ovsPod := range ovsPods {
		if err := ovsRemoveVLANAccessPort(ovsPod.Namespace, ovsPod.Name, secondaryBridge, portName); err != nil {
			return fmt.Errorf("failed to remove old VLAN port: %v", err)
		}

		if err := ovsEnableVLANAccessPort(ovsPod.Namespace, ovsPod.Name, secondaryBridge, portName, newVLANID); err != nil {
			return fmt.Errorf("failed to add new VLAN port: %v", err)
		}
	}

	return nil
}

func teardownUnderlay(ovsPods []v1.Pod, bridgeName string) error {
	for _, ovsPod := range ovsPods {
		if bridgeName != defaultOvsBridge {
			if err := removeOVSBridge(ovsPod.Namespace, ovsPod.Name, bridgeName); err != nil {
				return err
			}
		}
		// restore default bridge mapping
		if err := configureBridgeMappings(
			ovsPod.Namespace,
			ovsPod.Name,
			defaultNetworkBridgeMapping(),
		); err != nil {
			return err
		}
	}
	return nil
}

func ovsPods(clientSet clientset.Interface) []v1.Pod {
	const (
		ovsNodeLabel = "app=ovs-node"
	)
	pods, err := clientSet.CoreV1().Pods(deploymentconfig.Get().OVNKubernetesNamespace()).List(
		context.Background(),
		metav1.ListOptions{LabelSelector: ovsNodeLabel},
	)
	if err != nil {
		return nil
	}
	return pods.Items
}

func addOVSBridge(podNamespace, podName string, bridgeName string) error {
	cmd := strings.Join([]string{"ovs-vsctl", add, bridgeName}, " ")
	if _, err := e2epodoutput.RunHostCmdWithRetries(podNamespace, podName, cmd, time.Second, time.Second*5); err != nil {
		return fmt.Errorf("failed to add ovs bridge %q: %v", bridgeName, err)
	}
	return nil
}

func removeOVSBridge(podNamespace, podName string, bridgeName string) error {
	cmd := strings.Join([]string{"ovs-vsctl", del, bridgeName}, " ")
	if _, err := e2epodoutput.RunHostCmdWithRetries(podNamespace, podName, cmd, time.Second, time.Second*5); err != nil {
		return fmt.Errorf("failed to add ovs bridge %q: %v", bridgeName, err)
	}
	return nil
}

func ovsAttachPortToBridge(podNamespace, podName string, bridgeName string, portName string) error {
	cmd := strings.Join([]string{
		"ovs-vsctl", "add-port", bridgeName, portName,
	}, " ")
	if _, err := e2epodoutput.RunHostCmdWithRetries(podNamespace, podName, cmd, time.Second, time.Second*5); err != nil {
		return fmt.Errorf("failed to remove port %s from OVS bridge %s: %v", portName, bridgeName, err)
	}
	return nil
}

func ovsEnableVLANAccessPort(podNamespace, podName string, bridgeName string, portName string, vlanID int) error {
	cmd := strings.Join([]string{
		"ovs-vsctl", "add-port", bridgeName, portName, fmt.Sprintf("tag=%d", vlanID), "vlan_mode=access",
	}, " ")
	if _, err := e2epodoutput.RunHostCmdWithRetries(podNamespace, podName, cmd, time.Second, time.Second*5); err != nil {
		return fmt.Errorf("failed to remove port %s from OVS bridge %s: %v", portName, bridgeName, err)
	}
	return nil
}

func ovsRemoveVLANAccessPort(podNamespace, podName string, bridgeName string, portName string) error {
	cmd := strings.Join([]string{
		"ovs-vsctl", "del-port", bridgeName, portName,
	}, " ")
	if _, err := e2epodoutput.RunHostCmdWithRetries(podNamespace, podName, cmd, time.Second, time.Second*5); err != nil {
		return fmt.Errorf("failed to remove port %s from OVS bridge %s: %v", portName, bridgeName, err)
	}
	return nil
}

type BridgeMapping struct {
	physnet   string
	ovsBridge string
}

func (bm BridgeMapping) String() string {
	return fmt.Sprintf("%s:%s", bm.physnet, bm.ovsBridge)
}

type BridgeMappings []BridgeMapping

func (bms BridgeMappings) String() string {
	return strings.Join(Map(bms, func(bm BridgeMapping) string { return bm.String() }), ",")
}

func Map[T, V any](items []T, fn func(T) V) []V {
	result := make([]V, len(items))
	for i, t := range items {
		result[i] = fn(t)
	}
	return result
}

func configureBridgeMappings(podNamespace, podName string, mappings ...BridgeMapping) error {
	mappingsString := fmt.Sprintf("external_ids:ovn-bridge-mappings=%s", BridgeMappings(mappings).String())
	cmd := strings.Join([]string{"ovs-vsctl", "set", "open", ".", mappingsString}, " ")
	if _, err := e2epodoutput.RunHostCmdWithRetries(podNamespace, podName, cmd, time.Second, time.Second*5); err != nil {
		return fmt.Errorf("failed to configure bridge mappings %q: %v", mappingsString, err)
	}
	return nil
}

func defaultNetworkBridgeMapping() BridgeMapping {
	return BridgeMapping{
		physnet:   "physnet",
		ovsBridge: "breth0",
	}
}

func bridgeMapping(physnet, ovsBridge string) BridgeMapping {
	return BridgeMapping{
		physnet:   physnet,
		ovsBridge: ovsBridge,
	}
}

// TODO: make this function idempotent; use golang netlink instead
func createVLANInterface(deviceName string, vlanID string, ipAddress *string) error {
	vlan := vlanName(deviceName, vlanID)
	cmd := exec.Command("sudo", "ip", "link", "add", "link", deviceName, "name", vlan, "type", "vlan", "id", vlanID)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create vlan interface %s: %v", vlan, err)
	}

	cmd = exec.Command("sudo", "ip", "link", "set", "dev", vlan, "up")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to enable vlan interface %s: %v", vlan, err)
	}

	if ipAddress != nil {
		cmd = exec.Command("sudo", "ip", "addr", "add", *ipAddress, "dev", vlan)
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to define the vlan interface %q IP Address %s: %v", vlan, *ipAddress, err)
		}
	}
	return nil
}

// TODO: make this function idempotent; use golang netlink instead
func deleteVLANInterface(deviceName string, vlanID string) error {
	vlan := vlanName(deviceName, vlanID)
	cmd := exec.Command("sudo", "ip", "link", "del", vlan)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to delete vlan interface %s: %v", vlan, err)
	}
	return nil
}

func vlanName(deviceName string, vlanID string) string {
	// MAX IFSIZE 16; got to truncate it to add the vlan suffix
	if len(deviceName)+len(vlanID)+1 > 16 {
		deviceName = deviceName[:len(deviceName)-len(vlanID)-1]
	}
	return fmt.Sprintf("%s.%s", deviceName, vlanID)
}
