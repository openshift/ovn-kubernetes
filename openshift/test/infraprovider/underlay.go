package infraprovider

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	e2epodoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
)

const ovnKubeNodeLabel = "app=ovnkube-node"

// bridgeMapping represents a single OVN bridge-mapping entry (physnet:ovsBridge).
type bridgeMapping struct {
	physnet   string
	ovsBridge string
}

func (bm bridgeMapping) String() string {
	return fmt.Sprintf("%s:%s", bm.physnet, bm.ovsBridge)
}

func bridgeMappingsString(mappings []bridgeMapping) string {
	entries := make([]string, 0, len(mappings))
	for _, m := range mappings {
		entries = append(entries, m.String())
	}
	return strings.Join(entries, ",")
}

// defaultNetworkBridgeMapping is the mapping OVN-Kubernetes maintains for the
// cluster default network's external bridge.
func defaultNetworkBridgeMapping() bridgeMapping {
	return bridgeMapping{physnet: "physnet", ovsBridge: deploymentconfig.Get().ExternalBridgeName()}
}

func configureBridgeMappings(podNamespace, podName string, mappings ...bridgeMapping) error {
	mappingsArg := fmt.Sprintf("external_ids:ovn-bridge-mappings=%s", bridgeMappingsString(mappings))
	cmd := strings.Join([]string{"ovs-vsctl", "set", "open", ".", mappingsArg}, " ")
	if _, err := e2epodoutput.RunHostCmdWithRetries(podNamespace, podName, cmd, time.Second, 5*time.Second); err != nil {
		return fmt.Errorf("failed to configure bridge mappings %q: %w", mappingsArg, err)
	}
	return nil
}

func findOVSPods(f *framework.Framework) ([]corev1.Pod, error) {
	namespace := deploymentconfig.Get().OVNKubernetesNamespace()
	ovsPodList, err := f.ClientSet.CoreV1().Pods(namespace).List(
		context.Background(),
		metav1.ListOptions{LabelSelector: ovnKubeNodeLabel},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list OVS pods with label %q in namespace %q: %w", ovnKubeNodeLabel, namespace, err)
	}
	if len(ovsPodList.Items) == 0 {
		return nil, fmt.Errorf("no pods with label %q in namespace %q", ovnKubeNodeLabel, namespace)
	}
	return ovsPodList.Items, nil
}

// SetupUnderlay wires a localnet logical network to an OVS bridge on every node
// by configuring the OVN bridge-mappings. On OpenShift the localnet is mapped to
// the shared external bridge (br-ex): no dedicated bridge or physical NIC is
// created, so only the bridge-mapping is added alongside the default mapping.
// A cleanup function restores the default mapping when the test context ends.
func (o *contextOpenshift) SetupUnderlay(f *framework.Framework, underlay api.Underlay) error {
	if underlay.LogicalNetworkName == "" {
		return fmt.Errorf("underlay logical network name must be set")
	}
	if underlay.BridgeName == "" {
		underlay.BridgeName = deploymentconfig.Get().ExternalBridgeName()
	}
	if underlay.BridgeName != deploymentconfig.Get().ExternalBridgeName() {
		return fmt.Errorf("openshift underlay only supports the external bridge %q, got %q",
			deploymentconfig.Get().ExternalBridgeName(), underlay.BridgeName)
	}

	o.AddCleanUpFn(func() error {
		ovsPods, err := findOVSPods(f)
		if err != nil {
			return fmt.Errorf("failed finding OVS pods during openshift underlay tear down: %w", err)
		}
		for _, ovsPod := range ovsPods {
			if err := configureBridgeMappings(ovsPod.Namespace, ovsPod.Name, defaultNetworkBridgeMapping()); err != nil {
				return fmt.Errorf("failed to restore default bridge mappings for pod %s/%s during cleanup: %w",
					ovsPod.Namespace, ovsPod.Name, err)
			}
		}
		return nil
	})

	ovsPods, err := findOVSPods(f)
	if err != nil {
		return fmt.Errorf("failed finding OVS pods during openshift underlay setup: %w", err)
	}
	for _, ovsPod := range ovsPods {
		if err := configureBridgeMappings(
			ovsPod.Namespace,
			ovsPod.Name,
			defaultNetworkBridgeMapping(),
			bridgeMapping{physnet: underlay.LogicalNetworkName, ovsBridge: underlay.BridgeName},
		); err != nil {
			return fmt.Errorf("failed to configure bridge mappings for pod %s/%s for logical network %s to bridge %s: %w",
				ovsPod.Namespace, ovsPod.Name, underlay.LogicalNetworkName, underlay.BridgeName, err)
		}
	}
	return nil
}
