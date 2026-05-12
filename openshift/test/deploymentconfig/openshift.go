package deploymentconfig

import (
	"context"
	"fmt"
	"strings"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig/api"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	e2epodoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
)

func IsOpenShift(config *rest.Config) (bool, error) {
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return false, fmt.Errorf("failed to create kubernetes client: %w", err)
	}
	// Check for OpenShift-specific API groups
	groups, err := kubeClient.Discovery().ServerGroups()
	if err != nil {
		return false, fmt.Errorf("failed to get server groups: %w", err)
	}
	for _, group := range groups.Groups {
		if strings.HasSuffix(group.Name, ".openshift.io") {
			return true, nil
		}
	}
	return false, nil
}

const (
	ovnpodNamespace = "openshift-ovn-kubernetes"
)

type openshift struct {
	config           *rest.Config
	primaryInterface string
}

func New(cfg *rest.Config) api.DeploymentConfig {
	return &openshift{config: cfg}
}

// findPrimaryInterface queries ovs-vsctl on an ovnkube-node pod to find the
// physical uplink port on br-ex. The physical NIC is the OVS port whose
// interface type is "system".
func findPrimaryInterface(kubeClient *kubernetes.Clientset, nodeName string) (string, error) {
	ovnkubeNodePods, err := kubeClient.CoreV1().Pods(ovnpodNamespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: "app=ovnkube-node",
		FieldSelector: "spec.nodeName=" + nodeName,
	})
	if err != nil {
		return "", err
	}
	if len(ovnkubeNodePods.Items) != 1 {
		return "", fmt.Errorf("failed to find ovnkube-node pod for node instance %s", nodeName)
	}
	ovnKubeNodePodName := ovnkubeNodePods.Items[0].Name
	ports, err := e2epodoutput.RunHostCmd(ovnpodNamespace, ovnKubeNodePodName, "ovs-vsctl list-ports br-ex")
	if err != nil {
		return "", err
	}
	for _, port := range strings.Split(strings.TrimSpace(ports), "\n") {
		port = strings.TrimSpace(port)
		if port == "" {
			continue
		}
		out, err := e2epodoutput.RunHostCmd(ovnpodNamespace, ovnKubeNodePodName, fmt.Sprintf("ovs-vsctl get Port %s Interfaces", port))
		if err != nil {
			return "", err
		}
		// remove brackets on list of interfaces
		ifaces := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(out), "]"), "[")
		for _, iface := range strings.Split(ifaces, ",") {
			out, err := e2epodoutput.RunHostCmd(ovnpodNamespace, ovnKubeNodePodName, fmt.Sprintf("ovs-vsctl get Interface %s Type", strings.TrimSpace(iface)))
			if err != nil {
				return "", err
			}
			// If system Type we know this is the OVS port is the NIC
			if strings.TrimSpace(out) == "system" {
				return port, nil
			}
		}
	}
	return "", fmt.Errorf("failed to find network interface from ovnkube-node pod %s", ovnKubeNodePodName)
}

func (m *openshift) OVNKubernetesNamespace() string {
	return "openshift-ovn-kubernetes"
}

func (m *openshift) FRRK8sNamespace() string {
	return "openshift-frr-k8s"
}

func (m *openshift) ExternalBridgeName() string {
	return "br-ex"
}

func (m *openshift) PrimaryInterfaceName() string {
	if m.primaryInterface != "" {
		return m.primaryInterface
	}
	kubeClient, err := kubernetes.NewForConfig(m.config)
	if err != nil {
		panic(fmt.Sprintf("failed to create kubernetes client: %v", err))
	}
	nodes, err := kubeClient.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{Limit: 1})
	if err != nil {
		panic(fmt.Sprintf("failed to list nodes: %v", err))
	}
	if len(nodes.Items) == 0 {
		panic("no nodes found in cluster")
	}
	iface, err := findPrimaryInterface(kubeClient, nodes.Items[0].Name)
	if err != nil {
		panic(fmt.Sprintf("failed to find primary interface: %v", err))
	}
	m.primaryInterface = iface
	return m.primaryInterface
}

func (m *openshift) GetAgnHostContainerImage() string {
	// use downloadable image for external container.
	// ref: https://github.com/openshift/release/blob/db6697de61f4ae7e05c5a2db782a87c459e849bf/ci-operator/step-registry/baremetalds/e2e/ovn/bgp/pre/baremetalds-e2e-ovn-bgp-pre-commands.sh#L197
	return "registry.k8s.io/e2e-test-images/agnhost:2.40"
}
