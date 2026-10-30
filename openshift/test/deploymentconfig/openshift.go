// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package deploymentconfig

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig/api"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	e2epodoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
	imageutils "k8s.io/kubernetes/test/utils/image"

	imageclient "github.com/openshift/client-go/image/clientset/versioned"
)

// FedoraKubevirtContainerDiskImage is the source image for virtualization tests.
const FedoraKubevirtContainerDiskImage = "quay.io/kubevirt/fedora-with-test-tooling-container-disk:v1.8.2"

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

type openshift struct {
	kubeConfig     *rest.Config
	requiredImages map[api.ImageID]struct{}
	imageConfigMap map[api.ImageID]api.ImageConfig
}

func New(config *rest.Config) *openshift {
	return &openshift{
		kubeConfig:     config,
		requiredImages: make(map[api.ImageID]struct{}),
	}
}

// SetupImages resolves the test images for this deployment configuration.
func (m *openshift) SetupImages() error {
	// Add images that are needed by the test suite.
	imageConfigMap := map[api.ImageID]api.ImageConfig{
		api.Agnhost: {
			ImageID:  api.Agnhost,
			PullSpec: imageutils.GetE2EImage(imageutils.Agnhost),
		},
	}

	var err error
	imageConfigMap[api.FedoraKubevirtContainerDisk], err = imageConfigWithPullSpecFromMirror(
		api.FedoraKubevirtContainerDisk,
		FedoraKubevirtContainerDiskImage)
	if err != nil {
		return err
	}

	// ImageStream resolution requires cluster access; keep offline discovery
	// available when no kubeconfig is supplied.
	if m.kubeConfig != nil {
		imageConfigMap[api.Netshoot], err = imageConfigWithPullSpecFromImageStream(m.kubeConfig,
			api.Netshoot,
			"network-tools")
		if err != nil {
			return err
		}
	}

	m.imageConfigMap = imageConfigMap
	return nil
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
	if m.kubeConfig == nil {
		return ""
	}
	kubeClient, err := kubernetes.NewForConfig(m.kubeConfig)
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
	iface, err := m.findPrimaryInterface(kubeClient, nodes.Items[0].Name)
	if err != nil {
		panic(fmt.Sprintf("failed to find primary interface: %v", err))
	}
	return iface
}

func (m *openshift) IsConfigurationEnabled(config api.Config) bool {
	return false
}

func (m *openshift) NBDBContainerName() string {
	return "nbdb"
}

func imageConfigWithPullSpecFromMirror(imageID api.ImageID, pullSpec string) (api.ImageConfig, error) {
	// The repository mapping supports images outside the Kubernetes registry
	// list. Without it, discovery uses the source pull spec.
	if os.Getenv("KUBE_TEST_REPO") != "" {
		mirroredPullSpec, err := imageutils.ReplaceRegistryInImageURL(pullSpec)
		if err != nil {
			return api.ImageConfig{}, fmt.Errorf("failed resolving pull spec %q from mirror: %w", pullSpec, err)
		}
		pullSpec = mirroredPullSpec
	}
	return api.ImageConfig{
		ImageID:  imageID,
		PullSpec: pullSpec,
	}, nil
}

func imageConfigWithPullSpecFromImageStream(kubeConfig *rest.Config, imageID api.ImageID, imageStream string) (api.ImageConfig, error) {
	imageClient, err := imageclient.NewForConfig(kubeConfig)
	if err != nil {
		return api.ImageConfig{}, fmt.Errorf("failed resolving pull spec while retrieving openshift image client: %w", err)
	}

	istag, err := imageClient.ImageV1().ImageStreamTags("openshift").Get(context.Background(), imageStream+":latest", metav1.GetOptions{})
	if err != nil {
		return api.ImageConfig{}, fmt.Errorf("failed resolving pull spec while retrieving image stream tags from %q: %w", imageStream, err)
	}

	return api.ImageConfig{
		ImageID:  imageID,
		PullSpec: istag.Image.DockerImageReference,
	}, nil
}

func (m *openshift) GetImage(imageID api.ImageID) api.ImageConfig {
	return m.imageConfigMap[imageID]
}

func (m *openshift) AddRequiredImage(imageID ...api.ImageID) {
	for _, imgID := range imageID {
		m.requiredImages[imgID] = struct{}{}
	}
}

func (m *openshift) GetRequiredImages() []api.ImageConfig {
	imageConfigs := []api.ImageConfig{}
	for imageID := range m.requiredImages {
		imageConfigs = append(imageConfigs, m.GetImage(imageID))
	}
	return imageConfigs
}

func (m *openshift) GetNodeMachineNetworks() (map[string][]string, error) {
	if m.kubeConfig == nil {
		return make(map[string][]string), nil
	}
	kubeClient, err := kubernetes.NewForConfig(m.kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	nodes, err := kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}
	result := make(map[string][]string, len(nodes.Items))
	for i := range nodes.Items {
		node := &nodes.Items[i]
		// On cloud platforms, CNCC sets the cloud egress IP annotation
		// with the actual routable subnet. Use it when present, fall
		// back to node-primary-ifaddr for baremetal.
		parsed, err := util.ParseCloudEgressIPConfig(node)
		if err != nil {
			parsed, err = util.ParseNodePrimaryIfAddr(node)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse node %s primary address: %w", node.Name, err)
		}
		var subnets []string
		if parsed.V4.Net != nil {
			subnets = append(subnets, parsed.V4.Net.String())
		}
		if parsed.V6.Net != nil {
			subnets = append(subnets, parsed.V6.Net.String())
		}
		result[node.Name] = subnets
	}
	return result, nil
}

// findPrimaryInterface queries ovs-vsctl on an ovnkube-node pod to find the
// physical uplink port on br-ex. The physical NIC is the OVS port whose
// interface type is "system".
func (m *openshift) findPrimaryInterface(kubeClient *kubernetes.Clientset, nodeName string) (string, error) {
	ovnNamespace := m.OVNKubernetesNamespace()
	ovnkubeNodePods, err := kubeClient.CoreV1().Pods(ovnNamespace).List(context.Background(), metav1.ListOptions{
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
	ports, err := e2epodoutput.RunHostCmd(ovnNamespace, ovnKubeNodePodName, "ovs-vsctl list-ports br-ex")
	if err != nil {
		return "", err
	}
	for _, port := range strings.Split(strings.TrimSpace(ports), "\n") {
		port = strings.TrimSpace(port)
		if port == "" {
			continue
		}
		out, err := e2epodoutput.RunHostCmd(ovnNamespace, ovnKubeNodePodName, fmt.Sprintf("ovs-vsctl get Port %s Interfaces", port))
		if err != nil {
			return "", err
		}
		// remove brackets on list of interfaces
		ifaces := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(out), "]"), "[")
		for _, iface := range strings.Split(ifaces, ",") {
			out, err := e2epodoutput.RunHostCmd(ovnNamespace, ovnKubeNodePodName, fmt.Sprintf("ovs-vsctl get Interface %s Type", strings.TrimSpace(iface)))
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

func (m *openshift) OVNControllerLogPath() string {
	return "/var/log/ovn/acl-audit-log.log"
}
