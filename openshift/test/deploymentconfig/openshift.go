package deploymentconfig

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig/api"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	imageutils "k8s.io/kubernetes/test/utils/image"
)

var (
	imageIDMapping map[api.ImageID]imageutils.ImageID = map[api.ImageID]imageutils.ImageID{
		api.Agnhost: imageutils.Agnhost,
	}
	imageConfigMap map[api.ImageID]api.ImageConfig
)

func init() {
	// Add images that are needed by the test suite.
	imageConfigMap = map[api.ImageID]api.ImageConfig{
		api.Agnhost: {
			ImageID:  api.Agnhost,
			PullSpec: imageutils.GetE2EImage(imageutils.Agnhost),
		},
	}
}

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
}

func New(config *rest.Config) api.DeploymentConfig {
	return &openshift{kubeConfig: config,
		requiredImages: make(map[api.ImageID]struct{})}
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
	// support only for baremetald which expects the following interface name
	// TODO; dynamically look up primary interface name instead of hardcoding it to baremetald env
	return "enp0s3"
}

func (m *openshift) IsConfigurationEnabled(config api.Config) bool {
	return false
}

func (m *openshift) NBDBContainerName() string {
	return "nbdb"
}

func (m *openshift) GetImage(imageID api.ImageID) api.ImageConfig {
	return imageConfigMap[imageID]
}

func (m *openshift) AddRequiredImage(imageID ...api.ImageID) {
	for _, imgID := range imageID {
		m.requiredImages[imgID] = struct{}{}
	}
}

func (m *openshift) GetRequiredImages() []api.ImageConfig {
	imageConfigs := []api.ImageConfig{}
	for imageID := range m.requiredImages {
		newID, ok := imageIDMapping[imageID]
		if !ok {
			newID = imageutils.None
		}
		imageConfigs = append(imageConfigs, api.ImageConfig{
			ImageID:  api.ImageID(newID),
			PullSpec: m.GetImage(imageID).PullSpec,
		})
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
