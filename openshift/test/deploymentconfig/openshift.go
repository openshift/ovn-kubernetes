package deploymentconfig

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig/api"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	imageutils "k8s.io/kubernetes/test/utils/image"
)

// FedoraContainerDiskImage matches Origin's approved live-migration test image.
const FedoraContainerDiskImage = "quay.io/kubevirt/fedora-with-test-tooling-container-disk:v1.8.2"

var (
	deploymentConfig api.DeploymentConfig
	imageIDMapping   map[api.ImageID]imageutils.ImageID = map[api.ImageID]imageutils.ImageID{
		api.Agnhost:             imageutils.Agnhost,
		api.FedoraContainerDisk: imageutils.None,
	}
	imageConfigMap map[api.ImageID]string
)

func init() {
	deploymentConfig = &openshift{
		requiredImages: make(map[api.ImageID]struct{}),
	}
	deploymentconfig.Set(deploymentConfig)

	// Add images that are needed by the test suite.
	imageConfigMap = map[api.ImageID]string{
		api.Agnhost:             imageutils.GetE2EImage(imageutils.Agnhost),
		api.FedoraContainerDisk: FedoraContainerDiskImage,
	}
	deploymentConfig.AddRequiredImage(api.Agnhost, api.FedoraContainerDisk)
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
	requiredImages map[api.ImageID]struct{}
}

func New() api.DeploymentConfig {
	return deploymentConfig
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
	return api.ImageConfig{ImageID: imageID, PullSpec: imageConfigMap[imageID]}
}

func (m *openshift) AddRequiredImage(imageID ...api.ImageID) {
	if m.requiredImages == nil {
		m.requiredImages = make(map[api.ImageID]struct{})
	}
	for _, imgID := range imageID {
		m.requiredImages[imgID] = struct{}{}
	}
}

func (m *openshift) GetRequiredImages() []api.ImageConfig {
	// OTE discovery runs without KIND_INSTALL_KUBEVIRT or cluster access.
	m.AddRequiredImage(api.Agnhost, api.FedoraContainerDisk)
	imageConfigs := []api.ImageConfig{}
	ids := make([]int, 0, len(m.requiredImages))
	for id := range m.requiredImages {
		ids = append(ids, int(id))
	}
	sort.Ints(ids)
	for _, id := range ids {
		imageID := api.ImageID(id)
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
