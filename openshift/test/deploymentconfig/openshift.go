package deploymentconfig

import (
	"fmt"
	"strings"
	"sync"

	imageclient "github.com/openshift/client-go/image/clientset/versioned"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/images"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	imageutils "k8s.io/kubernetes/test/utils/image"
)

var (
	deploymentConfig api.DeploymentConfig
	imageIDMapping   map[api.ImageID]imageutils.ImageID = map[api.ImageID]imageutils.ImageID{
		images.Agnhost: imageutils.Agnhost,
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
		images.Agnhost: imageutils.GetE2EImage(imageutils.Agnhost),
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
	requiredImages map[api.ImageID]struct{}
	imageLock         sync.Mutex
	imageClient       imageclient.Interface
	networkToolsImage string
	configClient      kubernetes.Interface
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
	if config == api.PreconfiguredUDNAddressesConfig {
		enabled, err := m.preconfiguredUDNAddressesEnabled()
		if err != nil {
			panic(err)
		}
		return enabled
	}
	return false
}

func (m *openshift) NBDBContainerName() string {
	return "nbdb"
}

func (m *openshift) GetImage(imageID api.ImageID) string {
	return imageConfigMap[imageID]
}

func (m *openshift) AddImage(imageID ...api.ImageID) {
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
			PullSpec: m.GetImage(imageID),
		})
	}
	return imageConfigs
}
