package deploymentconfig

import (
	"fmt"
	"os"
	"strings"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig/api"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	e2ekubectl "k8s.io/kubernetes/test/e2e/framework/kubectl"
	imageutils "k8s.io/kubernetes/test/utils/image"
)

// FedoraKubevirtContainerDiskImage matches Origin's approved live-migration test image.
const FedoraKubevirtContainerDiskImage = "quay.io/kubevirt/fedora-with-test-tooling-container-disk:v1.8.2"

var (
	deploymentConfig api.DeploymentConfig
	imageIDMapping   map[api.ImageID]imageutils.ImageID = map[api.ImageID]imageutils.ImageID{
		api.Agnhost:             imageutils.Agnhost,
		api.FedoraKubevirtContainerDisk: imageutils.None,
	}
	imageConfigMap map[api.ImageID]api.ImageConfig
)

func init() {
	deploymentConfig = &openshift{
		requiredImages: make(map[api.ImageID]struct{}),
	}
	deploymentconfig.Set(deploymentConfig)

	// Add images that are needed by the test suite.
	imageConfigMap = map[api.ImageID]api.ImageConfig{
		api.Agnhost: {
			ImageID:  api.Agnhost,
			PullSpec: imageutils.GetE2EImage(imageutils.Agnhost),
		},
		api.FedoraKubevirtContainerDisk: {
			ImageID:  api.FedoraKubevirtContainerDisk,
			PullSpec: FedoraKubevirtContainerDiskImage,
		},
	}
	deploymentConfig.AddRequiredImage(api.Agnhost, api.FedoraKubevirtContainerDisk)
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
	if imageID == api.FedoraKubevirtContainerDisk && os.Getenv("KUBE_TEST_REPO") != "" {
		pullSpec, err := imageutils.ReplaceRegistryInImageURL(imageConfigMap[imageID].PullSpec)
		if err != nil {
			panic(err)
		}
		return api.ImageConfig{ImageID: imageID, PullSpec: pullSpec}
	}
	if imageID == api.Netshoot {
		pullSpec := os.Getenv("NETSHOOT_IMAGE")
		if pullSpec == "" {
			pullSpec = strings.TrimSpace(e2ekubectl.RunKubectlOrDie("openshift", "get", "imagestream", "network-tools",
				"-o=jsonpath={.status.tags[?(@.tag==\"latest\")].items[0].dockerImageReference}"))
			if pullSpec == "" {
				panic("openshift/network-tools:latest has no imported Docker image reference")
			}
		}
		return api.ImageConfig{ImageID: imageID, PullSpec: pullSpec}
	}
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
		if imageID == api.Netshoot {
			// network-tools is supplied by the payload, not the test-image mirror.
			continue
		}
		newID, ok := imageIDMapping[imageID]
		if !ok {
			newID = imageutils.None
		}
		imageConfigs = append(imageConfigs, api.ImageConfig{
			ImageID:  api.ImageID(newID),
			PullSpec: imageConfigMap[imageID].PullSpec,
		})
	}
	return imageConfigs
}
