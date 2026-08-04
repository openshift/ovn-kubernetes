package deploymentconfig

import (
	"fmt"
	"strings"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig/api"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	imageutils "k8s.io/kubernetes/test/utils/image"
)

var deploymentConfig api.DeploymentConfig

func init() {
	deploymentConfig = openshift{}
	deploymentconfig.Set(deploymentConfig)
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

type openshift struct{}

func New() api.DeploymentConfig {
	return deploymentConfig
}

func (m openshift) OVNKubernetesNamespace() string {
	return "openshift-ovn-kubernetes"
}

func (m openshift) FRRK8sNamespace() string {
	return "openshift-frr-k8s"
}

func (m openshift) ExternalBridgeName() string {
	return "br-ex"
}

func (m openshift) PrimaryInterfaceName() string {
	// support only for baremetald which expects the following interface name
	// TODO; dynamically look up primary interface name instead of hardcoding it to baremetald env
	return "enp0s3"
}

func (m openshift) GetAgnHostContainerImage() string {
	// Resolve agnhost the same way the k8s e2e framework does
	// (e2epod.NewAgnhostPod et al). imageutils honors the repository
	// mapping (KUBE_TEST_REPO_LIST) that openshift-tests sets up, so pods
	// use the mirrored image and pass origin's known-image-checker
	// monitor. A hardcoded registry.k8s.io reference gets flagged as an
	// unknown image and fails the job.
	return imageutils.GetE2EImage(imageutils.Agnhost)
}

func (m openshift) GetExternalAgnHostContainerImage() string {
	// External containers run under podman on the bare-metal hypervisor and
	// cannot authenticate to the cluster's mirrored image registry.
	return "registry.k8s.io/e2e-test-images/agnhost:2.40"
}

func (m openshift) IsConfigurationEnabled(config api.Config) bool {
	return false
}
