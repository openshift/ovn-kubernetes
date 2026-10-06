package deploymentconfig

import (
	"fmt"
	"strings"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig/api"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
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
	// use downloadable image for external container.
	// ref: https://github.com/openshift/release/blob/db6697de61f4ae7e05c5a2db782a87c459e849bf/ci-operator/step-registry/baremetalds/e2e/ovn/bgp/pre/baremetalds-e2e-ovn-bgp-pre-commands.sh#L197
	return "registry.k8s.io/e2e-test-images/agnhost:2.40"
}

func (m openshift) IsConfigurationEnabled(config api.Config) bool {
	return false
}

func (m openshift) NBDBContainerName() string {
	return "nbdb"
}

// ProviderSubnetCIDR returns the effective routable subnet CIDR for a node.
// On cloud platforms (AWS, Azure, GCP), the Cloud Network Config Controller
// (CNCC) sets the cloud egress IP annotation with the actual routable subnet,
// which may differ from node-primary-ifaddr (e.g., GCP uses /32 for the
// primary interface). On baremetal, node-primary-ifaddr is used directly.
func (m openshift) ProviderSubnetCIDR(node *corev1.Node, isIPv6 bool) (string, error) {
	if node == nil {
		return "", fmt.Errorf("node must not be nil")
	}
	// On cloud platforms, CNCC sets the cloud egress IP annotation with the
	// actual routable subnet. Use it when present, fall back to
	// node-primary-ifaddr for baremetal.
	parsed, err := util.ParseCloudEgressIPConfig(node)
	if err != nil {
		parsed, err = util.ParseNodePrimaryIfAddr(node)
	}
	if err != nil {
		return "", fmt.Errorf("failed to get provider subnet CIDR for node %s: %v", node.Name, err)
	}
	if isIPv6 {
		if parsed.V6.Net == nil {
			return "", fmt.Errorf("node %s has no IPv6 primary interface address", node.Name)
		}
		return parsed.V6.Net.String(), nil
	}
	if parsed.V4.Net == nil {
		return "", fmt.Errorf("node %s has no IPv4 primary interface address", node.Name)
	}
	return parsed.V4.Net.String(), nil
}
