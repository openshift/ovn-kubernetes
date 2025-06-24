package openshift

import (
	"fmt"
	"strings"

	"github.com/ovn-org/ovn-kubernetes/test/e2e/deploymentconfig/api"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func IsOpenShift(config *rest.Config) (bool, error) {
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return false, fmt.Errorf("failed to create kubernetes client: %v", err)
	}
	// Check for OpenShift-specific API groups
	groups, err := kubeClient.Discovery().ServerGroups()
	if err != nil {
		return false, fmt.Errorf("failed to get server groups: %v", err)
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
	return openshift{}
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
