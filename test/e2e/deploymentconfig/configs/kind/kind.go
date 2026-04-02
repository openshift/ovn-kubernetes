package kind

import (
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/images"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider"
)

type kind struct{}

func New() api.DeploymentConfig {
	if !infraprovider.IsKind() {
		panic("Cluster provider must be KinD type")
	}
	return kind{}
}

func (k kind) OVNKubernetesNamespace() string {
	return "ovn-kubernetes"
}

func (k kind) FRRK8sNamespace() string {
	return "frr-k8s-system"
}

func (k kind) ExternalBridgeName() string {
	return "breth0"
}

func (k kind) PrimaryInterfaceName() string {
	return "eth0"
}

func (k kind) GetAgnHostContainerImage() string {
	return images.AgnHost()
}
