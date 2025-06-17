package openshift

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/deploymentconfig/api"
)

func IsBaremetalds() bool {
	return true
}

type baremetalds struct{}

func NewBaremetalds() api.DeploymentConfig {
	return baremetalds{}
}

func (m baremetalds) OVNKubernetesNamespace() string {
	return "openshift-ovn-kubernetes"
}

func (m baremetalds) ExternalBridgeName() string {
	return "br-ex"
}

func (m baremetalds) PrimaryInterfaceName() string {
	return "enp0s3"
}
