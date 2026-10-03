// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package generic

import (
	"k8s.io/kubernetes/test/utils/image"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig/api"
)

// generic supplies KinD-like deployment metadata without requiring a kind-* kubectl
// context. It only prevents TestMain from panicking when the active kubeconfig
// is not KinD-shaped; downstream adapters must supply accurate deployment config
// for their platform.
type generic struct{}

func New() api.DeploymentConfig {
	return generic{}
}

func (g generic) OVNKubernetesNamespace() string {
	return "ovn-kubernetes"
}

func (g generic) FRRK8sNamespace() string {
	return "frr-k8s-system"
}

func (g generic) ExternalBridgeName() string {
	return "breth0"
}

func (g generic) PrimaryInterfaceName() string {
	return "eth0"
}

func (g generic) GetAgnHostContainerImage() string {
	return image.GetE2EImage(image.Agnhost)
}

func (g generic) IsConfigurationEnabled(config api.Config) bool {
	switch config {
	case api.L3UDNMultiSubnetConfig:
		return false
	default:
		return false
	}
}
