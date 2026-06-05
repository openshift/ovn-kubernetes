// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package kind

import (
	"fmt"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/test/utils/image"
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
	return image.GetE2EImage(image.Agnhost)
}

func (k kind) IsConfigurationEnabled(config api.Config) bool {
	switch config {
	case api.L3UDNMultiSubnetConfig:
		// Currently enabled by default for Kind cluster. Could use
		// an ENV variable check instead if we need variability later.
		return true
	default:
		return false
	}
}

func (k kind) NBDBContainerName() string {
	return "nb-ovsdb"
}

func (k kind) ProviderSubnetCIDR(node *corev1.Node, isIPv6 bool) (string, error) {
	if node == nil {
		return "", fmt.Errorf("node must not be nil")
	}
	parsed, err := util.ParseNodePrimaryIfAddr(node)
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
