// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package kind

import (
	"context"
	"fmt"
	"time"

	"k8s.io/kubernetes/test/utils/image"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type kind struct {
	kubeConfig *rest.Config
}

func New(config *rest.Config) api.DeploymentConfig {
	if !infraprovider.IsKind() {
		panic("Cluster provider must be KinD type")
	}
	return &kind{
		kubeConfig: config,
	}
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

func (k *kind) GetNodeMachineNetworks() (map[string][]string, error) {
	if k.kubeConfig == nil {
		return make(map[string][]string), nil
	}
	kubeClient, err := kubernetes.NewForConfig(k.kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	nodes, err := kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}
	result := make(map[string][]string, len(nodes.Items))
	for i := range nodes.Items {
		node := &nodes.Items[i]
		parsed, err := util.ParseNodePrimaryIfAddr(node)
		if err != nil {
			return nil, fmt.Errorf("failed to parse node %s primary address: %w", node.Name, err)
		}
		var subnets []string
		if parsed.V4.Net != nil {
			subnets = append(subnets, parsed.V4.Net.String())
		}
		if parsed.V6.Net != nil {
			subnets = append(subnets, parsed.V6.Net.String())
		}
		result[node.Name] = subnets
	}
	return result, nil
}
