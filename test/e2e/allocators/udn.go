// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package allocators

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/kubernetes/test/e2e/framework"
)

var (
	udnOnce      sync.Once
	udnV4, udnV6 subnetSpec
)

func initSubnetSpecs() {
	udnOnce.Do(func() {
		v4Exclusions, v6Exclusions := infrastructureNetworkExclusions()
		udnV4 = newSubnetSpec(udnSubnets, v4Exclusions)
		udnV6 = newSubnetSpec(udnSubnets6, v6Exclusions)
	})
}

func infrastructureNetworkExclusions() (ipv4, ipv6 []string) {
	v4, v6, err := getMachineNetworkSubnets()
	if err != nil {
		framework.Logf("Warning: failed to get machine network subnets for exclusion: %v", err)
	}
	// infraprovider.Get() panics when the provider is not set, which happens
	// during test listing where no cluster is available.
	if infraprovider.IsSet() {
		infraV4, infraV6 := infraprovider.Get().InfrastructureNetworkExclusions()
		v4 = v4.Union(infraV4)
		v6 = v6.Union(infraV6)
	}
	return v4.UnsortedList(), v6.UnsortedList()
}

// GetFirstUDNSubnets always allocates the first UDN IPv4 and IPv6 subnet
// within the dedicated UDN subnet broader range. Used when overlaps across UDNs
// are not a concern but still prevents overlaps with other subnets.
func GetFirstUDNSubnets() (ipv4, ipv6 string) {
	subnets4, subnets6 := GetNthFirstUDNSubnets(1)
	return subnets4[0], subnets6[0]
}

// GetNthFirstUDNSubnets returns the first n UDN IPv4 and IPv6 subnets within
// the dedicated UDN subnet broader range. Used when overlaps across UDNs are
// not a concern but still prevents overlaps with other subnets.
func GetNthFirstUDNSubnets(n int) (ipv4, ipv6 []string) {
	if n < 1 {
		panic("GetNthFirstUDNSubnets: n must be >= 1")
	}
	initSubnetSpecs()
	if n > udnV4.usable() || n > udnV6.usable() {
		panic("GetNthFirstUDNSubnets: not enough free subnets available")
	}

	ipv4 = make([]string, 0, n)
	ipv6 = make([]string, 0, n)
	for i := 1; i < n+1; i++ {
		udnV4Idx := udnV4.nthFree(i)
		udnV6Idx := udnV6.nthFree(i)
		ipv4 = append(ipv4, udnV4.cidr(udnV4Idx))
		ipv6 = append(ipv6, udnV6.cidr(udnV6Idx))
	}
	return ipv4, ipv6
}

// getMachineNetworkSubnets retrieves the machine network subnets from node
// annotations via the deployment config's ProviderSubnetCIDR. It returns the
// unique IPv4 and IPv6 CIDR networks found across all nodes. When KUBECONFIG
// or deployment config is not set, the call is a no-op and returns empty sets.
func getMachineNetworkSubnets() (sets.Set[string], sets.Set[string], error) {
	ipv4 := sets.New[string]()
	ipv6 := sets.New[string]()
	kubeConfig := os.Getenv("KUBECONFIG")
	if kubeConfig == "" || !deploymentconfig.IsSet() {
		return ipv4, ipv6, nil
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfig)
	if err != nil {
		return ipv4, ipv6, err
	}
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return ipv4, ipv6, fmt.Errorf("failed to create kubernetes client: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	nodes, err := kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return ipv4, ipv6, fmt.Errorf("failed to list nodes: %w", err)
	}
	for i := range nodes.Items {
		node := &nodes.Items[i]
		v4CIDR, v6CIDR, err := machineNetworkCIDRsFromNode(node)
		if err != nil {
			return ipv4, ipv6, err
		}
		if v4CIDR != "" {
			ipv4.Insert(v4CIDR)
		}
		if v6CIDR != "" {
			ipv6.Insert(v6CIDR)
		}
	}
	return ipv4, ipv6, nil
}

// machineNetworkCIDRsFromNode extracts machine network CIDRs from a node
// using the deployment config's ProviderSubnetCIDR.
func machineNetworkCIDRsFromNode(node *corev1.Node) (v4, v6 string, err error) {
	cfg := deploymentconfig.Get()
	v4, err = cfg.ProviderSubnetCIDR(node, false)
	if err != nil {
		v4 = "" // IPv4 may not be configured
	}
	v6, err = cfg.ProviderSubnetCIDR(node, true)
	if err != nil {
		v6 = "" // IPv6 may not be configured
	}
	if v4 == "" && v6 == "" {
		return "", "", fmt.Errorf("no provider subnet CIDR found for node %q", node.Name)
	}
	return v4, v6, nil
}
