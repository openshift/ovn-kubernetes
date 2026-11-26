// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0
//
// baremetal_isolated.go provides external containers with their own network
// identity on the baremetal machine network.
//
// The default baremetal path gives primary-network containers the hypervisor's
// network namespace, which is enough for specs that only need an external host.
// Some specs need external hosts with their own IP and MAC on the cluster's L2
// network, and change the container's MAC or link: with host networking they
// would all share the hypervisor's IP/MAC and the link changes would hit the
// hypervisor. Containers that opt in by name (isolatedContainerNames) are
// therefore created through the normal container engine on ovnk-e2e-isolated,
// a dedicated unmanaged podman network on the machine network bridge, with
// static addresses from the e2e primary IP allocator.
//
// The first user is the upstream "MAC binding mirroring with ARP/NDP flood
// disabled" group (two containers, A and B). The egress firewall specs with
// external containers, disabled in test/annotate/rules.go for the same reason,
// are the next candidate.
//
// TODO(CORENET-7750): when the existing primary-network containers move off
// host networking onto a container network backend, fold this file into
// baremetal.go and drop the name-based isolation; specs that need their own
// L2 identity on the machine network stay the exception.
package infraprovider

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/allocators"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/container/network"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	utilsnet "k8s.io/utils/net"
)

const (
	// nofloodContainerPrefix is the prefix of the upstream no-flood container
	// name format "noflood-ext-%d-%s". Its matcher and the rename contract test
	// both derive from it.
	nofloodContainerPrefix = "noflood-ext-"

	// isolatedNetworkName is the dedicated podman network. It is
	// deliberately not ostestbm_net, which belongs to the BGP pre-step and is
	// the base provider's host-networked routing key.
	isolatedNetworkName = "ovnk-e2e-isolated"
)

// isolatedNetwork is ovnk-e2e-isolated as the engine addresses it.
var isolatedNetwork api.Network = &network.ContainerEngineNetwork{NetName: isolatedNetworkName}

// isolatedContainerNames are the primary-network container names that get
// their own network identity. Each entry belongs to an upstream spec group
// whose container names are pinned by a contract test.
var isolatedContainerNames = []*regexp.Regexp{
	// "MAC binding mirroring with ARP/NDP flood disabled": containers A and B,
	// created as noflood-ext-<index>-<random>.
	regexp.MustCompile("^" + regexp.QuoteMeta(nofloodContainerPrefix) + "[0-9]+-"),
}

// needsIsolation reports whether a primary-network container with this name
// gets its own network identity.
func needsIsolation(name string) bool {
	return slices.ContainsFunc(isolatedContainerNames, func(re *regexp.Regexp) bool { return re.MatchString(name) })
}

// isolatedContainers creates the isolated external containers.
type isolatedContainers struct {
	// mu serializes create within this process. It does not order
	// separate test processes: the specs using isolated containers are
	// Serial, so no other spec runs alongside them.
	mu              sync.Mutex
	runner          api.Runner
	machineNetwork  api.Network
	hostNetworkInfo *api.NetworkInterface
}

func newIsolatedContainers(r api.Runner, machineNetwork api.Network, hostNetworkInfo *api.NetworkInterface) *isolatedContainers {
	return &isolatedContainers{
		runner:          r,
		machineNetwork:  machineNetwork,
		hostNetworkInfo: hostNetworkInfo,
	}
}

func (f *isolatedContainers) podman(args ...string) (string, error) {
	return f.runner.Run(containerRuntime, args...)
}

// create runs the creation sequence for one isolated container: the dedicated
// network, then creation through the base provider's engine path with
// addresses from the e2e primary IP allocator.
func (f *isolatedContainers) create(ec api.ExternalContainer, base *baseContextProvider) (api.ExternalContainer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	wrap := func(err error) error { return fmt.Errorf("isolated container %s: %w", ec.Name, err) }
	nets, err := f.machineNetworks()
	if err != nil {
		return ec, wrap(err)
	}
	// 1. The dedicated network.
	if err := f.ensureNetwork(nets); err != nil {
		return ec, wrap(err)
	}
	// 2. Engine path, with addresses from the e2e primary IP allocator (its
	// reserved per-node range of the machine network, checked against the
	// node host addresses).
	isolatedEC := ec
	isolatedEC.Network = isolatedNetwork
	isolatedEC.IPv4, isolatedEC.IPv6 = "", ""
	node, err := f.allocationNode()
	if err != nil {
		return ec, wrap(err)
	}
	// One address per family the machine network has: a single-stack cluster
	// gets a single-stack container.
	for _, subnet := range nets {
		if utilsnet.IsIPv4(subnet.IP) {
			ip, err := allocators.NewPrimaryIPv4(node)
			if err != nil {
				return ec, wrap(fmt.Errorf("failed to allocate an IPv4 address from node %s: %w", node, err))
			}
			isolatedEC.IPv4 = ip.String()
		}
		if utilsnet.IsIPv6(subnet.IP) {
			ip, err := allocators.NewPrimaryIPv6(node)
			if err != nil {
				return ec, wrap(fmt.Errorf("failed to allocate an IPv6 address from node %s: %w", node, err))
			}
			isolatedEC.IPv6 = ip.String()
		}
	}
	created, err := base.CreateExternalContainer(isolatedEC)
	if err != nil {
		return created, wrap(err)
	}
	return created, nil
}

// machineNetworks returns every machine network subnet, one per IP family.
func (f *isolatedContainers) machineNetworks() ([]*net.IPNet, error) {
	v4, v6, err := f.machineNetwork.IPv4IPv6Subnets()
	if err != nil {
		return nil, fmt.Errorf("failed to read machine networks: %w", err)
	}
	var nets []*net.IPNet
	for _, cidr := range []string{v4, v6} {
		if cidr == "" {
			continue
		}
		_, subnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid machine network %q: %w", cidr, err)
		}
		nets = append(nets, subnet)
	}
	if len(nets) == 0 {
		return nil, fmt.Errorf("machine network has no IPv4 or IPv6 CIDR")
	}
	return nets, nil
}

// allocationNode returns a node name to allocate the machine network
// addresses from: every node is on the same machine network, so any works.
// It reads the node from the kube API to keep this package independent of
// the deploymentconfig layer.
func (f *isolatedContainers) allocationNode() (string, error) {
	cs, err := framework.LoadClientset()
	if err != nil {
		return "", fmt.Errorf("failed to create kube client: %w", err)
	}
	nodes, err := cs.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{Limit: 1})
	if err != nil {
		return "", fmt.Errorf("failed to list nodes: %w", err)
	}
	if len(nodes.Items) == 0 {
		return "", fmt.Errorf("cluster has no nodes")
	}
	return nodes.Items[0].Name, nil
}

// ensureNetwork creates ovnk-e2e-isolated over the machine network subnets if
// it is missing, and otherwise reuses it: only this code creates a network with
// that name, and each job gets its own hypervisor. The network attaches to the
// hypervisor interface that holds the machine network addresses
// (hostNetworkInfo, ostestbm on dev-scripts): if that isn't a bridge, attaching
// a container fails. It never modifies or removes an existing network.
func (f *isolatedContainers) ensureNetwork(nets []*net.IPNet) error {
	out, err := f.podman("network", "ls", "--format", "json")
	if err != nil {
		return fmt.Errorf("failed to list podman networks: %w (podman output: %s)", err, strings.TrimSpace(out))
	}
	var existing []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(out), &existing); err != nil {
		return fmt.Errorf("failed to parse podman networks: %w", err)
	}
	for _, n := range existing {
		if n.Name == isolatedNetworkName {
			return nil
		}
	}
	args := []string{"network", "create", "--driver", "bridge",
		"--opt", "com.docker.network.bridge.name=" + f.hostNetworkInfo.InfName,
		"--opt", "mode=unmanaged", "--opt", "no_default_route=true", "--disable-dns"}
	for _, subnet := range nets {
		if subnet.IP.To4() == nil {
			args = append(args, "--ipv6")
		}
		args = append(args, "--subnet", subnet.String())
	}
	args = append(args, isolatedNetworkName)
	if out, err := f.podman(args...); err != nil {
		return fmt.Errorf("could not create podman network %s in unmanaged mode on bridge %s with subnets %v: %w (podman output: %s)",
			isolatedNetworkName, f.hostNetworkInfo.InfName, nets, err, strings.TrimSpace(out))
	}
	framework.Logf("isolated container: created podman network %s", isolatedNetworkName)
	return nil
}
