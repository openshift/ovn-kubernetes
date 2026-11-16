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
// a dedicated unmanaged podman network on the machine network bridge whose
// IPAM pool is a few preflight-checked addresses per IP family.
//
// The first user is the upstream "MAC binding mirroring with ARP/NDP flood
// disabled" group (two containers, A and B). The egress firewall specs with
// external containers, disabled in test/annotate/rules.go for the same reason,
// are the next candidate.
package infraprovider

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/allocators"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/container/network"
	"k8s.io/kubernetes/test/e2e/framework"
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

// isolatedContainers creates the isolated external containers. It keeps no state
// besides its configuration.
type isolatedContainers struct {
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
	nets, err := f.machineNetworks()
	if err != nil {
		return ec, err
	}
	// 1. The dedicated network.
	if err := f.ensureNetwork(nets); err != nil {
		return ec, err
	}
	// 2. Engine path, with addresses from the e2e primary IP allocator (its
	// reserved per-node range of the machine network, checked against the
	// node host addresses).
	isolatedEC := ec
	isolatedEC.Network = isolatedNetwork
	isolatedEC.IPv4, isolatedEC.IPv6 = "", ""
	node := f.allocationNode()
	if node == "" {
		return ec, fmt.Errorf("isolated container: no node to allocate the machine network address from")
	}
	// One address per family the machine network has: a single-stack cluster
	// gets a single-stack container.
	for _, subnet := range nets {
		if subnet.IP.To4() != nil {
			ip, err := allocators.NewPrimaryIPv4(node)
			if err != nil {
				return ec, fmt.Errorf("isolated container: %w", err)
			}
			isolatedEC.IPv4 = ip.String()
		} else {
			ip, err := allocators.NewPrimaryIPv6(node)
			if err != nil {
				return ec, fmt.Errorf("isolated container: %w", err)
			}
			isolatedEC.IPv6 = ip.String()
		}
	}
	return base.CreateExternalContainer(isolatedEC)
}

// machineNetworks returns every machine network subnet, one per IP family.
func (f *isolatedContainers) machineNetworks() ([]*net.IPNet, error) {
	v4, v6, err := f.machineNetwork.IPv4IPv6Subnets()
	if err != nil {
		return nil, fmt.Errorf("isolated container: failed to read machine networks: %w", err)
	}
	var nets []*net.IPNet
	for _, cidr := range []string{v4, v6} {
		if cidr == "" {
			continue
		}
		_, subnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("isolated container: invalid machine network %q: %w", cidr, err)
		}
		nets = append(nets, subnet)
	}
	if len(nets) == 0 {
		return nil, fmt.Errorf("isolated container: machine network has no IPv4 or IPv6 CIDR")
	}
	return nets, nil
}

// allocationNode returns a node name to allocate the machine network
// addresses from: every node is on the same machine network, so any works.
func (f *isolatedContainers) allocationNode() string {
	nets, _ := deploymentconfig.Get().GetNodeMachineNetworks()
	for name := range nets {
		return name
	}
	return ""
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
		return fmt.Errorf("isolated container: failed to list podman networks: %w (%s)", err, out)
	}
	var existing []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(out), &existing); err != nil {
		return fmt.Errorf("isolated container: failed to parse podman networks: %w", err)
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
		return fmt.Errorf("isolated container: could not create %s as an unmanaged bridge network (no managed fallback): %w (podman output: %s)",
			isolatedNetworkName, err, strings.TrimSpace(out))
	}
	framework.Logf("isolated container: created podman network %s", isolatedNetworkName)
	return nil
}
