// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package infraprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	coreclient "k8s.io/client-go/kubernetes/typed/core/v1"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/container"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/container/network"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/runner"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/testcontext"
)

const (
	hypervisorNodeUser = "root"
	hypervisorSshport  = "22"
	// use network name created for attaching frr container with
	// cluster primary network as per changes in the link:
	// https://github.com/openshift/release/blob/db6697de61f4ae7e05c5a2db782a87c459e849bf/ci-operator/step-registry/baremetalds/e2e/ovn/bgp/pre/baremetalds-e2e-ovn-bgp-pre-commands.sh#L123-L124
	bmPrimaryNetworkName       = "ostestbm_net"
	frrContainerPrimaryNetIPv4 = "192.168.111.3"
	frrContainerPrimaryNetIPv6 = "fd2e:6f44:5dd8:c956::3"
	externalFRRContainerName   = "frr"

	// bmExGwNetworkName is a dedicated macvlan on the machine-network parent
	// for External Gateway e2es. It must differ from bmPrimaryNetworkName so
	// CreateExternalContainer uses the engine path (isolated netns / eth0)
	// instead of host networking. Name matches Kind's OVN_TEST_EX_GW_NETWORK.
	bmExGwNetworkName = "xgw"
	// bmExGwHostLinkName is a host-side macvlan sibling on the same parent.
	// Containers cannot reach the parent's host IP (macvlan filter); they use
	// this sibling as their default gateway so the hypervisor can NAT apk /
	// internet traffic while keeping L2 adjacency to cluster nodes on xgw.
	// The sibling carries a /32 (IPv4) or /128 (IPv6) address; connected
	// routes for the container IPAM pools are added explicitly on this link.
	bmExGwHostLinkName = "xgw-host"
	// exGwPoolBits sizes the container IPAM slice (2^exGwPoolBits addresses).
	exGwPoolBits = 4

	bmSecondaryNetworkName = "secondarynetwork"
	// Secondary subnets must match the values in test/e2e/egressip.go
	// (secondaryIPV4Subnet / secondaryIPV6Subnet) because EgressIP tests
	// hardcode addresses from these ranges. The CI step that provisions
	// the baremetal secondary network must use the same subnets.
	bmSecondaryIPv4Subnet = "10.10.10.0/24"
	bmSecondaryIPv6Subnet = "2001:db8:abcd:1234::/64"
)

type baremetalInfra struct {
	base                 *baseInfra
	secondaryNetwork     api.Network
	secondaryHostNetInfo *api.NetworkInterface
	// isolated creates primary-network containers with their own network
	// identity, see baremetal_isolated.go.
	isolated        *isolatedContainers
	exGwMu          sync.Mutex
	exGwReady       bool
	exGwFirewallErr error
	nodes           coreclient.NodeInterface
	gatewayVIPs     []string
}

// initializeBaremetalInfra sets up the hypervisor-backed provider.
func initializeBaremetalInfra(infra *configv1.Infrastructure) (*baremetalInfra, error) {
	// Initialize command runner for executing commands on hypervisor
	// (optional, may not be available)
	sshRunner, err := hypervisorSshCmdRunner()
	if err != nil {
		return nil, err
	}
	if sshRunner == nil {
		return nil, nil
	}

	// Verify SSH connectivity works
	if _, err := sshRunner.Run("echo", "connection test"); err != nil {
		return nil, fmt.Errorf("failed to check frr container status, connectivity check failed with hypervisor: %w", err)
	}

	h := &baseInfra{
		runner:             sshRunner,
		externalContainers: make(map[string]api.ExternalContainer),
		engine:             container.NewEngine("podman", sshRunner),
		primaryNetworkName: bmPrimaryNetworkName,
	}

	if infra.Spec.PlatformSpec.BareMetal == nil {
		return nil, fmt.Errorf("infrastructure platform type is BareMetal but BareMetal spec is nil")
	}

	// just mimic machine network with ContainerEngineNetwork to make it
	// compatibile with api.Network API.
	machineNetwork := &network.ContainerEngineNetwork{NetName: bmPrimaryNetworkName}
	var cidrs []network.ContainerEngineNetworkConfig
	for _, cidr := range infra.Spec.PlatformSpec.BareMetal.MachineNetworks {
		cidrs = append(cidrs, network.ContainerEngineNetworkConfig{Subnet: string(cidr)})
	}
	machineNetwork.Configs = cidrs
	h.machineNetwork = machineNetwork

	v4, v6, err := h.machineNetwork.IPv4IPv6Subnets()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve primary network subnets: %w", err)
	}
	// Retrieve primary network interface from hypervisor instance
	h.hostNetworkInfo, err = findHypervisorNodeInterface(sshRunner, v4, v6)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve hypervisor node interface for machine network: %w", err)
	}
	bm := &baremetalInfra{base: h}
	// Open the external container port range (12000-65535/tcp) in the
	// hypervisor firewall once, instead of per-port during each test.
	if h.hostNetworkInfo != nil {
		// Create the inactive policy before the existing initialization reload.
		// Its failure belongs to gateway specs, not unrelated infrastructure users.
		bm.exGwFirewallErr = prepareExGwFirewallPolicy(sshRunner)
		if err := configureFirewallForExternalContainerPorts(sshRunner, h.hostNetworkInfo.InfName); err != nil {
			return nil, fmt.Errorf("failed to configure firewall for external container ports: %w", err)
		}
	}

	bm.isolated = newIsolatedContainers(sshRunner, h.machineNetwork, h.hostNetworkInfo)

	// Discover secondary network interface on hypervisor (optional).
	secondaryNetInfo, err := findHypervisorNodeInterface(sshRunner, bmSecondaryIPv4Subnet, bmSecondaryIPv6Subnet)
	if err == nil && secondaryNetInfo != nil {
		secondaryNet := &network.ContainerEngineNetwork{
			NetName: bmSecondaryNetworkName,
			Configs: []network.ContainerEngineNetworkConfig{
				{Subnet: bmSecondaryIPv4Subnet},
				{Subnet: bmSecondaryIPv6Subnet},
			}}
		bm.secondaryNetwork = secondaryNet
		bm.secondaryHostNetInfo = secondaryNetInfo
	}

	return bm, nil
}

func (ci *baremetalInfra) InfrastructureNetworkExclusions() (ipv4, ipv6 sets.Set[string]) {
	// The hypervisor is on the same machine network as the cluster nodes.
	return nil, nil
}

// enableSecondaryForwarding enables IPv4/IPv6 forwarding on the secondary
// network interface of each cluster node. On baremetal, these interfaces are
// pre-configured but may have forwarding disabled by default. The interface
// name is discovered per-node since it may differ across nodes.
func (ci *baremetalInfra) enableSecondaryForwarding(nodeNames []string, execNodeCmd func(nodeName string, cmd []string) (string, error)) error {
	if ci.secondaryNetwork == nil {
		return nil
	}
	for _, nodeName := range nodeNames {
		output, err := execNodeCmd(nodeName, []string{"ip", "-j", "addr"})
		if err != nil {
			return fmt.Errorf("failed to get addresses from node %s: %w", nodeName, err)
		}
		ifName, err := findInterfaceBySubnet(output, bmSecondaryIPv4Subnet, bmSecondaryIPv6Subnet)
		if err != nil {
			return fmt.Errorf("failed to parse addresses from node %s: %w", nodeName, err)
		}
		if ifName == "" {
			return fmt.Errorf("no secondary network interface found on node %s for subnets %s, %s", nodeName, bmSecondaryIPv4Subnet, bmSecondaryIPv6Subnet)
		}
		// The sysctl changes are runtime-only (lost on reboot) and are not reverted
		// at teardown, which is acceptable for CI nodes.
		for _, sysctl := range []string{
			fmt.Sprintf("net.ipv4.conf.%s.forwarding=1", ifName),
			fmt.Sprintf("net.ipv6.conf.%s.forwarding=1", ifName),
		} {
			if _, err := execNodeCmd(nodeName, []string{"sysctl", "-w", sysctl}); err != nil {
				return fmt.Errorf("failed to set %s on node %s: %w", sysctl, nodeName, err)
			}
		}
	}
	return nil
}

// findInterfaceBySubnet parses ip -j addr output and returns the interface
// name that has an address within one of the given subnets.
func findInterfaceBySubnet(ipAddrJSON, v4Subnet, v6Subnet string) (string, error) {
	var links []linkInfo
	if err := json.Unmarshal([]byte(ipAddrJSON), &links); err != nil {
		return "", fmt.Errorf("failed to parse ip addr JSON: %w", err)
	}
	for _, link := range links {
		for _, addr := range link.AddrInfo {
			if v4Subnet != "" {
				if ok, _ := ipInCIDR(addr.Local, v4Subnet); ok {
					return link.IfName, nil
				}
			}
			if v6Subnet != "" {
				if ok, _ := ipInCIDR(addr.Local, v6Subnet); ok {
					return link.IfName, nil
				}
			}
		}
	}
	return "", nil
}

func (ci *baremetalInfra) PrimaryNetwork() (api.Network, error) {
	return ci.base.PrimaryNetwork()
}

func (ci *baremetalInfra) GetNetwork(name string) (api.Network, error) {
	if name == "host" {
		// Host networking is a runtime mode, not a named Podman network.
		return buildMachineNetwork(name, ci.base.hostNetworkInfo)
	}
	if name == bmExGwNetworkName {
		ci.exGwMu.Lock()
		defer ci.exGwMu.Unlock()
		if !ci.exGwReady {
			if ci.exGwFirewallErr != nil {
				// The startup reload may have activated an existing policy even
				// when preparation failed. Check its current state before failing.
				policies, err := ci.base.runner.Run("firewall-cmd", "--get-policies")
				if err != nil {
					return nil, errors.Join(ci.exGwFirewallErr, fmt.Errorf("check active gateway policy: %w", err))
				}
				if !sets.New(strings.Fields(policies)...).Has(exGwFirewallPolicy) {
					return nil, fmt.Errorf("gateway firewall policy %s is inactive after startup preparation failed: %w", exGwFirewallPolicy, ci.exGwFirewallErr)
				}
				ci.exGwFirewallErr = nil
			}
			v4, v6, err := ci.base.machineNetwork.IPv4IPv6Subnets()
			if err != nil {
				return nil, err
			}
			if err := ci.validateExGwClusterAddresses(v4, v6); err != nil {
				return nil, err
			}
			if err := ensureExternalGatewayNetwork(ci.base.runner, ci.base.hostNetworkInfo, v4, v6); err != nil {
				return nil, fmt.Errorf("failed to prepare external gateway network %s: %w", name, err)
			}
			ci.exGwReady = true
		} else {
			// A host firewall reload discards runtime rules while the Podman
			// network remains. Restore forwarding without recreating xgw.
			v4, v6, err := ci.base.machineNetwork.IPv4IPv6Subnets()
			if err != nil {
				return nil, err
			}
			var pools [2]string
			for i, subnet := range []string{v4, v6} {
				if subnet == "" {
					continue
				}
				ipam, err := reservedExGwIPAM(subnet)
				if err != nil {
					return nil, err
				}
				pools[i] = ipam.IPRange
			}
			if err := ensureExGwInternetNAT(ci.base.runner, ci.base.hostNetworkInfo.InfName, pools[0], pools[1]); err != nil {
				return nil, fmt.Errorf("restore external gateway firewall rules: %w", err)
			}
		}
	}

	if name == bmSecondaryNetworkName && ci.secondaryNetwork != nil {
		return ci.secondaryNetwork, nil
	}
	network, err := ci.base.GetNetwork(name)
	if name == bmExGwNetworkName && errors.Is(err, api.NotFound) {
		ci.exGwReady = false
	}
	return network, err
}

// validateExGwClusterAddresses rejects assigned node and VIP addresses before
// the host sibling or Podman's pool can claim them.
func (ci *baremetalInfra) validateExGwClusterAddresses(subnets ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	nodes, err := ci.nodes.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list nodes before reserving gateway addresses: %w", err)
	}
	assigned := append([]string(nil), ci.gatewayVIPs...)
	for _, node := range nodes.Items {
		for _, address := range node.Status.Addresses {
			assigned = append(assigned, address.Address)
		}
		// The annotation includes additional primary addresses on dual-stack nodes.
		if annotation := node.Annotations["k8s.ovn.org/node-primary-ifaddr"]; annotation != "" {
			var addresses map[string]string
			if err := json.Unmarshal([]byte(annotation), &addresses); err != nil {
				return fmt.Errorf("parse primary addresses on node %s: %w", node.Name, err)
			}
			for _, cidr := range addresses {
				if cidr == "" {
					continue
				}
				ip, _, err := net.ParseCIDR(cidr)
				if err != nil {
					return fmt.Errorf("parse node %s primary address %q: %w", node.Name, cidr, err)
				}
				assigned = append(assigned, ip.String())
			}
		}
	}
	for _, subnet := range subnets {
		if subnet == "" {
			continue
		}
		ipam, err := reservedExGwIPAM(subnet)
		if err != nil {
			return err
		}
		_, pool, err := net.ParseCIDR(ipam.IPRange)
		if err != nil {
			return err
		}
		for _, address := range assigned {
			ip := net.ParseIP(address)
			if ip.Equal(net.ParseIP(ipam.Gateway)) || pool.Contains(ip) {
				return fmt.Errorf("node or VIP address %s conflicts with gateway %s or pool %s", address, ipam.Gateway, pool)
			}
		}
	}
	return nil
}

func (ci *baremetalInfra) ListNetworks() ([]string, error) {
	return ci.base.ListNetworks()
}

func (ci *baremetalInfra) ExecExternalContainerCommand(container api.ExternalContainer, cmd []string) (string, error) {
	return ci.base.ExecExternalContainerCommand(container, cmd)
}

func (ci *baremetalInfra) ExternalContainerPrimaryInterfaceName() string {
	return ci.base.ExternalContainerPrimaryInterfaceName()
}

func (ci *baremetalInfra) GetExternalContainerLogs(container api.ExternalContainer) (string, error) {
	return ci.base.GetExternalContainerLogs(container)
}

// GetExternalContainerContextProvider always returns the baremetal provider,
// with or without a secondary network, so that isolated containers
// are handled; every other call behaves like the base provider.
func (ci *baremetalInfra) GetExternalContainerContextProvider(context *testcontext.TestContext) api.ExternalContainerContextProvider {
	baseProvider := &baseContextProvider{
		parent: ci.base,
		engine: ci.base.engine.WithTestContext(context),
	}
	return &baremetalContextProvider{base: baseProvider, bm: ci}
}

// GetExternalContainerPort delegates to base and also configures the
// hypervisor firewall for the allocated port.
func (ci *baremetalInfra) GetExternalContainerPort() uint16 {
	return ci.base.GetExternalContainerPort()
}

// GetExternalContainerNetworkInterface handles isolated containers and the FRR
// container special cases, then delegates to base for everything else.
func (ci *baremetalInfra) GetExternalContainerNetworkInterface(ec api.ExternalContainer, network api.Network) (api.NetworkInterface, error) {
	if needsIsolation(ec.Name) {
		// Isolated containers are only on the dedicated network, whatever
		// network the spec asks about (usually PrimaryNetwork()).
		return ci.base.engine.GetExternalContainerNetworkInterface(ec, isolatedNetwork)
	}
	if ec.Name == externalFRRContainerName && network.Name() == bmPrimaryNetworkName {
		// frr container uses static ip configuration for ostestbm_net,
		// querying it with podman inspect returns empty values, so build
		// it explicitly.
		if ci.base.hostNetworkInfo == nil {
			return api.NetworkInterface{}, fmt.Errorf("can not find primary network gateway node for frr container")
		}
		return api.NetworkInterface{
				IPv4:        frrContainerPrimaryNetIPv4,
				IPv6:        frrContainerPrimaryNetIPv6,
				IPv4Gateway: ci.base.hostNetworkInfo.IPv4,
				IPv6Gateway: ci.base.hostNetworkInfo.IPv6,
				InfName:     "eth0",
				IPv4Prefix:  ci.base.hostNetworkInfo.IPv4Prefix,
				IPv6Prefix:  ci.base.hostNetworkInfo.IPv6Prefix},
			nil
	}
	// Cached secondary network container: return IPs from cache with
	// secondary network prefix info.
	if network.Name() == bmSecondaryNetworkName && ci.secondaryHostNetInfo != nil {
		ci.base.mu.Lock()
		cached, isCached := ci.base.externalContainers[ec.Name]
		ci.base.mu.Unlock()
		if isCached {
			return api.NetworkInterface{
				IPv4:       cached.IPv4,
				IPv6:       cached.IPv6,
				IPv4Prefix: ci.secondaryHostNetInfo.IPv4Prefix,
				IPv6Prefix: ci.secondaryHostNetInfo.IPv6Prefix,
				InfName:    ci.secondaryHostNetInfo.InfName,
			}, nil
		}
	}
	return ci.base.GetExternalContainerNetworkInterface(ec, network)
}

// hypervisorSshCmdRunner creates an SSH runner for the baremetal hypervisor.
// Returns (nil, nil) when hypervisor access is not configured, for example
// when SHARED_DIR is unset or the required files are absent. This is
// expected when ovn-kubernetes-tests-ext runs with the list option
// outside a CI environment.
func hypervisorSshCmdRunner() (api.Runner, error) {
	ip, err := readSharedDirFile("server-ip", "hypervisor ip")
	if err != nil {
		return nil, err
	}
	if ip == "" {
		return nil, nil
	}

	// Find SSH key for hypervisor access
	sshKeyPath, err := findClusterProfileFile("equinix-ssh-key", "packet-ssh-key")
	if err != nil {
		return nil, err
	}
	if sshKeyPath == "" {
		return nil, nil
	}

	sshRunner, err := runner.NewSSHRunner(ip, hypervisorNodeUser, hypervisorSshport, sshKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create ssh runner for hypervisor: %w", err)
	}

	return sshRunner, nil
}

// findHypervisorNodeInterface retrieves attached interface for the matching subnets from the hypervisor node.
func findHypervisorNodeInterface(runner api.Runner, v4Subnet, v6Subnet string) (*api.NetworkInterface, error) {
	ipAddrCmdArgs := []string{"-j", "addr"}
	result, err := runner.Run("ip", ipAddrCmdArgs...)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve network links: %w", err)
	}

	var links []linkInfo
	if err := json.Unmarshal([]byte(result), &links); err != nil {
		return nil, fmt.Errorf("failed to parse network links: %w", err)
	}

	for _, link := range links {
		if netInfo := tryMatchLink(link, v4Subnet, v6Subnet); netInfo != nil {
			return netInfo, nil
		}
	}
	return nil, fmt.Errorf("no network interface found matching subnets v4=%s v6=%s", v4Subnet, v6Subnet)
}

func tryMatchLink(link linkInfo, v4Subnet, v6Subnet string) *api.NetworkInterface {
	netInterface := &api.NetworkInterface{}

	for _, addr := range link.AddrInfo {
		// Check for IPv4 match
		if v4Subnet != "" {
			if ok, _ := ipInCIDR(addr.Local, v4Subnet); ok {
				netInterface.IPv4 = addr.Local
				netInterface.IPv4Prefix = v4Subnet
			}
		}

		// Check for IPv6 match
		if v6Subnet != "" {
			if ok, _ := ipInCIDR(addr.Local, v6Subnet); ok {
				netInterface.IPv6 = addr.Local
				netInterface.IPv6Prefix = v6Subnet
			}
		}
	}

	// Only consider this link a match if we found all requested IPs
	hasV4Match := v4Subnet == "" || netInterface.IPv4 != ""
	hasV6Match := v6Subnet == "" || netInterface.IPv6 != ""

	if hasV4Match && hasV6Match {
		netInterface.InfName = link.IfName
		netInterface.MAC = link.Mac
		return netInterface
	}

	// Not a complete match, return nil
	return nil
}

// ensureExternalGatewayNetwork creates a podman macvlan on the hypervisor
// machine-network interface for External Gateway e2es. Containers get isolated
// netns and eth0 on the same L2 as cluster nodes. A host macvlan sibling
// (xgw-host) is the containers' default gateway so the hypervisor can NAT
// internet access (apk) — macvlan cannot reach the parent's host IP. Podman
// --subnet stays the full machine-network CIDR; the host sibling uses /32
// and /128 plus explicit routes for the container IPAM pools. Must not use
// --internal bridge create (unreachable from nodes).
func ensureExternalGatewayNetwork(runner api.Runner, hostNet *api.NetworkInterface, v4Subnet, v6Subnet string) error {
	if hostNet == nil || hostNet.InfName == "" {
		return fmt.Errorf("hypervisor machine-network interface is required to create %s", bmExGwNetworkName)
	}
	if v4Subnet == "" && v6Subnet == "" {
		return fmt.Errorf("machine-network subnets are required to create %s", bmExGwNetworkName)
	}

	var (
		v4GW, v6GW       string
		v4Range, v6Range string
	)
	if v4Subnet != "" {
		ipam, err := reservedExGwIPAM(v4Subnet)
		if err != nil {
			return err
		}
		v4GW, v4Range = ipam.Gateway, ipam.IPRange
	}
	if v6Subnet != "" {
		ipam, err := reservedExGwIPAM(v6Subnet)
		if err != nil {
			return err
		}
		v6GW, v6Range = ipam.Gateway, ipam.IPRange
	}

	// Never remove containers owned by an earlier or concurrent invocation.
	// Report them before changing host addresses, routes, or firewall rules.
	_, probeErr := runner.Run("podman", "network", "exists", bmExGwNetworkName)
	if probeErr != nil {
		var status interface{ ExitStatus() int }
		if !errors.As(probeErr, &status) || status.ExitStatus() != 1 {
			return fmt.Errorf("probe %s network: %w", bmExGwNetworkName, probeErr)
		}
	}
	if err := validateExGwParentAddresses(runner, hostNet.InfName, v4GW, v4Range, v6GW, v6Range); err != nil {
		return err
	}
	if probeErr == nil {
		attached, listErr := runner.Run("podman", "ps", "-a", "--filter", "network="+bmExGwNetworkName, "--format", "{{.Names}}")
		if listErr != nil {
			return fmt.Errorf("failed to list %s attachments: %w", bmExGwNetworkName, listErr)
		}
		if strings.TrimSpace(attached) != "" {
			return fmt.Errorf("cannot recreate %s: attached containers must be cleaned up first: %s", bmExGwNetworkName, strings.TrimSpace(attached))
		}
		if err := validateExGwHostMacvlan(runner, hostNet.InfName); err != nil {
			return err
		}
		if _, err := runner.Run("podman", "network", "rm", bmExGwNetworkName); err != nil {
			return fmt.Errorf("failed to remove existing %s network before recreate: %w", bmExGwNetworkName, err)
		}
	}
	if err := ensureExGwHostMacvlan(runner, hostNet.InfName, v4GW, v4Range, v6GW, v6Range); err != nil {
		return err
	}
	if err := ensureExGwInternetNAT(runner, hostNet.InfName, v4Range, v6Range); err != nil {
		return err
	}

	cmdArgs := []string{
		"network", "create",
		"-d", "macvlan",
		"-o", "parent=" + hostNet.InfName,
	}
	if v4Subnet != "" {
		cmdArgs = append(cmdArgs, "--subnet", v4Subnet, "--ip-range", v4Range, "--gateway", v4GW)
	}
	if v6Subnet != "" {
		cmdArgs = append(cmdArgs, "--subnet", v6Subnet, "--ip-range", v6Range, "--gateway", v6GW, "--ipv6")
	}
	cmdArgs = append(cmdArgs, bmExGwNetworkName)

	stdOut, err := runner.Run("podman", cmdArgs...)
	if err != nil {
		return fmt.Errorf("podman %s failed: %w (%s)", strings.Join(cmdArgs, " "), err, stdOut)
	}
	return nil
}

// exGwIPAM holds the host-sibling gateway and container IPAM slice for one family.
type exGwIPAM struct {
	Gateway      string // host sibling IP (podman --gateway); installed as /32 or /128
	IPRange      string // CIDR for podman --ip-range and host route via xgw-host
	SubnetPrefix int    // machine-network prefix (podman --subnet); not used on xgw-host
}

// existingExGwPoolExclusions protects endpoints from earlier runs until lazy
// setup can remove the old network. Podman retains its configured allocation range.
func existingExGwPoolExclusions(runner api.Runner) ([]string, error) {
	if _, err := runner.Run("podman", "network", "exists", bmExGwNetworkName); err != nil {
		var status interface{ ExitStatus() int }
		if errors.As(err, &status) && status.ExitStatus() == 1 {
			return nil, nil
		}
		return nil, fmt.Errorf("probe existing gateway pool: %w", err)
	}
	out, err := runner.Run("podman", "network", "inspect", bmExGwNetworkName)
	if err != nil {
		return nil, err
	}
	var networks []struct {
		Subnets []struct {
			Subnet     string `json:"subnet"`
			LeaseRange *struct {
				StartIP string `json:"start_ip"`
				EndIP   string `json:"end_ip"`
			} `json:"lease_range"`
		} `json:"subnets"`
	}
	if err := json.Unmarshal([]byte(out), &networks); err != nil {
		return nil, fmt.Errorf("decode existing gateway pool: %w", err)
	}
	if len(networks) != 1 {
		return nil, fmt.Errorf("expected one existing gateway network, got %d", len(networks))
	}
	if len(networks[0].Subnets) == 0 {
		return nil, fmt.Errorf("existing gateway network has no subnet inventory")
	}
	var exclusions []string
	for _, subnet := range networks[0].Subnets {
		// Reserve the full subnet if Podman does not expose a lease range.
		// This is conservative and never permits allocating a live endpoint.
		_, prefix, err := net.ParseCIDR(subnet.Subnet)
		if err != nil {
			return nil, err
		}
		if subnet.LeaseRange == nil {
			exclusions = append(exclusions, prefix.String())
			continue
		}
		start, end := net.ParseIP(subnet.LeaseRange.StartIP), net.ParseIP(subnet.LeaseRange.EndIP)
		if !prefix.Contains(start) || !prefix.Contains(end) || bytes.Compare(start, end) > 0 {
			return nil, fmt.Errorf("invalid lease range on gateway subnet %s", subnet.Subnet)
		}
		bits := 128
		if start.To4() != nil {
			start = start.To4()
			bits = 32
		}
		// A covering prefix keeps this bounded even for large lease ranges.
		for ones := bits; ones >= 0; ones-- {
			mask := net.CIDRMask(ones, bits)
			cover := &net.IPNet{IP: start.Mask(mask), Mask: mask}
			if cover.Contains(end) {
				exclusions = append(exclusions, cover.String())
				break
			}
		}
	}
	return exclusions, nil
}

// validateExGwParentAddresses checks secondary addresses as well as the primary
// address: neither the host gateway nor Podman's pool may overlap the parent.
func validateExGwParentAddresses(runner api.Runner, parent, v4GW, v4Range, v6GW, v6Range string) error {
	entries, err := listDeviceAddrs(runner, parent)
	if err != nil {
		return fmt.Errorf("list parent %s addresses: %w", parent, err)
	}
	for _, cidr := range []string{v4Range, v6Range} {
		if cidr == "" {
			continue
		}
		_, pool, err := net.ParseCIDR(cidr)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			for _, address := range entry.AddrInfo {
				ip := net.ParseIP(address.Local)
				if pool.Contains(ip) || ip.Equal(net.ParseIP(v4GW)) || ip.Equal(net.ParseIP(v6GW)) {
					return fmt.Errorf("parent interface %s address %s conflicts with external gateway reservation", parent, address.Local)
				}
			}
		}
	}
	return nil
}

// reservedExGwIPAM returns a high IPAM slice and the address immediately before
// it for the host macvlan sibling gateway. Setup checks this reservation against
// parent, node and VIP assignments before using it. Fits /24 and /64 as well as
// metal dualstack IPv6 /120.
func reservedExGwIPAM(subnet string) (exGwIPAM, error) {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return exGwIPAM{}, fmt.Errorf("invalid subnet %q: %w", subnet, err)
	}
	ones, bits := ipNet.Mask.Size()
	hostBits := bits - ones
	// Need room for the host gateway plus a 16-address container pool.
	if hostBits < exGwPoolBits+1 {
		return exGwIPAM{}, fmt.Errorf("subnet %s too small for EG IPAM (need at least %d host bits)", subnet, exGwPoolBits+1)
	}
	rangePrefix := bits - exGwPoolBits

	poolStart := make(net.IP, bits/8)
	if bits == 32 {
		copy(poolStart, ipNet.IP.To4())
	} else {
		copy(poolStart, ipNet.IP.To16())
	}
	for b := 0; b < hostBits; b++ {
		byteIdx := len(poolStart) - 1 - b/8
		poolStart[byteIdx] |= 1 << (b % 8)
	}
	for b := 0; b < exGwPoolBits; b++ {
		byteIdx := len(poolStart) - 1 - b/8
		poolStart[byteIdx] &^= 1 << (b % 8)
	}
	if !ipNet.Contains(poolStart) {
		return exGwIPAM{}, fmt.Errorf("EG IP range start %s is outside subnet %s", poolStart, subnet)
	}

	gw := decIP(poolStart)
	if !ipNet.Contains(gw) {
		return exGwIPAM{}, fmt.Errorf("EG host gateway %s is outside subnet %s", gw, subnet)
	}
	return exGwIPAM{
		Gateway:      gw.String(),
		IPRange:      fmt.Sprintf("%s/%d", poolStart.String(), rangePrefix),
		SubnetPrefix: ones,
	}, nil
}

func decIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]--
		if out[i] != 0xff {
			break
		}
	}
	return out
}

// validateExGwHostMacvlan checks ownership before removing an existing network.
func validateExGwHostMacvlan(runner api.Runner, parent string) error {
	if _, err := runner.Run("ip", "link", "show", "dev", bmExGwHostLinkName); err != nil {
		var status interface{ ExitStatus() int }
		if errors.As(err, &status) && status.ExitStatus() == 1 {
			return nil
		}
		return fmt.Errorf("probe gateway sibling: %w", err)
	}
	// Existence alone is insufficient: a previous run may have used a
	// different uplink. Do not alter an interface with unexpected ownership.
	out, inspectErr := runner.Run("ip", "-j", "-d", "link", "show", "dev", bmExGwHostLinkName)
	if inspectErr != nil {
		return fmt.Errorf("inspect %s: %w", bmExGwHostLinkName, inspectErr)
	}
	var links []struct {
		LinkIndex int    `json:"link_index"`
		Parent    string `json:"link"`
		LinkInfo  struct {
			Kind string `json:"info_kind"`
			Data struct {
				Mode string `json:"mode"`
			} `json:"info_data"`
		} `json:"linkinfo"`
	}
	if err := json.Unmarshal([]byte(out), &links); err != nil {
		return fmt.Errorf("decode %s: %w", bmExGwHostLinkName, err)
	}
	out, inspectErr = runner.Run("ip", "-j", "link", "show", "dev", parent)
	if inspectErr != nil {
		return fmt.Errorf("inspect parent %s: %w", parent, inspectErr)
	}
	var parents []struct {
		Index int `json:"ifindex"`
	}
	if err := json.Unmarshal([]byte(out), &parents); err != nil {
		return fmt.Errorf("decode parent %s: %w", parent, err)
	}
	if len(links) != 1 || len(parents) != 1 ||
		(links[0].Parent != parent && (links[0].Parent != "" || links[0].LinkIndex != parents[0].Index)) ||
		links[0].LinkInfo.Kind != "macvlan" || links[0].LinkInfo.Data.Mode != "bridge" {
		return fmt.Errorf("existing %s must be a bridge-mode macvlan on %s; remove the stale test interface before retrying", bmExGwHostLinkName, parent)
	}
	return nil
}

// ensureExGwHostMacvlan creates/up the host sibling macvlan used as xgw gateway.
// The gateway address is installed as /32 (IPv4) or /128 (IPv6) so the kernel
// does not install a connected route for the whole machine subnet on xgw-host;
// container pools are reached via explicit routes on this device instead.
func ensureExGwHostMacvlan(runner api.Runner, parent, v4GW, v4Range, v6GW, v6Range string) error {
	if _, err := runner.Run("ip", "link", "show", "dev", bmExGwHostLinkName); err != nil {
		stdOut, err := runner.Run("ip", "link", "add", bmExGwHostLinkName, "link", parent, "type", "macvlan", "mode", "bridge")
		if err != nil {
			return fmt.Errorf("failed to create host macvlan %s on parent %s: %w (%s)", bmExGwHostLinkName, parent, err, stdOut)
		}
	} else {
		if err := validateExGwHostMacvlan(runner, parent); err != nil {
			return err
		}
	}
	if err := reconcileExGwHostState(runner, v4GW, v4Range, v6GW, v6Range); err != nil {
		return err
	}

	if v4GW != "" {
		if err := ensureAddrOnDevice(runner, bmExGwHostLinkName, v4GW+"/32"); err != nil {
			return err
		}
	}
	if v6GW != "" {
		if err := ensureAddrOnDevice(runner, bmExGwHostLinkName, v6GW+"/128"); err != nil {
			return err
		}
	}
	if stdOut, err := runner.Run("ip", "link", "set", "dev", bmExGwHostLinkName, "up"); err != nil {
		return fmt.Errorf("failed to bring up %s: %w (%s)", bmExGwHostLinkName, err, stdOut)
	}
	if v4Range != "" {
		if err := ensureExGwHostPoolRoute(runner, false, v4Range); err != nil {
			return err
		}
	}
	if v6Range != "" {
		if err := ensureExGwHostPoolRoute(runner, true, v6Range); err != nil {
			return err
		}
	}
	return nil
}

// reconcileExGwHostState removes obsolete addresses and explicit routes only
// from the validated test-owned sibling. Link-local and kernel routes stay intact.
func reconcileExGwHostState(runner api.Runner, v4GW, v4Range, v6GW, v6Range string) error {
	entries, err := listDeviceAddrs(runner, bmExGwHostLinkName)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		for _, address := range entry.AddrInfo {
			ip := net.ParseIP(address.Local)
			if ip == nil || ip.IsLinkLocalUnicast() || ip.IsLoopback() || ip.Equal(net.ParseIP(v4GW)) || ip.Equal(net.ParseIP(v6GW)) {
				continue
			}
			cidr := fmt.Sprintf("%s/%d", address.Local, address.PrefixLen)
			if _, err := runner.Run("ip", "addr", "del", cidr, "dev", bmExGwHostLinkName); err != nil {
				return fmt.Errorf("remove obsolete gateway address %s: %w", cidr, err)
			}
		}
	}
	for _, family := range []struct {
		prefix []string
		pool   string
	}{{nil, v4Range}, {[]string{"-6"}, v6Range}} {
		args := append(append([]string{}, family.prefix...), "-j", "route", "show", "dev", bmExGwHostLinkName)
		out, err := runner.Run("ip", args...)
		if err != nil {
			return fmt.Errorf("list gateway pool routes: %w", err)
		}
		var routes []struct {
			Dst      string `json:"dst"`
			Protocol string `json:"protocol"`
		}
		if err := json.Unmarshal([]byte(out), &routes); err != nil {
			return fmt.Errorf("decode gateway pool routes: %w", err)
		}
		for _, route := range routes {
			if _, pool, err := net.ParseCIDR(route.Dst); err == nil && route.Protocol != "kernel" && !pool.IP.IsLinkLocalUnicast() {
				bin := "iptables"
				if pool.IP.To4() == nil {
					bin = "ip6tables"
				}
				if err := removeLegacyExGwRules(runner, bin, pool.String()); err != nil {
					return err
				}
			}
			if route.Protocol == "kernel" || route.Dst == family.pool {
				continue
			}
			if _, prefix, err := net.ParseCIDR(route.Dst); err == nil && prefix.IP.IsLinkLocalUnicast() {
				continue
			}
			args = append(append([]string{}, family.prefix...), "route", "del", route.Dst, "dev", bmExGwHostLinkName)
			if _, err := runner.Run("ip", args...); err != nil {
				return fmt.Errorf("remove obsolete gateway route %s: %w", route.Dst, err)
			}
		}
	}
	return nil
}

// ensureAddrOnDevice installs cidr on dev. Matching addresses for the same IP
// with a different prefix (e.g. leftover /24 or /120 on xgw-host) are deleted
// first — "ip addr replace" does not migrate IPv4/IPv6 prefix lengths and would
// leave the machine-subnet connected route in place.
func ensureAddrOnDevice(runner api.Runner, dev, cidr string) error {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid address %q: %w", cidr, err)
	}
	wantPrefix, _ := network.Mask.Size()
	if err := deleteMismatchedGatewayAddrs(runner, dev, ip, wantPrefix); err != nil {
		return err
	}
	exact, err := hasExactAddr(runner, dev, ip, wantPrefix)
	if err != nil {
		return err
	}
	if exact {
		return nil
	}
	args := []string{"addr", "add", cidr, "dev", dev}
	if ip.To4() == nil {
		args = append(args, "nodad")
	}
	stdOut, err := runner.Run("ip", args...)
	if err != nil {
		// SSH reports command stderr in the error, so verify state rather
		// than treating an error string as proof that the address exists.
		if exact, checkErr := hasExactAddr(runner, dev, ip, wantPrefix); checkErr == nil && exact {
			return nil
		}
		return fmt.Errorf("failed to add %s on %s: %w (%s)", cidr, dev, err, stdOut)
	}
	return nil
}

type ipAddrShowEntry struct {
	IfName   string `json:"ifname"`
	AddrInfo []struct {
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
	} `json:"addr_info"`
}

func listDeviceAddrs(runner api.Runner, dev string) ([]ipAddrShowEntry, error) {
	args := []string{"-j", "addr", "show"}
	if dev != "" {
		args = append(args, "dev", dev)
	}
	out, err := runner.Run("ip", args...)
	if err != nil {
		return nil, err
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return nil, nil
	}
	var entries []ipAddrShowEntry
	if err := json.Unmarshal([]byte(out), &entries); err != nil {
		return nil, fmt.Errorf("parse addr show for %s: %w (%s)", dev, err, out)
	}
	return entries, nil
}

func deleteMismatchedGatewayAddrs(runner api.Runner, dev string, wantIP net.IP, wantPrefix int) error {
	entries, err := listDeviceAddrs(runner, dev)
	if err != nil {
		return fmt.Errorf("failed to list addresses on %s: %w", dev, err)
	}
	for _, entry := range entries {
		for _, ai := range entry.AddrInfo {
			existing := net.ParseIP(ai.Local)
			if existing == nil || !existing.Equal(wantIP) {
				continue
			}
			if ai.PrefixLen == wantPrefix {
				continue
			}
			delCIDR := fmt.Sprintf("%s/%d", wantIP.String(), ai.PrefixLen)
			args := []string{"addr", "del", delCIDR, "dev", dev}
			stdOut, delErr := runner.Run("ip", args...)
			if delErr != nil {
				remaining, checkErr := listDeviceAddrs(runner, dev)
				mismatched := false
				for _, link := range remaining {
					for _, address := range link.AddrInfo {
						if wantIP.Equal(net.ParseIP(address.Local)) && address.PrefixLen != wantPrefix {
							mismatched = true
						}
					}
				}
				if checkErr == nil && !mismatched {
					return nil
				}
				return fmt.Errorf("failed to delete mismatched %s on %s: %w (%s)", delCIDR, dev, delErr, stdOut)
			}
		}
	}
	return nil
}

func hasExactAddr(runner api.Runner, dev string, wantIP net.IP, wantPrefix int) (bool, error) {
	entries, err := listDeviceAddrs(runner, dev)
	if err != nil {
		return false, fmt.Errorf("failed to list addresses on %s: %w", dev, err)
	}
	for _, entry := range entries {
		for _, ai := range entry.AddrInfo {
			existing := net.ParseIP(ai.Local)
			if existing != nil && existing.Equal(wantIP) && ai.PrefixLen == wantPrefix {
				return true, nil
			}
		}
	}
	return false, nil
}

func ensureExGwHostPoolRoute(runner api.Runner, ipv6 bool, poolCIDR string) error {
	args := []string{"route", "replace", poolCIDR, "dev", bmExGwHostLinkName}
	if ipv6 {
		args = append([]string{"-6"}, args...)
	}
	stdOut, err := runner.Run("ip", args...)
	if err != nil {
		return fmt.Errorf("failed to replace route %s via %s: %w (%s)", poolCIDR, bmExGwHostLinkName, err, stdOut)
	}
	return nil
}

// ensureExGwInternetNAT enables forwarding and MASQUERADE so xgw containers
// can reach the public internet via the hypervisor (for apk on official FRR).
// Metal CI squid only allows cluster domains, so EG containers must use direct
// egress through this NAT path rather than HTTP_PROXY.
func ensureExGwInternetNAT(runner api.Runner, parentIface, v4Range, v6Range string) error {
	if v4Range != "" {
		if _, err := runner.Run("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
			return fmt.Errorf("failed to enable IPv4 forwarding: %w", err)
		}
	}
	if v6Range != "" {
		if _, err := runner.Run("sysctl", "-w", "net.ipv6.conf.all.forwarding=1"); err != nil {
			return fmt.Errorf("failed to enable IPv6 forwarding: %w", err)
		}
	}
	if err := ensureExGwFirewalldNAT(runner, parentIface, v4Range, v6Range); err != nil {
		return err
	}
	for _, family := range []struct{ bin, pool string }{{"iptables", v4Range}, {"ip6tables", v6Range}} {
		if err := reconcileExGwIptables(runner, family.bin, family.pool); err != nil {
			return err
		}
	}
	return nil
}

const exGwFirewallPolicy = "ovn-exgw-forward"

// prepareExGwFirewallPolicy runs before the provider's existing startup reload.
// Lazy gateway setup can then configure this policy without losing runtime rules.
func prepareExGwFirewallPolicy(runner api.Runner) error {
	if _, err := runner.Run("firewall-cmd", "--state"); err != nil {
		return nil
	}
	policies, err := runner.Run("firewall-cmd", "--permanent", "--get-policies")
	if err != nil {
		return fmt.Errorf("list gateway firewall policies: %w", err)
	}
	if !sets.New(strings.Fields(policies)...).Has(exGwFirewallPolicy) {
		if _, err := runner.Run("firewall-cmd", "--permanent", "--new-policy="+exGwFirewallPolicy); err != nil {
			return fmt.Errorf("prepare gateway firewall policy: %w", err)
		}
	}
	if _, err := runner.Run("firewall-cmd", "--permanent", "--policy="+exGwFirewallPolicy, "--set-target=CONTINUE"); err != nil {
		return fmt.Errorf("prepare gateway firewall target: %w", err)
	}
	return nil
}

// ensureExGwFirewalldNAT changes only runtime gateway rules. ANY excludes host
// input, and NAT matches each configured pool instead of the whole parent zone.
func ensureExGwFirewalldNAT(runner api.Runner, parentIface, v4Range, v6Range string) error {
	if _, err := runner.Run("firewall-cmd", "--state"); err != nil {
		return nil
	}
	policies, err := runner.Run("firewall-cmd", "--get-policies")
	if err != nil {
		return err
	}
	if !sets.New(strings.Fields(policies)...).Has(exGwFirewallPolicy) {
		return fmt.Errorf("gateway firewall policy %s was not activated at provider startup", exGwFirewallPolicy)
	}
	zone, err := runner.Run("firewall-cmd", "--get-zone-of-interface="+parentIface)
	if err != nil || strings.TrimSpace(zone) == "" || strings.TrimSpace(zone) == "no zone" {
		zone, err = runner.Run("firewall-cmd", "--get-default-zone")
	}
	if err != nil {
		return err
	}
	zone = strings.TrimSpace(zone)
	if zone == "" {
		return fmt.Errorf("empty firewall zone for %s", parentIface)
	}
	policyArg := "--policy=" + exGwFirewallPolicy
	// The policy is owned by these tests; remove earlier pool/zone settings
	// without touching any other policy, zone rule, or runtime-only service.
	for _, setting := range []struct {
		list, remove string
		lines        bool
	}{
		{"--list-ingress-zones", "--remove-ingress-zone=", false},
		{"--list-egress-zones", "--remove-egress-zone=", false},
		{"--list-rich-rules", "--remove-rich-rule=", true},
	} {
		out, err := runner.Run("firewall-cmd", policyArg, setting.list)
		if err != nil {
			return err
		}
		values := strings.Fields(out)
		if setting.lines {
			values = strings.Split(strings.TrimSpace(out), "\n")
		}
		for _, value := range values {
			if value == "" {
				continue
			}
			if _, err := runner.Run("firewall-cmd", policyArg, setting.remove+value); err != nil {
				return err
			}
		}
	}
	commands := [][]string{
		{"--zone=" + zone, "--change-interface=" + bmExGwHostLinkName},
		{policyArg, "--add-ingress-zone=" + zone},
		{policyArg, "--add-egress-zone=ANY"},
	}
	for _, family := range []struct{ name, cidr string }{{"ipv4", v4Range}, {"ipv6", v6Range}} {
		if family.cidr == "" {
			continue
		}
		for _, action := range []string{"accept", "masquerade"} {
			rule := fmt.Sprintf("rule family=%q source address=%q %s", family.name, family.cidr, action)
			commands = append(commands, []string{policyArg, "--add-rich-rule=" + rule})
		}
	}
	for _, args := range commands {
		if _, err := runner.Run("firewall-cmd", args...); err != nil {
			return fmt.Errorf("configure gateway firewall %v: %w", args, err)
		}
	}
	return nil
}

// removeLegacyExGwRules migrates the untagged rules used before owned chains.
// Callers supply only pools identified by routes on the validated xgw sibling.
func removeLegacyExGwRules(runner api.Runner, bin, pool string) error {
	for _, rule := range []struct{ table, spec string }{
		{"nat", "-A POSTROUTING -s " + pool + " -j MASQUERADE"},
		{"filter", "-A FORWARD -s " + pool + " -j ACCEPT"},
		{"filter", "-A FORWARD -d " + pool + " -j ACCEPT"},
	} {
		out, err := runner.Run(bin, "-t", rule.table, "-S")
		if err != nil {
			return fmt.Errorf("list %s %s rules: %w", bin, rule.table, err)
		}
		for _, line := range strings.Split(out, "\n") {
			if strings.TrimSpace(line) != rule.spec {
				continue
			}
			args := append([]string{"-t", rule.table, "-D"}, strings.Fields(rule.spec)[1:]...)
			if _, err := runner.Run(bin, args...); err != nil {
				return fmt.Errorf("remove legacy gateway rule: %w", err)
			}
		}
	}
	return nil
}

// Rebuild only test-owned chains, including when a family no longer has a pool.
// Stable parent jumps keep retries from accumulating rules.
func reconcileExGwIptables(runner api.Runner, bin, pool string) error {
	for _, config := range []struct{ table, parent, chain string }{
		{"nat", "POSTROUTING", "OVN-EXGW-NAT"},
		{"filter", "FORWARD", "OVN-EXGW-FWD"},
	} {
		out, err := runner.Run(bin, "-t", config.table, "-S")
		if err != nil {
			return fmt.Errorf("list %s %s rules: %w", bin, config.table, err)
		}
		lines := sets.New(strings.Split(strings.TrimSpace(out), "\n")...)
		if !lines.Has("-N " + config.chain) {
			if _, err := runner.Run(bin, "-t", config.table, "-N", config.chain); err != nil {
				return err
			}
		}
		if _, err := runner.Run(bin, "-t", config.table, "-F", config.chain); err != nil {
			return err
		}
		if pool != "" {
			rules := [][]string{{"-s", pool, "-j", "MASQUERADE"}}
			if config.table == "filter" {
				rules = [][]string{{"-s", pool, "-j", "ACCEPT"}, {"-d", pool, "-j", "ACCEPT"}}
			}
			for _, rule := range rules {
				args := append([]string{"-t", config.table, "-A", config.chain}, rule...)
				if _, err := runner.Run(bin, args...); err != nil {
					return err
				}
			}
		}
		jump := "-A " + config.parent + " -j " + config.chain
		if !lines.Has(jump) {
			if _, err := runner.Run(bin, "-t", config.table, "-I", config.parent, "1", "-j", config.chain); err != nil {
				return err
			}
		}
	}
	return nil
}

// configureFirewallForExternalContainerPorts opens the external container port
// range (12000-65535/tcp) in the hypervisor firewall. The range matches the
// port allocator in the container engine. The rule is added as permanent and
// reloaded so it survives firewall restarts during the test run.
func configureFirewallForExternalContainerPorts(runner api.Runner, interfaceName string) error {
	zone, err := runner.Run("firewall-cmd", "--get-zone-of-interface="+interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get firewall zone for interface %s: %w", interfaceName, err)
	}
	zone = strings.TrimSpace(zone)
	if _, err := runner.Run("firewall-cmd", "--zone="+zone, "--add-port=12000-65535/tcp", "--permanent"); err != nil {
		return fmt.Errorf("failed to add firewall port range 12000-65535/tcp to zone %s: %w", zone, err)
	}
	if _, err := runner.Run("firewall-cmd", "--reload"); err != nil {
		return fmt.Errorf("failed to reload firewall: %w", err)
	}
	return nil
}

// baremetalContextProvider wraps baseContextProvider with secondary network
// awareness and isolated containers. On baremetal, the secondary network is
// pre-configured by CI and containers use host networking, so network
// creation/deletion and network attach/detach are no-ops for it. Every
// secondary network shortcut applies only when that network exists; otherwise
// the call goes to the base provider exactly as without this wrapper.
// Attaching or detaching networks on isolated containers is not supported:
// those containers are created on the isolated network with their
// allocator-assigned addresses, and no spec attaches networks to them.
type baremetalContextProvider struct {
	base *baseContextProvider
	bm   *baremetalInfra
}

func (p *baremetalContextProvider) hasSecondaryNetwork() bool {
	return p.bm.secondaryNetwork != nil
}

func (p *baremetalContextProvider) CreateNetwork(name string, subnets ...string) (api.Network, error) {
	if name == bmSecondaryNetworkName && p.hasSecondaryNetwork() {
		return p.bm.secondaryNetwork, nil
	}
	return p.base.CreateNetwork(name, subnets...)
}

func (p *baremetalContextProvider) DeleteNetwork(network api.Network) error {
	if network.Name() == bmSecondaryNetworkName && p.hasSecondaryNetwork() {
		return nil
	}
	return p.base.DeleteNetwork(network)
}

func (p *baremetalContextProvider) CreateExternalContainer(ec api.ExternalContainer) (api.ExternalContainer, error) {
	if ec.Network != nil && ec.Network.Name() == bmPrimaryNetworkName && needsIsolation(ec.Name) {
		return p.bm.isolated.create(ec, p.base)
	}
	if ec.Network != nil && ec.Network.Name() == bmSecondaryNetworkName && p.hasSecondaryNetwork() {
		return p.bm.base.getOrCreateHostNetworkedContainer(ec, p.bm.secondaryHostNetInfo)
	}
	return p.base.CreateExternalContainer(ec)
}

func (p *baremetalContextProvider) DeleteExternalContainer(ec api.ExternalContainer) error {
	return p.base.DeleteExternalContainer(ec)
}

func (p *baremetalContextProvider) AttachNetwork(network api.Network, instance string) (api.NetworkInterface, error) {
	if needsIsolation(instance) {
		return api.NetworkInterface{}, fmt.Errorf("attaching network %q to isolated container %q is not supported", network.Name(), instance)
	}
	if network.Name() == bmSecondaryNetworkName && p.hasSecondaryNetwork() {
		return api.NetworkInterface{}, nil
	}
	return p.base.AttachNetwork(network, instance)
}

func (p *baremetalContextProvider) DetachNetwork(network api.Network, instance string) error {
	if needsIsolation(instance) {
		return fmt.Errorf("detaching network %q from isolated container %q is not supported", network.Name(), instance)
	}
	if network.Name() == bmSecondaryNetworkName && p.hasSecondaryNetwork() {
		return nil
	}
	return p.base.DetachNetwork(network, instance)
}

func ipInCIDR(ipStr, cidrStr string) (bool, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, fmt.Errorf("invalid IP address: %q", ipStr)
	}
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return false, err
	}
	return ipNet.Contains(ip), nil
}
