// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package infraprovider

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"

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
}

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
	// Open the external container port range (12000-65535/tcp) in the
	// hypervisor firewall once, instead of per-port during each test.
	if h.hostNetworkInfo != nil {
		if err := configureFirewallForExternalContainerPorts(sshRunner, h.hostNetworkInfo.InfName); err != nil {
			return nil, fmt.Errorf("failed to configure firewall for external container ports: %w", err)
		}
		if err := ensureExternalGatewayNetwork(sshRunner, h.hostNetworkInfo, v4, v6); err != nil {
			return nil, fmt.Errorf("failed to ensure external gateway network %s: %w", bmExGwNetworkName, err)
		}
	}

	bm := &baremetalInfra{base: h}

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
	if name == bmSecondaryNetworkName && ci.secondaryNetwork != nil {
		return ci.secondaryNetwork, nil
	}
	return ci.base.GetNetwork(name)
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

func (ci *baremetalInfra) GetExternalContainerContextProvider(context *testcontext.TestContext) api.ExternalContainerContextProvider {
	baseProvider := &baseContextProvider{
		parent: ci.base,
		engine: ci.base.engine.WithTestContext(context),
	}
	if ci.secondaryNetwork == nil {
		return baseProvider
	}
	return &baremetalContextProvider{base: baseProvider, bm: ci}
}

// GetExternalContainerPort delegates to base and also configures the
// hypervisor firewall for the allocated port.
func (ci *baremetalInfra) GetExternalContainerPort() uint16 {
	return ci.base.GetExternalContainerPort()
}

// GetExternalContainerNetworkInterface handles the FRR container special case
// on the primary network, then delegates to base for everything else.
func (ci *baremetalInfra) GetExternalContainerNetworkInterface(ec api.ExternalContainer, network api.Network) (api.NetworkInterface, error) {
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
// internet access (apk) — macvlan cannot reach the parent's host IP. Must not
// use --internal bridge create (unreachable from nodes).
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
		v4Prefix         int
		v6Prefix         int
	)
	if v4Subnet != "" {
		ipam, err := reservedExGwIPAM(v4Subnet)
		if err != nil {
			return err
		}
		v4GW, v4Range, v4Prefix = ipam.Gateway, ipam.IPRange, ipam.SubnetPrefix
	}
	if v6Subnet != "" {
		ipam, err := reservedExGwIPAM(v6Subnet)
		if err != nil {
			return err
		}
		v6GW, v6Range, v6Prefix = ipam.Gateway, ipam.IPRange, ipam.SubnetPrefix
	}

	if err := ensureExGwHostMacvlan(runner, hostNet.InfName, v4GW, v4Prefix, v6GW, v6Prefix); err != nil {
		return err
	}
	if err := ensureExGwInternetNAT(runner, hostNet.InfName, v4Range, v6Range); err != nil {
		return err
	}

	if _, err := runner.Run("podman", "network", "exists", bmExGwNetworkName); err == nil {
		// Recreate so gateway points at the host sibling (older runs may have
		// used the unreachable parent IP). Safe at infra init before EG containers.
		if _, err := runner.Run("podman", "network", "rm", bmExGwNetworkName); err != nil {
			return fmt.Errorf("failed to remove existing %s network before recreate: %w", bmExGwNetworkName, err)
		}
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
	Gateway      string // host sibling IP (podman --gateway)
	IPRange      string // CIDR for podman --ip-range
	SubnetPrefix int    // machine-network prefix for ip addr add on the sibling
}

// reservedExGwIPAM returns a high IPAM slice and the address immediately before
// it for the host macvlan sibling gateway. The pool avoids VIPs, node IPs, and
// FRR (.3 / ::3). Fits /24 and /64 as well as metal dualstack IPv6 /120.
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

// reservedExGwIPRange is kept for tests that only assert the container pool.
func reservedExGwIPRange(subnet string) (string, error) {
	ipam, err := reservedExGwIPAM(subnet)
	if err != nil {
		return "", err
	}
	return ipam.IPRange, nil
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

// ensureExGwHostMacvlan creates/up the host sibling macvlan used as xgw gateway.
func ensureExGwHostMacvlan(runner api.Runner, parent, v4GW string, v4Prefix int, v6GW string, v6Prefix int) error {
	if _, err := runner.Run("ip", "link", "show", "dev", bmExGwHostLinkName); err != nil {
		stdOut, err := runner.Run("ip", "link", "add", bmExGwHostLinkName, "link", parent, "type", "macvlan", "mode", "bridge")
		if err != nil {
			return fmt.Errorf("failed to create host macvlan %s on parent %s: %w (%s)", bmExGwHostLinkName, parent, err, stdOut)
		}
	}
	if v4GW != "" {
		if err := ensureAddrOnDevice(runner, bmExGwHostLinkName, fmt.Sprintf("%s/%d", v4GW, v4Prefix)); err != nil {
			return err
		}
	}
	if v6GW != "" {
		if err := ensureAddrOnDevice(runner, bmExGwHostLinkName, fmt.Sprintf("%s/%d", v6GW, v6Prefix)); err != nil {
			return err
		}
	}
	if stdOut, err := runner.Run("ip", "link", "set", "dev", bmExGwHostLinkName, "up"); err != nil {
		return fmt.Errorf("failed to bring up %s: %w (%s)", bmExGwHostLinkName, err, stdOut)
	}
	return nil
}

func ensureAddrOnDevice(runner api.Runner, dev, cidr string) error {
	out, err := runner.Run("ip", "-j", "addr", "show", "dev", dev)
	if err == nil && strings.Contains(out, strings.Split(cidr, "/")[0]) {
		return nil
	}
	args := []string{"addr", "add", cidr, "dev", dev}
	if strings.Contains(cidr, ":") {
		args = append(args, "nodad")
	}
	stdOut, err := runner.Run("ip", args...)
	if err != nil && !strings.Contains(stdOut, "File exists") {
		return fmt.Errorf("failed to add %s on %s: %w (%s)", cidr, dev, err, stdOut)
	}
	return nil
}

// ensureExGwInternetNAT enables forwarding and MASQUERADE so xgw containers
// can reach the public internet via the hypervisor (for apk on official FRR).
// Metal CI squid only allows cluster domains, so EG containers must use direct
// egress through this NAT path rather than HTTP_PROXY.
func ensureExGwInternetNAT(runner api.Runner, parentIface, v4Range, v6Range string) error {
	if _, err := runner.Run("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return fmt.Errorf("failed to enable IPv4 forwarding: %w", err)
	}
	if v6Range != "" {
		if _, err := runner.Run("sysctl", "-w", "net.ipv6.conf.all.forwarding=1"); err != nil {
			return fmt.Errorf("failed to enable IPv6 forwarding: %w", err)
		}
	}
	if err := ensureExGwFirewalldNAT(runner, parentIface); err != nil {
		return err
	}
	if v4Range != "" {
		if err := ensureIptablesMasquerade(runner, "iptables", v4Range); err != nil {
			return err
		}
		if err := ensureIptablesForward(runner, "iptables", v4Range); err != nil {
			return err
		}
	}
	if v6Range != "" {
		if err := ensureIptablesMasquerade(runner, "ip6tables", v6Range); err != nil {
			return err
		}
		if err := ensureIptablesForward(runner, "ip6tables", v6Range); err != nil {
			return err
		}
	}
	return nil
}

// ensureExGwFirewalldNAT trusts the host sibling and enables zone masquerade so
// firewalld (nft) does not drop forwarded xgw traffic on metal hypervisors.
func ensureExGwFirewalldNAT(runner api.Runner, parentIface string) error {
	if _, err := runner.Run("firewall-cmd", "--state"); err != nil {
		return nil
	}
	if _, err := runner.Run("firewall-cmd", "--permanent", "--zone=trusted", "--add-interface="+bmExGwHostLinkName); err != nil {
		return fmt.Errorf("failed to add %s to trusted zone: %w", bmExGwHostLinkName, err)
	}
	zones := map[string]struct{}{}
	for _, iface := range []string{parentIface} {
		if iface == "" {
			continue
		}
		zone, err := runner.Run("firewall-cmd", "--get-zone-of-interface="+iface)
		if err != nil {
			continue
		}
		zones[strings.TrimSpace(zone)] = struct{}{}
	}
	if uplink, err := findDefaultRouteDev(runner, false); err == nil && uplink != "" {
		if zone, err := runner.Run("firewall-cmd", "--get-zone-of-interface="+uplink); err == nil {
			zones[strings.TrimSpace(zone)] = struct{}{}
		}
	}
	for zone := range zones {
		if zone == "" || zone == "trusted" {
			continue
		}
		if _, err := runner.Run("firewall-cmd", "--permanent", "--zone="+zone, "--add-masquerade"); err != nil {
			return fmt.Errorf("failed to enable masquerade on zone %s: %w", zone, err)
		}
	}
	if _, err := runner.Run("firewall-cmd", "--reload"); err != nil {
		return fmt.Errorf("failed to reload firewalld after EG NAT config: %w", err)
	}
	return nil
}

func ensureIptablesMasquerade(runner api.Runner, bin, cidr string) error {
	check := []string{"-t", "nat", "-C", "POSTROUTING", "-s", cidr, "-j", "MASQUERADE"}
	if _, err := runner.Run(bin, check...); err == nil {
		return nil
	}
	stdOut, err := runner.Run(bin, "-t", "nat", "-A", "POSTROUTING", "-s", cidr, "-j", "MASQUERADE")
	if err != nil {
		return fmt.Errorf("%s MASQUERADE for %s failed: %w (%s)", bin, cidr, err, stdOut)
	}
	return nil
}

func ensureIptablesForward(runner api.Runner, bin, cidr string) error {
	for _, args := range [][]string{
		{"-C", "FORWARD", "-s", cidr, "-j", "ACCEPT"},
		{"-C", "FORWARD", "-d", cidr, "-j", "ACCEPT"},
	} {
		if _, err := runner.Run(bin, args...); err == nil {
			continue
		}
		add := append([]string{"-I", "FORWARD", "1"}, args[2:]...)
		stdOut, err := runner.Run(bin, add...)
		if err != nil {
			return fmt.Errorf("%s FORWARD for %s failed: %w (%s)", bin, cidr, err, stdOut)
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
// awareness. On baremetal, the secondary network is pre-configured by CI and
// containers use host networking, so network creation/deletion and network
// attach/detach are no-ops.
type baremetalContextProvider struct {
	base *baseContextProvider
	bm   *baremetalInfra
}

func (p *baremetalContextProvider) CreateNetwork(name string, subnets ...string) (api.Network, error) {
	if name == bmSecondaryNetworkName {
		return p.bm.secondaryNetwork, nil
	}
	return p.base.CreateNetwork(name, subnets...)
}

func (p *baremetalContextProvider) DeleteNetwork(network api.Network) error {
	if network.Name() == bmSecondaryNetworkName {
		return nil
	}
	return p.base.DeleteNetwork(network)
}

func (p *baremetalContextProvider) CreateExternalContainer(ec api.ExternalContainer) (api.ExternalContainer, error) {
	if ec.Network != nil && ec.Network.Name() == bmSecondaryNetworkName {
		return p.bm.base.getOrCreateHostNetworkedContainer(ec, p.bm.secondaryHostNetInfo)
	}
	return p.base.CreateExternalContainer(ec)
}

func (p *baremetalContextProvider) DeleteExternalContainer(ec api.ExternalContainer) error {
	return p.base.DeleteExternalContainer(ec)
}

func (p *baremetalContextProvider) AttachNetwork(network api.Network, instance string) (api.NetworkInterface, error) {
	if network.Name() == bmSecondaryNetworkName {
		return api.NetworkInterface{}, nil
	}
	return p.base.AttachNetwork(network, instance)
}

func (p *baremetalContextProvider) DetachNetwork(network api.Network, instance string) error {
	if network.Name() == bmSecondaryNetworkName {
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
