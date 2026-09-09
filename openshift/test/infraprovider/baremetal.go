package infraprovider

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/container"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/container/network"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/runner"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/testcontext"
	"k8s.io/kubernetes/test/e2e/framework"
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

func initializeClusterInfra(infra *configv1.Infrastructure) (*baremetalInfra, error) {
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

	// Discover secondary network interface on hypervisor (optional).
	secondaryNetInfo, err := findHypervisorNodeInterface(sshRunner, bmSecondaryIPv4Subnet, bmSecondaryIPv6Subnet)
	if err == nil && secondaryNetInfo != nil {
		secondaryNet := &network.ContainerEngineNetwork{NetName: bmSecondaryNetworkName}
		secondaryNet.Configs = []network.ContainerEngineNetworkConfig{
			{Subnet: bmSecondaryIPv4Subnet},
			{Subnet: bmSecondaryIPv6Subnet},
		}
		bm.secondaryNetwork = secondaryNet
		bm.secondaryHostNetInfo = secondaryNetInfo
	}

	return bm, nil
}

// enableSecondaryForwarding enables IPv4/IPv6 forwarding on the secondary
// network interface of each cluster node. On baremetal, these interfaces are
// pre-configured but may have forwarding disabled by default. The interface
// name is the same across all cluster nodes, so it is discovered once from
// the first reachable node and reused for the rest.
func (ci *baremetalInfra) enableSecondaryForwarding(nodeNames []string, execNodeCmd func(nodeName string, cmd []string) (string, error)) error {
	if ci.secondaryNetwork == nil {
		return nil
	}
	// Discover interface name from the first reachable node.
	var ifName string
	for _, nodeName := range nodeNames {
		output, err := execNodeCmd(nodeName, []string{"ip", "-j", "addr"})
		if err != nil {
			return fmt.Errorf("failed to get addresses from node %s: %w", nodeName, err)
		}
		ifName = findInterfaceBySubnet(output, bmSecondaryIPv4Subnet, bmSecondaryIPv6Subnet)
		if ifName != "" {
			break
		}
	}
	if ifName == "" {
		return fmt.Errorf("no secondary network interface found on any node for subnets %s, %s", bmSecondaryIPv4Subnet, bmSecondaryIPv6Subnet)
	}
	for _, nodeName := range nodeNames {
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
func findInterfaceBySubnet(ipAddrJSON, v4Subnet, v6Subnet string) string {
	var links []linkInfo
	if err := json.Unmarshal([]byte(ipAddrJSON), &links); err != nil {
		return ""
	}
	for _, link := range links {
		for _, addr := range link.AddrInfo {
			if v4Subnet != "" {
				if ok, _ := ipInCIDR(addr.Local, v4Subnet); ok {
					return link.IfName
				}
			}
			if v6Subnet != "" {
				if ok, _ := ipInCIDR(addr.Local, v6Subnet); ok {
					return link.IfName
				}
			}
		}
	}
	return ""
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
	port := ci.base.GetExternalContainerPort()
	if ci.base.hostNetworkInfo != nil {
		if err := configureFirewallForPort(ci.base.runner, ci.base.hostNetworkInfo.InfName, port); err != nil {
			framework.Failf("failed to configure firewall for port %d: %v", port, err)
		}
	}
	return port
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

func hypervisorSshCmdRunner() (api.Runner, error) {
	// Read hypervisor IP from shared directory
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

// configureFirewallForPort configures firewall on the hypervisor to allow traffic on the
// given port for both tcp and udp protocols.
func configureFirewallForPort(runner api.Runner, interfaceName string, port uint16) error {
	zone, err := runner.Run("firewall-cmd", "--get-zone-of-interface="+interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get firewall zone for interface %s: %w", interfaceName, err)
	}
	zone = strings.TrimSpace(zone)
	portStr := fmt.Sprintf("%d", port)
	for _, proto := range []string{"tcp", "udp"} {
		if _, err := runner.Run("firewall-cmd", "--zone="+zone, "--add-port="+portStr+"/"+proto, "--permanent"); err != nil {
			return fmt.Errorf("failed to add firewall port %s/%s to zone %s: %w", portStr, proto, zone, err)
		}
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
