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
)

type baremetalInfra struct {
	base *baseInfra
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
	}

	return &baremetalInfra{base: h}, nil
}

func (ci *baremetalInfra) InfrastructureNetworkExclusions() (ipv4, ipv6 sets.Set[string]) {
	// The hypervisor is on the same machine network as the cluster nodes.
	return nil, nil
}

func (ci *baremetalInfra) PrimaryNetwork() (api.Network, error) {
	return ci.base.PrimaryNetwork()
}

func (ci *baremetalInfra) GetNetwork(name string) (api.Network, error) {
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
	return ci.base.GetExternalContainerContextProvider(context)
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
