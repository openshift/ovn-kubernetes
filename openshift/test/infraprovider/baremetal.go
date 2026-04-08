package infraprovider

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/container"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/container/network"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/runner"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/testcontext"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/kubernetes/test/e2e/framework"
)

const (
	hypervisorNodeUser = "root"
	hypervisorSshport  = "22"
	// use network name created for attaching frr container with
	// cluster primary network as per changes in the link:
	// https://github.com/openshift/release/blob/db6697de61f4ae7e05c5a2db782a87c459e849bf/ci-operator/step-registry/baremetalds/e2e/ovn/bgp/pre/baremetalds-e2e-ovn-bgp-pre-commands.sh#L123-L124
	primaryNetworkName         = "ostestbm_net"
	frrContainerPrimaryNetIPv4 = "192.168.111.3"
	frrContainerPrimaryNetIPv6 = "fd2e:6f44:5dd8:c956::3"
	externalFRRContainerName   = "frr"
)

type baremetalInfra struct {
	engine               *container.Engine
	machineNetwork       api.Network           // contains subnet details about cluster machine network
	machineNetworkGwInfo *api.NetworkInterface // contains interface info about hypervisor node machine network interface
}

func initializeClusterInfra(config *rest.Config) (*baremetalInfra, error) {
	// Initialize command runner for executing commands on hypervisor
	// (optional, may not be available)
	sshRunner, err := hypervisorSshCmdRunner()
	if err != nil {
		return nil, err
	}
	if sshRunner == nil {
		return nil, nil
	}
	configClient, err := configclient.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve config client: %w", err)
	}
	infra, err := configClient.ConfigV1().Infrastructures().Get(context.Background(), "cluster", metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve cluster infrastructure object: %w", err)
	}
	// Skip populating cluster infra object if cluster is not a BM.
	// This is sufficient for now to support EVPN E2Es.
	if infra.Spec.PlatformSpec.Type != configv1.BareMetalPlatformType {
		return nil, nil
	}
	ci := &baremetalInfra{}
	// Verify SSH connectivity works
	if _, err := sshRunner.Run("echo", "connection test"); err != nil {
		return nil, fmt.Errorf("failed to check frr container status, connectivity check failed with hypervisor: %w", err)
	}
	// Initialize podman container engine
	ci.engine = container.NewEngine("podman", sshRunner)
	// just mimic machine network with ContainerEngineNetwork to make it
	// compatibile with api.Network API.
	machineNetwork := &network.ContainerEngineNetwork{NetName: primaryNetworkName}
	var cidrs []network.ContainerEngineNetworkConfig
	for _, cidr := range infra.Spec.PlatformSpec.BareMetal.MachineNetworks {
		cidrs = append(cidrs, network.ContainerEngineNetworkConfig{Subnet: string(cidr)})
	}
	machineNetwork.Configs = cidrs
	ci.machineNetwork = machineNetwork

	v4, v6, err := ci.machineNetwork.IPv4IPv6Subnets()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve primary network subnets: %w", err)
	}
	// Retrieve primary network interface from hypervisor instance
	ci.machineNetworkGwInfo, err = findHypervisorNodeInterface(sshRunner, v4, v6)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve hypervisor node interface for machine network: %w", err)
	}
	return ci, nil
}

func (ci *baremetalInfra) GetNetwork(name string) (api.Network, error) {
	// Override "kind" network queries with the actual primary network name
	// FUP: remove the override once this is fixed appropriately in u/s E2Es.
	if name == "kind" {
		framework.Logf("overriding kind network with actual primary network name %s for the query", primaryNetworkName)
		name = primaryNetworkName
	}
	return ci.getNetwork(name)
}

func (ci *baremetalInfra) getNetwork(name string) (api.Network, error) {
	// check primary network first.
	if name == primaryNetworkName {
		return ci.machineNetwork, nil
	}
	// fall back into container networks.
	return ci.engine.GetNetwork(name)
}

func (ci *baremetalInfra) ExecExternalContainerCommand(container api.ExternalContainer, cmd []string) (string, error) {
	return ci.engine.ExecExternalContainerCommand(container, cmd)
}

func (ci *baremetalInfra) ExternalContainerPrimaryInterfaceName() string {
	return ci.engine.ExternalContainerPrimaryInterfaceName()
}

func (ci *baremetalInfra) GetExternalContainerLogs(container api.ExternalContainer) (string, error) {
	return ci.engine.GetExternalContainerLogs(container)
}

func (ci *baremetalInfra) GetExternalContainerPort() uint16 {
	return ci.engine.GetExternalContainerPort()
}

func (ci *baremetalInfra) ListNetworks() ([]string, error) {
	return ci.engine.ListNetworks()
}

func (ci *baremetalInfra) GetExternalContainerNetworkInterface(container api.ExternalContainer, network api.Network) (api.NetworkInterface, error) {
	if container.Name == externalFRRContainerName && network.Name() == primaryNetworkName {
		// frr container uses static ip configuration for ostestbm_net,
		// querying it with podman inspect returns empty values, so build
		// it explicitly.
		if ci.machineNetworkGwInfo == nil {
			return api.NetworkInterface{}, fmt.Errorf("can not find primary network gateway node for frr container")
		}
		return api.NetworkInterface{
				IPv4:        frrContainerPrimaryNetIPv4,
				IPv6:        frrContainerPrimaryNetIPv6,
				IPv4Gateway: ci.machineNetworkGwInfo.IPv4,
				IPv6Gateway: ci.machineNetworkGwInfo.IPv6,
				InfName:     "eth0",
				IPv4Prefix:  ci.machineNetworkGwInfo.IPv4Prefix,
				IPv6Prefix:  ci.machineNetworkGwInfo.IPv6Prefix},
			nil
	}
	return ci.engine.GetNetworkInterface(container.Name, network.Name())
}

func (ci *baremetalInfra) GetExternalContainerContextProvider(context *testcontext.TestContext) api.ExternalContainerContextProvider {
	ciWithTestContext := &baremetalInfra{
		engine: ci.engine.WithTestContext(context)}
	return ciWithTestContext
}

func (ci *baremetalInfra) CreateExternalContainer(container api.ExternalContainer) (api.ExternalContainer, error) {
	return ci.engine.CreateExternalContainer(container)
}

func (ci *baremetalInfra) DeleteExternalContainer(container api.ExternalContainer) error {
	return ci.engine.DeleteExternalContainer(container)
}

func (ci *baremetalInfra) CreateNetwork(name string, subnets ...string) (api.Network, error) {
	return ci.engine.CreateNetwork(name, subnets...)
}

func (ci *baremetalInfra) AttachNetwork(network api.Network, container string) (api.NetworkInterface, error) {
	return ci.engine.AttachNetwork(network, container)
}

func (ci *baremetalInfra) DetachNetwork(network api.Network, container string) error {
	return ci.engine.DetachNetwork(network, container)
}

func (ci *baremetalInfra) DeleteNetwork(network api.Network) error {
	return ci.engine.DeleteNetwork(network)
}

func hypervisorSshCmdRunner() (api.Runner, error) {
	// Read hypervisor IP from shared directory
	ip, err := readHypervisorIP()
	if err != nil {
		return nil, err
	}
	if ip == "" {
		return nil, nil // Not configured
	}

	// Find SSH key for hypervisor access
	sshKeyPath, err := findSSHKeyPath()
	if err != nil {
		return nil, err
	}
	if sshKeyPath == "" {
		return nil, nil // Not configured
	}

	sshRunner, err := runner.NewSSHRunner(ip, hypervisorNodeUser, hypervisorSshport, sshKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create ssh runner for hypervisor: %w", err)
	}

	return sshRunner, nil
}

// readHypervisorIP reads the hypervisor IP from the SHARED_DIR/server-ip file.
// Returns empty string if not configured, error if misconfigured.
func readHypervisorIP() (string, error) {
	sharedDir := os.Getenv("SHARED_DIR")
	if sharedDir == "" {
		return "", nil
	}

	ipFile := filepath.Join(sharedDir, "server-ip")
	exists, err := fileExists(ipFile)
	if err != nil {
		return "", fmt.Errorf("failed to check hypervisor ip file: %w", err)
	}
	if !exists {
		return "", nil
	}

	data, err := os.ReadFile(ipFile)
	if err != nil {
		return "", fmt.Errorf("failed to read hypervisor ip file: %w", err)
	}

	ip := strings.TrimSpace(string(data))
	if ip == "" {
		return "", fmt.Errorf("hypervisor ip file is empty")
	}

	return ip, nil
}

// findSSHKeyPath locates the SSH private key file for hypervisor access.
// Tries equinix-ssh-key first, falls back to packet-ssh-key.
// Returns empty string if not configured, error if misconfigured.
func findSSHKeyPath() (string, error) {
	clusterProfileDir := os.Getenv("CLUSTER_PROFILE_DIR")
	if clusterProfileDir == "" {
		return "", nil
	}

	// Try equinix-ssh-key first
	equinixKey := filepath.Join(clusterProfileDir, "equinix-ssh-key")
	exists, err := fileExists(equinixKey)
	if err != nil {
		return "", fmt.Errorf("failed to check equinix-ssh-key: %w", err)
	}
	if exists {
		return equinixKey, nil
	}

	// Fall back to packet-ssh-key
	packetKey := filepath.Join(clusterProfileDir, "packet-ssh-key")
	exists, err = fileExists(packetKey)
	if err != nil {
		return "", fmt.Errorf("failed to check packet-ssh-key: %w", err)
	}
	if exists {
		return packetKey, nil
	}

	return "", nil
}

// fileExists checks if a file exists and is accessible.
// Returns (false, nil) if file doesn't exist, (false, error) for access errors.
func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

type linkInfo struct {
	IfName   string          `json:"ifname"`
	Mac      string          `json:"address"`
	AddrInfo []ipAddressInfo `json:"addr_info"`
}

type ipAddressInfo struct {
	Family string `json:"family"`
	Local  string `json:"local"`
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
