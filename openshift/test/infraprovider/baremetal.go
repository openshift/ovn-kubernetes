package infraprovider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	configv1 "github.com/openshift/api/config/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	allocator "github.com/ovn-kubernetes/ovn-kubernetes/openshift/test/allocator"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/allocators"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/container"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/container/network"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/runner"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/testcontext"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
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

const (
	ipvlanPrimaryNetNameIPv4      = "ostestbm-ipvlan-v4"
	ipvlanPrimaryNetNameIPv6      = "ostestbm-ipvlan-v6"
	ipvlanPrimaryNetNameDualStack = "ostestbm-ipvlan-dual"
	// Ipvlan uses separate subnet from machine network to avoid IP allocation conflicts
	// Machine network: 192.168.111.0/24, Ipvlan network: 192.168.112.0/24
	ipvlanPrimaryNetIPv4        = "192.168.112.0/24"
	ipvlanPrimaryNetIPv4Gateway = "192.168.112.1"
	// IPv6 subnet for ipvlan (fd2e:6f44:5dd8:c957::/120) is separate from
	// machine network IPv6 subnet (fd2e:6f44:5dd8:c956::/120)
	ipvlanPrimaryNetIPv6        = "fd2e:6f44:5dd8:c957::/120"
	ipvlanPrimaryNetIPv6Gateway = "fd2e:6f44:5dd8:c957::1"
)

const (
	// VNI valid range is 1-16777215 (24-bit)
	vniMax          = 16777215
	infraNetworkKey = "ocp-infra-network"
)

// networkState contains state shared across baremetalInfra clones created by GetExternalContainerContextProvider.
// All map access must be protected by the mutex.
type networkState struct {
	sync.Mutex                                                            // protects networkVNIMap and containerNetworkInterfaces
	networkVNIMap              map[string]int                             // maps network name to VNI for VXLAN overlay networks
	containerNetworkInterfaces map[string]map[string]api.NetworkInterface // containerName -> networkName -> interface info
}

type baremetalInfra struct {
	kubeClient                        kubernetes.Interface
	testContext                       *testcontext.TestContext
	engine                            *container.Engine
	runner                            api.Runner            // SSH runner for executing commands on hypervisor
	machineNetwork                    api.Network           // contains subnet details about cluster machine network
	machineNetworkGwInfo              *api.NetworkInterface // contains interface info about hypervisor node machine network interface
	primaryNetworkBackendForContainer api.Network           // ipvlan network which is a container network backend for cluster machine network
	networkState                      *networkState         // shared state across clones
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
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve kubernetes client: %w", err)
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
	ci := &baremetalInfra{
		kubeClient: kubeClient,
		networkState: &networkState{
			networkVNIMap:              make(map[string]int),
			containerNetworkInterfaces: make(map[string]map[string]api.NetworkInterface),
		},
	}
	// Verify SSH connectivity works
	if _, err := sshRunner.Run("echo", "connection test"); err != nil {
		return nil, fmt.Errorf("failed to check frr container status, connectivity check failed with hypervisor: %w", err)
	}
	// Initialize podman container engine
	ci.engine = container.NewEngine("podman", sshRunner)
	ci.runner = sshRunner
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
	// Create ipvlan network based on IP family configuration
	if ci.machineNetworkGwInfo.IPv4 != "" && ci.machineNetworkGwInfo.IPv6 != "" {
		// Dual-stack configuration
		if err := createIpvlanNetwork(sshRunner, ipvlanPrimaryNetNameDualStack, ci.machineNetworkGwInfo.InfName,
			ipvlanPrimaryNetIPv4, ipvlanPrimaryNetIPv4Gateway,
			ipvlanPrimaryNetIPv6, ipvlanPrimaryNetIPv6Gateway); err != nil {
			return nil, fmt.Errorf("failed to create dual-stack ipvlan container network for primary machine network: %w", err)
		}
		ci.primaryNetworkBackendForContainer = &network.ContainerEngineNetwork{NetName: ipvlanPrimaryNetNameDualStack,
			Configs: []network.ContainerEngineNetworkConfig{
				{Subnet: ipvlanPrimaryNetIPv4, Gateway: ipvlanPrimaryNetIPv4Gateway},
				{Subnet: ipvlanPrimaryNetIPv6, Gateway: ipvlanPrimaryNetIPv6Gateway}}}
	} else if ci.machineNetworkGwInfo.IPv6 != "" {
		// IPv6-only configuration
		if err := createIpvlanNetwork(sshRunner, ipvlanPrimaryNetNameIPv6, ci.machineNetworkGwInfo.InfName,
			"", "", ipvlanPrimaryNetIPv6, ipvlanPrimaryNetIPv6Gateway); err != nil {
			return nil, fmt.Errorf("failed to create IPv6 ipvlan container network for primary machine network: %w", err)
		}
		ci.primaryNetworkBackendForContainer = &network.ContainerEngineNetwork{NetName: ipvlanPrimaryNetNameIPv6,
			Configs: []network.ContainerEngineNetworkConfig{{Subnet: ipvlanPrimaryNetIPv6, Gateway: ipvlanPrimaryNetIPv6Gateway}}}
	} else if ci.machineNetworkGwInfo.IPv4 != "" {
		// IPv4-only configuration
		if err := createIpvlanNetwork(sshRunner, ipvlanPrimaryNetNameIPv4, ci.machineNetworkGwInfo.InfName,
			ipvlanPrimaryNetIPv4, ipvlanPrimaryNetIPv4Gateway, "", ""); err != nil {
			return nil, fmt.Errorf("failed to create IPv4 ipvlan container network for primary machine network: %w", err)
		}
		ci.primaryNetworkBackendForContainer = &network.ContainerEngineNetwork{NetName: ipvlanPrimaryNetNameIPv4,
			Configs: []network.ContainerEngineNetworkConfig{{Subnet: ipvlanPrimaryNetIPv4, Gateway: ipvlanPrimaryNetIPv4Gateway}}}
	}
	return ci, nil
}

// createIpvlanNetwork creates an ipvlan L3 network with the specified configuration.
// It checks if the network already exists to support idempotent initialization.
// For IPv4-only, pass empty strings for v6Subnet and v6Gateway.
// For IPv6-only, pass empty strings for v4Subnet and v4Gateway.
func createIpvlanNetwork(runner api.Runner, networkName, parentInterface, v4Subnet, v4Gateway, v6Subnet, v6Gateway string) error {
	// Check if network already exists (idempotency)
	existingNets, err := runner.Run("podman", "network", "ls", "--format", "{{.Name}}")
	if err != nil {
		return fmt.Errorf("failed to list existing networks: %w", err)
	}
	if slices.Contains(strings.Split(strings.TrimSpace(existingNets), "\n"), networkName) {
		framework.Logf("ipvlan network %s already exists, skipping creation", networkName)
		return nil
	}

	// Build podman network create command
	args := []string{"network", "create", "-d", "ipvlan"}

	// Add IPv4 configuration if provided
	if v4Subnet != "" {
		args = append(args, fmt.Sprintf("--subnet=%s", v4Subnet))
		args = append(args, fmt.Sprintf("--gateway=%s", v4Gateway))
	}

	// Add IPv6 configuration if provided
	if v6Subnet != "" {
		args = append(args, fmt.Sprintf("--subnet=%s", v6Subnet))
		args = append(args, fmt.Sprintf("--gateway=%s", v6Gateway))
		args = append(args, "--ipv6")
	}

	// Add ipvlan-specific options
	args = append(args, "-o", fmt.Sprintf("parent=%s", parentInterface))
	args = append(args, "-o", "mode=l3")
	args = append(args, networkName)

	// Create the network
	if _, err := runner.Run("podman", args...); err != nil {
		return fmt.Errorf("failed to create ipvlan network %s: %w", networkName, err)
	}

	framework.Logf("created ipvlan L3 network %s (parent: %s, v4: %s, v6: %s)",
		networkName, parentInterface, v4Subnet, v6Subnet)
	return nil
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
	} else if network.Name() == primaryNetworkName {
		network = ci.primaryNetworkBackendForContainer
		return ci.engine.GetNetworkInterface(container.Name, network.Name())
	}

	// Check if this is a VXLAN overlay network
	ci.networkState.Lock()
	netInterface, ok := ci.networkState.containerNetworkInterfaces[container.Name][network.Name()]
	ci.networkState.Unlock()

	if ok {
		return netInterface, nil
	}

	// Fall back to engine for other networks
	return ci.engine.GetNetworkInterface(container.Name, network.Name())
}

func (ci *baremetalInfra) GetExternalContainerContextProvider(context *testcontext.TestContext) api.ExternalContainerContextProvider {
	ciWithTestContext := &baremetalInfra{
		testContext:                       context,
		engine:                            ci.engine.WithTestContext(context),
		kubeClient:                        ci.kubeClient,
		runner:                            ci.runner,
		machineNetwork:                    ci.machineNetwork,
		machineNetworkGwInfo:              ci.machineNetworkGwInfo,
		primaryNetworkBackendForContainer: ci.primaryNetworkBackendForContainer,
		networkState:                      ci.networkState, // Share the same state and mutex across clones
	}
	return ciWithTestContext
}

func (ci *baremetalInfra) CreateExternalContainer(container api.ExternalContainer) (api.ExternalContainer, error) {
	var networkToBeAttached api.Network
	if container.Network != nil && container.Network.Name() == primaryNetworkName {
		container.Network = ci.primaryNetworkBackendForContainer
	} else if container.Network != nil {
		networkToBeAttached = container.Network
		// for other networks, let's create container first and plump the network afterwards.
		container.Network = nil
	}
	container, err := ci.engine.CreateExternalContainer(container)
	if err != nil {
		return container, err
	}
	if networkToBeAttached == nil {
		return container, nil
	}

	// Attach VXLAN overlay network to container
	netInterface, err := ci.attachVXLANNetwork(networkToBeAttached, container.Name)
	if err != nil {
		if delErr := ci.engine.DeleteExternalContainer(container); delErr != nil {
			return container, fmt.Errorf("failed to attach network %s to container %s: %w (rollback delete failed: %v)",
				networkToBeAttached.Name(), container.Name, err, delErr)
		}
		return container, fmt.Errorf("failed to attach network %s to container %s: %w", networkToBeAttached.Name(), container.Name, err)
	}

	// Assign allocated IPs to container
	container.IPv4 = netInterface.IPv4
	container.IPv6 = netInterface.IPv6

	return container, nil
}

func (ci *baremetalInfra) DeleteExternalContainer(container api.ExternalContainer) error {
	return ci.engine.DeleteExternalContainer(container)
}

func (ci *baremetalInfra) CreateNetwork(name string, subnets ...string) (api.Network, error) {
	vni, err := allocators.AllocateInt(ci.kubeClient, infraNetworkKey, vniMax)
	if err != nil {
		return nil, fmt.Errorf("VNI allocation failed for network %s: %w", name, err)
	}
	ci.testContext.AddCleanUpFn(func() error {
		return allocators.DeallocateInt(ci.kubeClient, infraNetworkKey, vni)
	})

	// Parse subnets - expecting at most 2 subnets (IPv4 and/or IPv6)
	var ipv4Subnet, ipv6Subnet string
	var ipv4Gateway, ipv6Gateway string

	for _, subnet := range subnets {
		ip, ipNet, err := net.ParseCIDR(subnet)
		if err != nil {
			return nil, fmt.Errorf("failed to parse subnet %s: %w", subnet, err)
		}
		// Calculate gateway IP (first IP in subnet)
		gateway := incrementIP(ipNet.IP)
		prefixLen := maskBits(ipNet.Mask)
		gatewayWithPrefix := fmt.Sprintf("%s/%d", gateway.String(), prefixLen)

		if ip.To4() != nil {
			ipv4Subnet = subnet
			ipv4Gateway = gatewayWithPrefix
		} else {
			ipv6Subnet = subnet
			ipv6Gateway = gatewayWithPrefix
		}
	}

	// Get bridge and VXLAN interface names from VNI
	bridgeName := vxlanBridgeName(vni)
	vxlanName := vxlanInterfaceName(vni)

	// Create Linux bridge
	if _, err := ci.runner.Run("ip", "link", "add", bridgeName, "type", "bridge"); err != nil {
		return nil, fmt.Errorf("failed to create bridge %s: %w", bridgeName, err)
	}

	// Configure IPv4 gateway on bridge if present
	if ipv4Subnet != "" {
		if _, err := ci.runner.Run("ip", "addr", "add", ipv4Gateway, "dev", bridgeName); err != nil {
			ci.runner.Run("ip", "link", "delete", bridgeName)
			return nil, fmt.Errorf("failed to add IPv4 address to bridge %s: %w", bridgeName, err)
		}
	}

	// Configure IPv6 gateway on bridge if present
	if ipv6Subnet != "" {
		if _, err := ci.runner.Run("ip", "-6", "addr", "add", ipv6Gateway, "dev", bridgeName); err != nil {
			ci.runner.Run("ip", "link", "delete", bridgeName)
			return nil, fmt.Errorf("failed to add IPv6 address to bridge %s: %w", bridgeName, err)
		}
	}

	// Bring up bridge
	if _, err := ci.runner.Run("ip", "link", "set", bridgeName, "up"); err != nil {
		ci.runner.Run("ip", "link", "delete", bridgeName)
		return nil, fmt.Errorf("failed to bring up bridge %s: %w", bridgeName, err)
	}

	// Determine local VTEP IP (prefer IPv4 if available, otherwise IPv6)
	localVTEP := ci.machineNetworkGwInfo.IPv4
	if localVTEP == "" {
		localVTEP = ci.machineNetworkGwInfo.IPv6
	}

	// Create VXLAN interface
	vxlanArgs := []string{
		"link", "add", vxlanName, "type", "vxlan",
		"id", fmt.Sprintf("%d", vni),
		"local", localVTEP,
		"dstport", "5789",
		"nolearning",
		"dev", ci.machineNetworkGwInfo.InfName,
	}
	if _, err := ci.runner.Run("ip", vxlanArgs...); err != nil {
		ci.runner.Run("ip", "link", "delete", bridgeName)
		return nil, fmt.Errorf("failed to create VXLAN interface %s: %w", vxlanName, err)
	}

	// Attach VXLAN interface to bridge
	if _, err := ci.runner.Run("ip", "link", "set", vxlanName, "master", bridgeName); err != nil {
		ci.runner.Run("ip", "link", "delete", vxlanName)
		ci.runner.Run("ip", "link", "delete", bridgeName)
		return nil, fmt.Errorf("failed to attach VXLAN %s to bridge %s: %w", vxlanName, bridgeName, err)
	}

	// Bring up VXLAN interface
	if _, err := ci.runner.Run("ip", "link", "set", vxlanName, "up"); err != nil {
		ci.runner.Run("ip", "link", "delete", vxlanName)
		ci.runner.Run("ip", "link", "delete", bridgeName)
		return nil, fmt.Errorf("failed to bring up VXLAN interface %s: %w", vxlanName, err)
	}

	// Store VNI mapping for later use in network attachment
	ci.networkState.Lock()
	ci.networkState.networkVNIMap[name] = vni
	ci.networkState.Unlock()

	// Add cleanup for VXLAN and bridge
	ci.testContext.AddCleanUpFn(func() error {
		ci.runner.Run("ip", "link", "delete", vxlanName)
		ci.runner.Run("ip", "link", "delete", bridgeName)
		ci.networkState.Lock()
		delete(ci.networkState.networkVNIMap, name)
		ci.networkState.Unlock()
		return nil
	})

	framework.Logf("created VXLAN overlay network %s (bridge: %s, vxlan: %s, vni: %d, local: %s, dev: %s)",
		name, bridgeName, vxlanName, vni, localVTEP, ci.machineNetworkGwInfo.InfName)

	// Build and return network object
	vxlanNetwork := &network.ContainerEngineNetwork{NetName: name}
	var configs []network.ContainerEngineNetworkConfig

	if ipv4Subnet != "" {
		// Extract gateway IP without prefix for the config
		gateway := strings.Split(ipv4Gateway, "/")[0]
		configs = append(configs, network.ContainerEngineNetworkConfig{
			Subnet:  ipv4Subnet,
			Gateway: gateway,
		})
	}

	if ipv6Subnet != "" {
		// Extract gateway IP without prefix for the config
		gateway := strings.Split(ipv6Gateway, "/")[0]
		configs = append(configs, network.ContainerEngineNetworkConfig{
			Subnet:  ipv6Subnet,
			Gateway: gateway,
		})
	}

	vxlanNetwork.Configs = configs

	return vxlanNetwork, nil
}

func (ci *baremetalInfra) AttachNetwork(network api.Network, container string) (api.NetworkInterface, error) {
	if network.Name() == primaryNetworkName {
		return ci.engine.AttachNetwork(ci.primaryNetworkBackendForContainer, container)
	}
	// Attach VXLAN overlay network using veth pairs
	return ci.attachVXLANNetwork(network, container)
}

func (ci *baremetalInfra) DetachNetwork(network api.Network, container string) error {
	if network.Name() == primaryNetworkName {
		return ci.engine.DetachNetwork(ci.primaryNetworkBackendForContainer, container)
	}
	// Detach VXLAN overlay network
	return ci.detachVXLANNetwork(network.Name(), container)
}

func (ci *baremetalInfra) DeleteNetwork(network api.Network) error {
	// Check if this is a VXLAN overlay network
	ci.networkState.Lock()
	vni, ok := ci.networkState.networkVNIMap[network.Name()]
	ci.networkState.Unlock()

	if ok {
		// Delete VXLAN overlay infrastructure
		vxlanName := vxlanInterfaceName(vni)
		bridgeName := vxlanBridgeName(vni)

		// Delete VXLAN interface
		if _, err := ci.runner.Run("ip", "link", "delete", vxlanName); err != nil {
			framework.Logf("Warning: failed to delete VXLAN interface %s: %v", vxlanName, err)
		}

		// Delete bridge
		if _, err := ci.runner.Run("ip", "link", "delete", bridgeName); err != nil {
			framework.Logf("Warning: failed to delete bridge %s: %v", bridgeName, err)
		}

		// Remove from VNI map
		ci.networkState.Lock()
		delete(ci.networkState.networkVNIMap, network.Name())
		ci.networkState.Unlock()

		framework.Logf("deleted VXLAN overlay network %s (bridge: %s, vxlan: %s, vni: %d)",
			network.Name(), bridgeName, vxlanName, vni)

		return nil
	}

	// Not a VXLAN overlay network, delegate to engine
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

// incrementIP returns the next IP address by incrementing the given IP by 1.
// This is used to calculate the gateway IP as the first usable IP in a subnet.
func incrementIP(ip net.IP) net.IP {
	result := make(net.IP, len(ip))
	copy(result, ip)
	for i := len(result) - 1; i >= 0; i-- {
		result[i]++
		if result[i] != 0 {
			break
		}
	}
	return result
}

// maskBits returns the number of bits set in the network mask.
func maskBits(mask net.IPMask) int {
	ones, _ := mask.Size()
	return ones
}

// vxlanBridgeName returns the bridge name for a given VNI.
// Bridge names are limited to 15 characters by Linux kernel.
func vxlanBridgeName(vni int) string {
	return fmt.Sprintf("tbr%d", vni)
}

// vxlanInterfaceName returns the VXLAN interface name for a given VNI.
// Interface names are limited to 15 characters by Linux kernel.
func vxlanInterfaceName(vni int) string {
	return fmt.Sprintf("tvx%d", vni)
}

// vethHostName returns the host-side veth name (vh<hash><vni>, max 14 chars).
func vethHostName(containerName string, vni int) string {
	hash := containerNameHash(containerName)
	return fmt.Sprintf("vh%s%d", hash, vni)
}

// vethContainerName returns the container-side veth name (vc<hash><vni>, max 14 chars).
func vethContainerName(containerName string, vni int) string {
	hash := containerNameHash(containerName)
	return fmt.Sprintf("vc%s%d", hash, vni)
}

// containerNameHash returns a 4-character hex hash of the container name.
func containerNameHash(name string) string {
	h := sha256.Sum256([]byte(name))
	return hex.EncodeToString(h[:])[:4]
}

// attachVXLANNetwork attaches a VXLAN overlay network to a container using veth pairs.
// It allocates IPs from the network subnets (excluding gateway IPs), creates veth pair,
// attaches host-side to bridge, moves container-side into container namespace, and configures routing.
func (ci *baremetalInfra) attachVXLANNetwork(network api.Network, containerName string) (api.NetworkInterface, error) {
	// Get VNI for this network
	ci.networkState.Lock()
	vni, ok := ci.networkState.networkVNIMap[network.Name()]
	ci.networkState.Unlock()

	if !ok {
		return api.NetworkInterface{}, fmt.Errorf("VNI not found for network %s", network.Name())
	}

	// Get bridge name for this VNI
	bridgeName := vxlanBridgeName(vni)

	// Get veth interface names
	vethHost := vethHostName(containerName, vni)
	vethCont := vethContainerName(containerName, vni)

	// Get container PID
	pidStr, err := ci.runner.Run("podman", "inspect", "-f", "{{.State.Pid}}", containerName)
	if err != nil {
		return api.NetworkInterface{}, fmt.Errorf("failed to get container PID for %s: %w", containerName, err)
	}
	containerPID := strings.TrimSpace(pidStr)

	// Get network subnets
	ipv4Subnet, ipv6Subnet, err := network.IPv4IPv6Subnets()
	if err != nil {
		return api.NetworkInterface{}, fmt.Errorf("failed to get network subnets for %s: %w", network.Name(), err)
	}

	netInterface := api.NetworkInterface{InfName: vethCont}

	// Allocate IPv4 address if IPv4 subnet exists
	if ipv4Subnet != "" {
		// Get gateway IP to reserve it
		_, ipv4Net, err := net.ParseCIDR(ipv4Subnet)
		if err != nil {
			return api.NetworkInterface{}, fmt.Errorf("failed to parse IPv4 subnet %s: %w", ipv4Subnet, err)
		}
		gatewayIP := incrementIP(ipv4Net.IP).String()

		// Allocate IP from subnet excluding gateway
		allocatedIP, err := allocator.AllocateIPWithReserved(ci.kubeClient, ci.testContext, ipv4Subnet, []string{gatewayIP})
		if err != nil {
			return api.NetworkInterface{}, fmt.Errorf("failed to allocate IPv4 from %s: %w", ipv4Subnet, err)
		}
		netInterface.IPv4 = allocatedIP
		netInterface.IPv4Gateway = gatewayIP
		netInterface.IPv4Prefix = ipv4Subnet
	}

	// Allocate IPv6 address if IPv6 subnet exists
	if ipv6Subnet != "" {
		// Get gateway IP to reserve it
		_, ipv6Net, err := net.ParseCIDR(ipv6Subnet)
		if err != nil {
			return api.NetworkInterface{}, fmt.Errorf("failed to parse IPv6 subnet %s: %w", ipv6Subnet, err)
		}
		gatewayIP := incrementIP(ipv6Net.IP).String()

		// Allocate IP from subnet excluding gateway
		allocatedIP, err := allocator.AllocateIPv6WithReserved(ci.kubeClient, ci.testContext, ipv6Subnet, []string{gatewayIP})
		if err != nil {
			return api.NetworkInterface{}, fmt.Errorf("failed to allocate IPv6 from %s: %w", ipv6Subnet, err)
		}
		netInterface.IPv6 = allocatedIP
		netInterface.IPv6Gateway = gatewayIP
		netInterface.IPv6Prefix = ipv6Subnet
	}

	// Create veth pair
	if _, err := ci.runner.Run("ip", "link", "add", vethHost, "type", "veth", "peer", "name", vethCont); err != nil {
		return api.NetworkInterface{}, fmt.Errorf("failed to create veth pair %s/%s: %w", vethHost, vethCont, err)
	}

	// Attach host-side veth to bridge
	if _, err := ci.runner.Run("ip", "link", "set", vethHost, "master", bridgeName); err != nil {
		ci.runner.Run("ip", "link", "delete", vethHost)
		return api.NetworkInterface{}, fmt.Errorf("failed to attach %s to bridge %s: %w", vethHost, bridgeName, err)
	}

	// Bring up host-side veth
	if _, err := ci.runner.Run("ip", "link", "set", vethHost, "up"); err != nil {
		ci.runner.Run("ip", "link", "delete", vethHost)
		return api.NetworkInterface{}, fmt.Errorf("failed to bring up %s: %w", vethHost, err)
	}

	// Move container-side veth into container namespace
	if _, err := ci.runner.Run("ip", "link", "set", vethCont, "netns", containerPID); err != nil {
		ci.runner.Run("ip", "link", "delete", vethHost)
		return api.NetworkInterface{}, fmt.Errorf("failed to move %s to container namespace: %w", vethCont, err)
	}

	// Configure IPv4 address in container if allocated
	if netInterface.IPv4 != "" {
		_, ipv4Net, _ := net.ParseCIDR(ipv4Subnet)
		prefixLen := maskBits(ipv4Net.Mask)
		ipWithPrefix := fmt.Sprintf("%s/%d", netInterface.IPv4, prefixLen)
		if _, err := ci.runner.Run("nsenter", "-t", containerPID, "-n", "ip", "addr", "add", ipWithPrefix, "dev", vethCont); err != nil {
			ci.runner.Run("ip", "link", "delete", vethHost)
			return api.NetworkInterface{}, fmt.Errorf("failed to configure IPv4 %s on %s: %w", ipWithPrefix, vethCont, err)
		}
	}

	// Configure IPv6 address in container if allocated
	if netInterface.IPv6 != "" {
		_, ipv6Net, _ := net.ParseCIDR(ipv6Subnet)
		prefixLen := maskBits(ipv6Net.Mask)
		ipWithPrefix := fmt.Sprintf("%s/%d", netInterface.IPv6, prefixLen)
		if _, err := ci.runner.Run("nsenter", "-t", containerPID, "-n", "ip", "addr", "add", ipWithPrefix, "dev", vethCont); err != nil {
			ci.runner.Run("ip", "link", "delete", vethHost)
			return api.NetworkInterface{}, fmt.Errorf("failed to configure IPv6 %s on %s: %w", ipWithPrefix, vethCont, err)
		}
	}

	// Bring up container-side veth
	if _, err := ci.runner.Run("nsenter", "-t", containerPID, "-n", "ip", "link", "set", vethCont, "up"); err != nil {
		ci.runner.Run("ip", "link", "delete", vethHost)
		return api.NetworkInterface{}, fmt.Errorf("failed to bring up %s in container: %w", vethCont, err)
	}

	// Bring up loopback
	if _, err := ci.runner.Run("nsenter", "-t", containerPID, "-n", "ip", "link", "set", "lo", "up"); err != nil {
		ci.runner.Run("ip", "link", "delete", vethHost)
		return api.NetworkInterface{}, fmt.Errorf("failed to bring up loopback in container: %w", err)
	}

	// Add default routes via the veth interface
	if netInterface.IPv4 != "" {
		if _, err := ci.runner.Run("nsenter", "-t", containerPID, "-n", "ip", "-4", "route", "add", "default", "dev", vethCont); err != nil {
			ci.runner.Run("ip", "link", "delete", vethHost)
			return api.NetworkInterface{}, fmt.Errorf("failed to add IPv4 default route in container: %w", err)
		}
	}

	if netInterface.IPv6 != "" {
		if _, err := ci.runner.Run("nsenter", "-t", containerPID, "-n", "ip", "-6", "route", "add", "default", "dev", vethCont); err != nil {
			ci.runner.Run("ip", "link", "delete", vethHost)
			return api.NetworkInterface{}, fmt.Errorf("failed to add IPv6 default route in container: %w", err)
		}
	}

	// Store network interface info for GetExternalContainerNetworkInterface
	ci.networkState.Lock()
	if ci.networkState.containerNetworkInterfaces[containerName] == nil {
		ci.networkState.containerNetworkInterfaces[containerName] = make(map[string]api.NetworkInterface)
	}
	ci.networkState.containerNetworkInterfaces[containerName][network.Name()] = netInterface
	ci.networkState.Unlock()

	// Add cleanup to delete veth pair
	ci.testContext.AddCleanUpFn(func() error {
		if _, err := ci.runner.Run("ip", "link", "delete", vethHost); err != nil {
			framework.Logf("Warning: failed to delete veth %s: %v", vethHost, err)
		}
		// Clean up stored interface info
		ci.networkState.Lock()
		if ci.networkState.containerNetworkInterfaces[containerName] != nil {
			delete(ci.networkState.containerNetworkInterfaces[containerName], network.Name())
			if len(ci.networkState.containerNetworkInterfaces[containerName]) == 0 {
				delete(ci.networkState.containerNetworkInterfaces, containerName)
			}
		}
		ci.networkState.Unlock()
		return nil
	})

	framework.Logf("attached VXLAN network %s to container %s (veth: %s/%s, IPv4: %s, IPv6: %s)",
		network.Name(), containerName, vethHost, vethCont, netInterface.IPv4, netInterface.IPv6)

	return netInterface, nil
}

// detachVXLANNetwork detaches a VXLAN overlay network from a container by deleting the veth pair.
func (ci *baremetalInfra) detachVXLANNetwork(networkName, containerName string) error {
	ci.networkState.Lock()
	vni, ok := ci.networkState.networkVNIMap[networkName]
	ci.networkState.Unlock()

	if !ok {
		return fmt.Errorf("VNI not found for network %s", networkName)
	}

	// Delete veth pair
	vethHost := vethHostName(containerName, vni)
	if _, err := ci.runner.Run("ip", "link", "delete", vethHost); err != nil {
		framework.Logf("Warning: failed to delete veth %s: %v", vethHost, err)
	}

	// Clean up stored interface info
	ci.networkState.Lock()
	if ci.networkState.containerNetworkInterfaces[containerName] != nil {
		delete(ci.networkState.containerNetworkInterfaces[containerName], networkName)
		if len(ci.networkState.containerNetworkInterfaces[containerName]) == 0 {
			delete(ci.networkState.containerNetworkInterfaces, containerName)
		}
	}
	ci.networkState.Unlock()

	framework.Logf("detached VXLAN network %s from container %s", networkName, containerName)
	return nil
}
