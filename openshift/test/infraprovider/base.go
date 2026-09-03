package infraprovider

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/container"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/container/network"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/runner"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/testcontext"
	"k8s.io/kubernetes/test/e2e/framework"
)

const (
	containerRuntime = "podman"
	// bastionPrimaryNetworkName is the primary network name for bastion-based
	// platforms (AWS, Azure, GCP) where containers use host networking.
	bastionPrimaryNetworkName = "host"
	bastionSSHPort            = "22"
)

// sudoRunner wraps a Runner and prepends "sudo" to every command.
// On bastion hosts (AWS, GCP, Azure) the SSH user is unprivileged (core),
// so rootless podman containers exit when the SSH session terminates.
// Running podman under sudo avoids this.
type sudoRunner struct {
	inner api.Runner
}

func (s *sudoRunner) Run(command string, args ...string) (string, error) {
	return s.inner.Run("sudo", append([]string{command}, args...)...)
}

// baseInfra provides shared infrastructure for platforms that manage
// external containers on a remote host via SSH + podman (e.g., baremetal, AWS).
type baseInfra struct {
	engine             *container.Engine
	runner             api.Runner
	machineNetwork     api.Network
	hostNetworkInfo    *api.NetworkInterface
	primaryNetworkName string
	mu                 sync.Mutex
	externalContainers map[string]api.ExternalContainer
}

func (h *baseInfra) PrimaryNetwork() (api.Network, error) {
	return h.machineNetwork, nil
}

func (h *baseInfra) GetNetwork(name string) (api.Network, error) {
	if name == h.primaryNetworkName {
		return h.machineNetwork, nil
	}
	return h.engine.GetNetwork(name)
}

func (h *baseInfra) ListNetworks() ([]string, error) {
	return h.engine.ListNetworks()
}

func (h *baseInfra) ExecExternalContainerCommand(container api.ExternalContainer, cmd []string) (string, error) {
	return h.engine.ExecExternalContainerCommand(container, cmd)
}

func (h *baseInfra) ExternalContainerPrimaryInterfaceName() string {
	return h.engine.ExternalContainerPrimaryInterfaceName()
}

func (h *baseInfra) GetExternalContainerLogs(container api.ExternalContainer) (string, error) {
	return h.engine.GetExternalContainerLogs(container)
}

func (h *baseInfra) GetExternalContainerPort() uint16 {
	return h.engine.GetExternalContainerPort()
}

func (h *baseInfra) GetExternalContainerNetworkInterface(ec api.ExternalContainer, network api.Network) (api.NetworkInterface, error) {
	h.mu.Lock()
	cached, isCached := h.externalContainers[ec.Name]
	h.mu.Unlock()
	if isCached && network.Name() == h.primaryNetworkName {
		if h.hostNetworkInfo == nil {
			return api.NetworkInterface{}, fmt.Errorf("can not find primary network interface info for cached container %q", ec.Name)
		}
		return api.NetworkInterface{
			IPv4:       cached.IPv4,
			IPv6:       cached.IPv6,
			IPv4Prefix: h.hostNetworkInfo.IPv4Prefix,
			IPv6Prefix: h.hostNetworkInfo.IPv6Prefix,
		}, nil
	}
	return h.engine.GetNetworkInterface(ec.Name, network.Name())
}

func (h *baseInfra) GetExternalContainerContextProvider(context *testcontext.TestContext) api.ExternalContainerContextProvider {
	return &baseContextProvider{
		parent: h,
		engine: h.engine.WithTestContext(context),
	}
}

// getOrCreateHostNetworkedContainer returns a cached host-networked container
// or creates one on the remote host using podman with --network host.
// These containers persist across the suite and are not cleaned up per-test.
func (h *baseInfra) getOrCreateHostNetworkedContainer(ec api.ExternalContainer, netInfo *api.NetworkInterface) (api.ExternalContainer, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if cached, ok := h.externalContainers[ec.Name]; ok {
		framework.Logf("reusing cached host-networked container %q", ec.Name)
		return cached, nil
	}

	// Check if container already exists in podman (from a previous suite run).
	if out, err := h.runner.Run(containerRuntime, "container", "inspect", "--format", "{{.State.Running}}", ec.Name); err == nil {
		running := strings.TrimSpace(out) == "true"
		if !running {
			framework.Logf("existing host-networked container %q is stopped, starting it", ec.Name)
			if _, err := h.runner.Run(containerRuntime, "start", ec.Name); err != nil {
				return api.ExternalContainer{}, fmt.Errorf("failed to start stopped host-networked container %q: %w", ec.Name, err)
			}
		}
		framework.Logf("found existing host-networked container %q from a previous run", ec.Name)
	} else {
		// Container does not exist; create it.
		cmd := []string{"run", "-itd", "--privileged", "--network", "host", "--name", ec.Name, "--hostname", ec.Name}
		cmd = append(cmd, ec.RuntimeArgs...)
		cmd = append(cmd, ec.Image)
		if len(ec.CmdArgs) > 0 {
			cmd = append(cmd, ec.CmdArgs...)
		}
		framework.Logf("creating host-networked container with command: %s %s", containerRuntime, strings.Join(cmd, " "))
		if _, err := h.runner.Run(containerRuntime, cmd...); err != nil {
			return api.ExternalContainer{}, fmt.Errorf("failed to create host-networked container %q: %w", ec.Name, err)
		}
	}
	// Populate IPs from the provided network interface.
	if netInfo == nil {
		return api.ExternalContainer{}, fmt.Errorf("no network info for host-networked container %q", ec.Name)
	}
	ec.IPv4 = netInfo.IPv4
	ec.IPv6 = netInfo.IPv6

	h.externalContainers[ec.Name] = ec
	return ec, nil
}

// baseContextProvider implements api.ExternalContainerContextProvider.
// For primary network containers, it delegates to the parent baseInfra's
// host-networked container cache. For secondary network containers, it
// delegates to the container engine (standard per-test lifecycle).
type baseContextProvider struct {
	parent *baseInfra
	engine *container.Engine
}

func (p *baseContextProvider) CreateExternalContainer(ec api.ExternalContainer) (api.ExternalContainer, error) {
	if ec.Network != nil && ec.Network.Name() == p.parent.primaryNetworkName {
		return p.parent.getOrCreateHostNetworkedContainer(ec, p.parent.hostNetworkInfo)
	}
	return p.engine.CreateExternalContainer(ec)
}

func (p *baseContextProvider) DeleteExternalContainer(ec api.ExternalContainer) error {
	p.parent.mu.Lock()
	_, cached := p.parent.externalContainers[ec.Name]
	p.parent.mu.Unlock()
	if cached {
		framework.Logf("skipping deletion of cached host-networked container %q", ec.Name)
		return nil
	}
	return p.engine.DeleteExternalContainer(ec)
}

func (p *baseContextProvider) CreateNetwork(name string, subnets ...string) (api.Network, error) {
	return p.engine.CreateNetwork(name, subnets...)
}

func (p *baseContextProvider) DeleteNetwork(network api.Network) error {
	return p.engine.DeleteNetwork(network)
}

func (p *baseContextProvider) AttachNetwork(network api.Network, instance string) (api.NetworkInterface, error) {
	state, err := p.engine.GetContainerState(instance)
	if err != nil {
		return api.NetworkInterface{}, fmt.Errorf("failed to check container %q existence: %w", instance, err)
	}
	if state == "" {
		framework.Logf("skipping AttachNetwork for %q: not a podman container", instance)
		return api.NetworkInterface{}, nil
	}
	return p.engine.AttachNetwork(network, instance)
}

func (p *baseContextProvider) DetachNetwork(network api.Network, instance string) error {
	return p.engine.DetachNetwork(network, instance)
}

// readSharedDirFile reads a trimmed string from a file in SHARED_DIR.
// Returns ("", nil) if SHARED_DIR is unset or the file does not exist.
func readSharedDirFile(filename, description string) (string, error) {
	sharedDir := os.Getenv("SHARED_DIR")
	if sharedDir == "" {
		return "", nil
	}

	path := filepath.Join(sharedDir, filename)
	exists, err := fileExists(path)
	if err != nil {
		return "", fmt.Errorf("failed to check %s file: %w", description, err)
	}
	if !exists {
		return "", nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read %s file: %w", description, err)
	}

	value := strings.TrimSpace(string(data))
	if value == "" {
		return "", fmt.Errorf("%s file is empty", description)
	}

	return value, nil
}

// findClusterProfileFile locates the first existing file from filenames
// in CLUSTER_PROFILE_DIR. Returns ("", nil) if none found or dir unset.
func findClusterProfileFile(filenames ...string) (string, error) {
	clusterProfileDir := os.Getenv("CLUSTER_PROFILE_DIR")
	if clusterProfileDir == "" {
		return "", nil
	}

	for _, name := range filenames {
		path := filepath.Join(clusterProfileDir, name)
		exists, err := fileExists(path)
		if err != nil {
			return "", fmt.Errorf("failed to check %s: %w", name, err)
		}
		if exists {
			return path, nil
		}
	}
	return "", nil
}

// fileExists checks if a file exists and is accessible.
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

// initializeBastionInfra sets up a baseInfra by connecting to a bastion host
// via SSH and discovering its primary network interface. Used by cloud platforms
// (AWS, Azure, GCP) that share the same bastion-based external container pattern.
func initializeBastionInfra() (*baseInfra, error) {
	primaryNetworkName := bastionPrimaryNetworkName
	sshRunner, err := bastionSshCmdRunner()
	if err != nil {
		return nil, err
	}
	if sshRunner == nil {
		return nil, nil
	}

	// Verify SSH connectivity works
	if _, err := sshRunner.Run("echo", "connection test"); err != nil {
		return nil, fmt.Errorf("failed connectivity check with bastion host: %w", err)
	}

	// Wrap runner with sudo: the bastion SSH user (core) is unprivileged,
	// and rootless podman containers exit when the SSH session ends.
	podmanRunner := &sudoRunner{inner: sshRunner}
	h := &baseInfra{
		runner:             podmanRunner,
		externalContainers: make(map[string]api.ExternalContainer),
		engine:             container.NewEngine("podman", podmanRunner),
		primaryNetworkName: primaryNetworkName,
	}

	// Discover bastion host's primary network interface by finding the
	// interface that carries the default route.
	h.hostNetworkInfo, err = findDefaultRouteInterface(sshRunner)
	if err != nil {
		return nil, fmt.Errorf("failed to discover bastion host network interface: %w", err)
	}

	// Build primary network from bastion's interface prefixes.
	h.machineNetwork, err = buildMachineNetwork(primaryNetworkName, h.hostNetworkInfo)
	if err != nil {
		return nil, err
	}

	return h, nil
}

// buildMachineNetwork creates a ContainerEngineNetwork from interface prefixes.
func buildMachineNetwork(netName string, netInfo *api.NetworkInterface) (api.Network, error) {
	if netInfo == nil {
		return nil, fmt.Errorf("no network info available to build machine network")
	}
	machineNetwork := &network.ContainerEngineNetwork{NetName: netName}
	var cidrs []network.ContainerEngineNetworkConfig
	if netInfo.IPv4Prefix != "" {
		cidrs = append(cidrs, network.ContainerEngineNetworkConfig{Subnet: netInfo.IPv4Prefix})
	}
	if netInfo.IPv6Prefix != "" {
		cidrs = append(cidrs, network.ContainerEngineNetworkConfig{Subnet: netInfo.IPv6Prefix})
	}
	machineNetwork.Configs = cidrs
	return machineNetwork, nil
}

// findDefaultRouteInterface discovers the bastion's primary network interface
// by finding the interface that carries the default route.
func findDefaultRouteInterface(r api.Runner) (*api.NetworkInterface, error) {
	// Try IPv4 default route first, fall back to IPv6.
	devName, err := findDefaultRouteDev(r, "ip", "-j", "route", "show", "default")
	if err != nil {
		return nil, err
	}
	if devName == "" {
		devName, err = findDefaultRouteDev(r, "ip", "-j", "-6", "route", "show", "default")
		if err != nil {
			return nil, err
		}
	}
	if devName == "" {
		return nil, fmt.Errorf("no default route found (tried IPv4 and IPv6)")
	}

	// Get address info for that interface.
	addrOut, err := r.Run("ip", "-j", "addr", "show", "dev", devName)
	if err != nil {
		return nil, fmt.Errorf("failed to get address info for %s: %w", devName, err)
	}

	netInfo, err := parseInterfaceAddresses(devName, addrOut)
	if err != nil {
		return nil, err
	}
	return netInfo, nil
}

// findDefaultRouteDev runs an ip route command and extracts the device name
// from the route with the lowest metric. Returns ("", nil) when the command
// succeeds but no routes are present.
func findDefaultRouteDev(r api.Runner, cmd string, args ...string) (string, error) {
	out, err := r.Run(cmd, args...)
	if err != nil {
		return "", fmt.Errorf("failed to get default route: %w", err)
	}
	return extractDevFromRouteJSON(strings.TrimSpace(out))
}

// extractDevFromRouteJSON extracts the device name from ip -j route output.
// Returns ("", nil) when no routes are present. Uses the first entry since
// the kernel returns routes sorted by priority (lowest metric first).
func extractDevFromRouteJSON(jsonStr string) (string, error) {
	type routeEntry struct {
		Dev string `json:"dev"`
	}
	var routes []routeEntry
	if err := json.Unmarshal([]byte(jsonStr), &routes); err != nil {
		return "", fmt.Errorf("failed to parse route JSON: %w", err)
	}
	if len(routes) == 0 {
		return "", nil
	}
	if routes[0].Dev == "" {
		return "", fmt.Errorf("default route has no device")
	}
	return routes[0].Dev, nil
}

// parseInterfaceAddresses parses ip -j addr show output for a single interface
// and returns its IPv4/IPv6 addresses.
func parseInterfaceAddresses(devName, jsonStr string) (*api.NetworkInterface, error) {
	var links []linkInfo
	if err := json.Unmarshal([]byte(jsonStr), &links); err != nil {
		return nil, fmt.Errorf("failed to parse address info for %s: %w", devName, err)
	}
	if len(links) == 0 {
		return nil, fmt.Errorf("no address info found for interface %s", devName)
	}

	netInfo := &api.NetworkInterface{
		InfName: devName,
		MAC:     links[0].Mac,
	}
	for _, addr := range links[0].AddrInfo {
		switch addr.Family {
		case "inet":
			if netInfo.IPv4 == "" {
				netInfo.IPv4 = addr.Local
				netInfo.IPv4Prefix = fmt.Sprintf("%s/%d", addr.Local, addr.PrefixLen)
			}
		case "inet6":
			// Skip link-local addresses
			if netInfo.IPv6 == "" && !strings.HasPrefix(addr.Local, "fe80") {
				netInfo.IPv6 = addr.Local
				netInfo.IPv6Prefix = fmt.Sprintf("%s/%d", addr.Local, addr.PrefixLen)
			}
		}
	}
	return netInfo, nil
}

func bastionSshCmdRunner() (api.Runner, error) {
	// Read Bastion IP from shared directory
	ip, err := readSharedDirFile("bastion_public_address", "bastion ip")
	if err != nil {
		return nil, err
	}
	if ip == "" {
		return nil, nil
	}

	// Read SSH user for bastion host
	user, err := readSharedDirFile("bastion_ssh_user", "bastion ssh user")
	if err != nil {
		return nil, err
	}
	if user == "" {
		return nil, nil
	}

	// Find SSH key for bastion host access
	sshKeyPath, err := findClusterProfileFile("ssh-privatekey")
	if err != nil {
		return nil, err
	}
	if sshKeyPath == "" {
		return nil, nil
	}

	sshRunner, err := runner.NewSSHRunner(ip, user, bastionSSHPort, sshKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create ssh runner for bastion host: %w", err)
	}

	return sshRunner, nil
}

// linkInfo and ipAddressInfo are used for parsing ip -j addr output.
type linkInfo struct {
	IfName   string          `json:"ifname"`
	Mac      string          `json:"address"`
	AddrInfo []ipAddressInfo `json:"addr_info"`
}

type ipAddressInfo struct {
	Family    string `json:"family"`
	Local     string `json:"local"`
	PrefixLen int    `json:"prefixlen"`
}
