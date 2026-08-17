package infraprovider

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/container"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/testcontext"
	"k8s.io/kubernetes/test/e2e/framework"
)

const containerRuntime = "podman"

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
func (h *baseInfra) getOrCreateHostNetworkedContainer(ec api.ExternalContainer) (api.ExternalContainer, error) {
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
	// Populate IPs from the host's primary network interface.
	if h.hostNetworkInfo == nil {
		return api.ExternalContainer{}, fmt.Errorf("no host network info available for host-networked container %q", ec.Name)
	}
	ec.IPv4 = h.hostNetworkInfo.IPv4
	ec.IPv6 = h.hostNetworkInfo.IPv6

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
		return p.parent.getOrCreateHostNetworkedContainer(ec)
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
