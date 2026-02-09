package infraprovider

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	ovnkconfig "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/container"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/portalloc"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/runner"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/testcontext"

	"github.com/onsi/ginkgo/v2"
	"k8s.io/client-go/rest"
	"k8s.io/kubernetes/test/e2e/framework"
)

const (
	hypervisorNodeUser = "root"
	hypervisorSshport  = "22"
)

type OpenshiftInfraProvider struct {
	engine   *container.Engine
	HostPort *portalloc.PortAllocator
}

func New(config *rest.Config) (*OpenshiftInfraProvider, error) {
	ovnkconfig.Kubernetes.DNSServiceNamespace = "openshift-dns"
	ovnkconfig.Kubernetes.DNSServiceName = "dns-default"
	// Initialize command runner for executing commands on hypervisor
	// (optional, may not be available)
	sshRunner, err := hypervisorSshCmdRunner()
	if err != nil {
		return nil, err
	}
	o := &OpenshiftInfraProvider{HostPort: portalloc.New(30000, 32767)}
	if sshRunner != nil {
		// Initialize podman container engine
		o.engine = container.NewEngine("podman", sshRunner)
	}
	return o, nil
}

func (o *OpenshiftInfraProvider) ShutdownNode(nodeName string) error {
	panic("not implemented")
}

func (o *OpenshiftInfraProvider) StartNode(nodeName string) error {
	panic("not implemented")
}

func (o *OpenshiftInfraProvider) GetDefaultTimeoutContext() *framework.TimeoutContext {
	timeouts := framework.NewTimeoutContext()
	timeouts.PodStart = 10 * time.Minute
	return timeouts
}

func (o OpenshiftInfraProvider) PreloadImages(images []string) {
	// no-op: OpenShift clusters pull images at runtime
}

func (o *OpenshiftInfraProvider) Name() string {
	return "openshift"
}

func (o *OpenshiftInfraProvider) PrimaryNetwork() (api.Network, error) {
	panic("not implemented")
}

func (o *OpenshiftInfraProvider) GetNetwork(name string) (api.Network, error) {
	return o.getNetwork(name)
}

func (o *OpenshiftInfraProvider) getNetwork(name string) (api.Network, error) {
	if o.engine == nil {
		return nil, fmt.Errorf("container engine not found, can not retrieve network %s", name)
	}
	return o.engine.GetNetwork(name)
}

func (o *OpenshiftInfraProvider) GetK8HostPort() uint16 {
	return o.HostPort.Allocate()
}

func (o *OpenshiftInfraProvider) GetK8NodeNetworkInterface(instance string, network api.Network) (api.NetworkInterface, error) {
	panic("not implemented")
}

func (o *OpenshiftInfraProvider) ExecK8NodeCommand(nodeName string, cmd []string) (string, error) {
	if len(cmd) == 0 {
		return "", fmt.Errorf("insufficient command arguments")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd = append([]string{"debug", fmt.Sprintf("node/%s", nodeName), "--to-namespace=default",
		"--", "chroot", "/host"}, cmd...)
	ocDebugCmd := exec.CommandContext(ctx, "oc", cmd...)
	var stdout, stderr bytes.Buffer
	ocDebugCmd.Stdout = &stdout
	ocDebugCmd.Stderr = &stderr

	if err := ocDebugCmd.Run(); err != nil {
		return "", fmt.Errorf("failed to run command %q on node %s: %v, stdout: %s, stderr: %s", ocDebugCmd.String(), nodeName, err, stdout.String(), stderr.String())
	}
	return stdout.String(), nil
}

func (o *OpenshiftInfraProvider) ExecExternalContainerCommand(container api.ExternalContainer, cmd []string) (string, error) {
	if o.engine == nil {
		return "", fmt.Errorf("container engine not found, can not execute command %v on the container %s", cmd, container.Name)
	}
	return o.engine.ExecExternalContainerCommand(container, cmd)
}

func (o *OpenshiftInfraProvider) ExternalContainerPrimaryInterfaceName() string {
	if o.engine == nil {
		panic("container engine not found, can not retrieve external container primary interface")
	}
	return o.engine.ExternalContainerPrimaryInterfaceName()
}

func (o *OpenshiftInfraProvider) GetExternalContainerLogs(container api.ExternalContainer) (string, error) {
	if o.engine == nil {
		return "", fmt.Errorf("container engine not found, can not retrieve logs from external container %s", container.Name)
	}
	return o.engine.GetExternalContainerLogs(container)
}

func (o *OpenshiftInfraProvider) GetExternalContainerNetworkInterface(container api.ExternalContainer, network api.Network) (api.NetworkInterface, error) {
	if o.engine == nil {
		return api.NetworkInterface{}, fmt.Errorf("container engine not found, can not retrieve network %s interface from container %s",
			network.Name(), container.Name)
	}
	return o.engine.GetExternalContainerNetworkInterface(container, network)
}

func (o *OpenshiftInfraProvider) GetExternalContainerPort() uint16 {
	if o.engine == nil {
		panic("container engine not found, can not allocate port for external container")
	}
	return o.engine.GetExternalContainerPort()
}

func (o *OpenshiftInfraProvider) ListNetworks() ([]string, error) {
	if o.engine == nil {
		return nil, fmt.Errorf("container engine not found, can not list networks")
	}
	return o.engine.ListNetworks()
}

func (o *OpenshiftInfraProvider) NewTestContext() api.Context {
	context := &testcontext.TestContext{}
	ginkgo.DeferCleanup(context.CleanUp)
	co := &contextOpenshift{
		TestContext: context,
		engine:      o.engine.WithTestContext(context),
	}
	return co
}

type contextOpenshift struct {
	*testcontext.TestContext
	engine *container.Engine
}

func (o *contextOpenshift) CreateExternalContainer(container api.ExternalContainer) (api.ExternalContainer, error) {
	if o.engine == nil {
		return api.ExternalContainer{},
			fmt.Errorf("container engine not found, can not create external container %s", container.Name)
	}
	return o.engine.CreateExternalContainer(container)
}

func (o *contextOpenshift) DeleteExternalContainer(container api.ExternalContainer) error {
	if o.engine == nil {
		return fmt.Errorf("container engine not found, can not delete external container %s", container.Name)
	}
	return o.engine.DeleteExternalContainer(container)
}

func (o *contextOpenshift) CreateNetwork(name string, subnets ...string) (api.Network, error) {
	if o.engine == nil {
		return nil, fmt.Errorf("container engine not found, can not create network %s", name)
	}
	return o.engine.CreateNetwork(name, subnets...)
}

func (o *contextOpenshift) AttachNetwork(network api.Network, container string) (api.NetworkInterface, error) {
	if o.engine == nil {
		return api.NetworkInterface{},
			fmt.Errorf("container engine not found, can't attach network %s from container %s", network.Name(), container)
	}
	return o.engine.AttachNetwork(network, container)
}

func (o *contextOpenshift) DetachNetwork(network api.Network, container string) error {
	if o.engine == nil {
		return fmt.Errorf("container engine not found, can't detach network %s from container %s", network.Name(), container)
	}
	return o.engine.DetachNetwork(network, container)
}

func (o *contextOpenshift) DeleteNetwork(network api.Network) error {
	if o.engine == nil {
		return fmt.Errorf("container engine not found, can not delete network %s", network.Name())
	}
	return o.engine.DeleteNetwork(network)
}

func (c *contextOpenshift) SetupUnderlay(f *framework.Framework, underlay api.Underlay) error {
	return fmt.Errorf("SetupUnderlay is not supported")
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
